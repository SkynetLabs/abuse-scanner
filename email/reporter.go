package email

import (
	"abuse-scanner/accounts"
	"abuse-scanner/database"
	"encoding/xml"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"gitlab.com/NebulousLabs/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.sia.tech/siad/build"
)

const (
	// anonUser is a helper constant used to identify an anonymous upload for
	// which we don't have any information
	anonUser = "anon"

	// maxShutdownTimeout is the amount of time we wait on the waitgroup when
	// Stop is being called before returning an error that indicates an unclean
	// shutdown.
	maxShutdownTimeout = time.Minute
)

var (
	// ncmecFileFrequency defines the frequency with which we file reports to
	// NCMEC.
	ncmecFileFrequency = build.Select(build.Var{
		Dev:      30 * time.Second,
		Standard: 4 * time.Hour,
		Testing:  3 * time.Second,
	}).(time.Duration)

	// reportingFrequency defines the frequency with which we scan the database
	// to build NCMEC reports from abuse emails
	reportingFrequency = build.Select(build.Var{
		Dev:      30 * time.Second,
		Standard: 30 * time.Minute,
		Testing:  3 * time.Second,
	}).(time.Duration)
)

type (
	// Reporter is an object that will periodically scan the database for CSAM
	// abuse reports that have not been reported to NCMEC yet.
	Reporter struct {
		staticAbuseDatabase  *database.AbuseScannerDB
		staticAccountsClient accounts.AccountsAPI
		staticClient         *NCMECClient
		staticLogger         *logrus.Entry
		staticPortalURL      string
		staticReporter       NCMECReporter
		staticStopChan       chan struct{}
		staticWaitGroup      sync.WaitGroup
	}
)

// NewReporter creates a new reporter.
func NewReporter(abuseDB *database.AbuseScannerDB, accountsClient accounts.AccountsAPI, creds NCMECCredentials, portalURL string, reporter NCMECReporter, logger *logrus.Logger) *Reporter {
	return &Reporter{
		staticAbuseDatabase:  abuseDB,
		staticAccountsClient: accountsClient,
		staticClient:         NewNCMECClient(creds),
		staticLogger:         logger.WithField("module", "Reporter"),
		staticPortalURL:      portalURL,
		staticReporter:       reporter,
		staticStopChan:       make(chan struct{}),
	}
}

// Start initializes the reporter process.
func (r *Reporter) Start() error {
	// check the status endpoint before we start this module
	res, err := r.staticClient.status()
	if err != nil {
		return fmt.Errorf("unexpected response from NCMEC API, err %v", err)
	}
	if res.ResponseCode != ncmecStatusOK {
		return fmt.Errorf("unexpected status response from NCMEC API, status %v", res.ResponseCode)
	}

	r.staticWaitGroup.Add(1)
	go func() {
		r.threadedBuildReports()
		r.staticWaitGroup.Done()
	}()

	r.staticWaitGroup.Add(1)
	go func() {
		r.threadedFileReports()
		r.staticWaitGroup.Done()
	}()
	return nil
}

// Stop waits for the finalizer's waitgroup and times out after one minute.
func (r *Reporter) Stop() error {
	close(r.staticStopChan)

	c := make(chan struct{})
	go func() {
		defer close(c)
		r.staticWaitGroup.Wait()
	}()
	select {
	case <-c:
		return nil
	case <-time.After(maxShutdownTimeout):
		return errors.New("unclean reporter shutdown")
	}
}

// buildReports fetches all abuse emails from the database that have not been
// converted to NCMEC reports yet and converts those emails to a set of NCMEC
// reports.
func (r *Reporter) buildReports() {
	// convenience variables
	abuseDB := r.staticAbuseDatabase
	logger := r.staticLogger

	// fetch all unreported emails
	toReport, err := abuseDB.FindUnreported()
	if err != nil {
		logger.Errorf("Failed fetching unreported emails, error %v", err)
		return
	}

	// log unreported message count
	numUnreported := len(toReport)
	if numUnreported == 0 {
		logger.Debugf("Found %v unreported abuse emails", numUnreported)
		return
	}

	logger.Infof("Found %v unreported abuse emails", numUnreported)

	// loop all emails and report them
	for _, email := range toReport {
		err := r.buildReportsForEmail(email)
		if err != nil {
			logger.Errorf("Failed building NCMEC reports for email %v, error %v", email.UID, err)
		}
	}
}

// buildReportsForEmail will build a set of NCMEC reports for the given email
// and persist them in the database. One abuse email can explode into a set of
// NCMEC reports as those reports are unique to a single uploader, if we have
// that information.
func (r *Reporter) buildReportsForEmail(email database.AbuseEmail) error {
	// convenience variables
	logger := r.staticLogger
	abuseDB := r.staticAbuseDatabase

	// acquire a lock on the email
	lock := abuseDB.NewLock(email.UID)
	err := lock.Lock()
	if err != nil {
		return errors.AddContext(err, "could not acquire lock")
	}

	// defer the unlock
	defer func() {
		unlockErr := lock.Unlock()
		if unlockErr != nil {
			err = errors.Compose(err, errors.AddContext(unlockErr, "could not release lock"))
			return
		}
	}()

	// under lock, check whether the email has not been reported yet by another
	// process, if so we simply return
	current, err := abuseDB.FindOne(email.UID)
	if err != nil {
		return errors.AddContext(err, "could not find email")
	}
	if current.Reported {
		return nil
	}

	// build the reports
	reports, err := r.buildReportsForEmailInner(email)
	if err != nil {
		return errors.AddContext(err, "could not build reports")
	}

	// build the report for every uploader and set of skylinks, and insert it
	// into the database, another process will file the report with NCMEC
	for _, report := range reports {
		reportBytes, err := xml.Marshal(report)
		if err != nil {
			logger.Errorf("failed to marshal report, err %v", err)
			continue
		}

		// construct the initial report, this does not contain any uploader info
		err = abuseDB.InsertReport(
			database.NCMECReport{
				ID:         primitive.NewObjectID(),
				EmailID:    email.ID,
				Report:     string(reportBytes),
				InsertedAt: time.Now().UTC(),
			},
		)
		if err != nil {
			logger.Errorf("failed to insert report, err %v", err)
			continue
		}
	}

	// update the email
	err = abuseDB.UpdateNoLock(email, bson.M{
		"$set": bson.M{
			"reported":    true,
			"reported_at": time.Now().UTC(),
		},
	})
	if err != nil {
		return errors.AddContext(err, "could not update email")
	}
	return nil
}

// buildReportsForEmailInner will build a set of NCMEC reports for the given
// email and persist them in the database. It's called by buildReportsForEmail.
func (r *Reporter) buildReportsForEmailInner(email database.AbuseEmail) ([]report, error) {
	incidentDate := email.InsertedAt

	// group the upload infos per user
	grouped := make(map[string][]accounts.UploadInfo)
	for _, skylink := range email.ParseResult.Skylinks {
		infos, err := r.staticAccountsClient.UploadInfoGET(skylink)
		if err != nil {
			return nil, errors.AddContext(err, "could not fetch upload info")
		}
		if len(infos) == 0 {
			grouped[anonUser] = append(grouped[anonUser], accounts.UploadInfo{
				Skylink: skylink,
			})
			continue
		}
		for _, info := range infos {
			user := info.Sub
			grouped[user] = append(grouped[user], info)
		}
	}

	// turn the uploads into reports per user, so every user will have a list of
	// skylinks he uploaded and potentially more information about the upload
	var reports []report
	for user, uploads := range grouped {
		reports = append(reports, r.buildReportForUploads(incidentDate, user, uploads))
	}
	return reports, nil
}

// buildReportForUploads takes an email and a set of uploads and returns an
// NCMEC report
func (r *Reporter) buildReportForUploads(date time.Time, user string, uploads []accounts.UploadInfo) report {
	// convenience variables
	portalURL := r.staticPortalURL

	// construct the urls
	var urls []string
	for _, upload := range uploads {
		urls = append(urls, fmt.Sprintf("%s/%s", portalURL, upload.Skylink))
	}

	// create the report
	report := report{
		IncidentSummary: ncmecIncidentSummary{
			IncidentType:     "Child Pornography (possession, manufacture, and distribution)",
			IncidentDateTime: date.Format(time.RFC3339),
		},
		InternetDetails: ncmecInternetDetails{
			ncmecWebPageIncident{
				ThirdPartyHostedContent: true,
				Url:                     urls,
			},
		},
		Reporter: r.staticReporter,
	}

	// return early if we don't have any uploader info
	if user == anonUser {
		return report
	}

	// construct the ip catures
	var ipCaptures []ncmecIPCaptureEvent
	for _, upload := range uploads {
		if upload.IP == "" {
			continue
		}
		ipCaptures = append(ipCaptures, ncmecIPCaptureEvent{
			IPAddress: upload.IP,
			EventName: "Upload",
			Date:      upload.CreatedAt.Format(time.RFC3339),
		})
	}

	// construct the uploader
	var additionalInfo string
	if uploads[0].UploaderInfo.StripeID != "" {
		additionalInfo = "Credit Card Info on file."
	}
	report.Uploader = ncmecReportedPerson{
		IPCaptureEvent: ipCaptures,
		AdditionalInfo: additionalInfo,
		UserReported:   ncmecPerson{Email: uploads[0].UploaderInfo.Email},
	}
	return report
}

// fileReports fetches all reports from the database that have not been
// successfully reported yet to NCMEC.
func (r *Reporter) fileReports() {
	// convenience variables
	abuseDB := r.staticAbuseDatabase
	logger := r.staticLogger

	// fetch all unfiled reports
	unfiled, err := abuseDB.FindUnfiledReports()
	if err != nil {
		logger.Errorf("Failed fetching unreported emails, error %v", err)
		return
	}

	// log unreported message count
	numUnfiled := len(unfiled)
	if numUnfiled == 0 {
		logger.Debugf("Found %v unfiled NCMEC reports", numUnfiled)
		return
	}

	logger.Infof("Found %v unfiled NCMEC reports", numUnfiled)

	// loop over all unfiled reports and file them with NCMEC
	for _, report := range unfiled {
		err := r.fileReport(report)
		if err != nil {
			logger.Infof("Failed filing report, err %v", err)
		}
	}
}

// fileReport will open the report with NCMEC and immediately finish it
func (r *Reporter) fileReport(report database.NCMECReport) error {
	// convenience variables
	logger := r.staticLogger
	abuseDB := r.staticAbuseDatabase

	// acquire a lock on the report
	lock := abuseDB.NewReportLock(report.ID.Hex())
	err := lock.Lock()
	if err != nil {
		return errors.AddContext(err, "could not acquire lock")
	}

	// defer the unlock
	defer func() {
		unlockErr := lock.Unlock()
		if unlockErr != nil {
			err = errors.Compose(err, errors.AddContext(unlockErr, "could not release lock"))
			return
		}
	}()

	// under lock, check whether the report has not been filed yet by another
	// process, if so we simply return
	current, err := abuseDB.FindReport(report.ID)
	if err != nil {
		return errors.AddContext(err, "could not find report")
	}
	if current.Filed {
		return nil
	}

	// if the report has an NCMEC report id, it means something went wrong when
	// trying to finish the report last time, so we try again.
	if report.ReportID != 0 {
		return r.finishReport(report)
	}

	// otherwise open a report with NCMEC
	reportId, err := r.openReport(report)
	if err != nil {
		logger.Errorf("failed to open report, error '%v'", err)
	}

	// only if the report id is 0 we want to escape, if it is not 0 it means
	// a report has been opened but something went wrong after opening the
	// report, in that case we want to try and continue to finish the report
	if reportId == 0 {
		return err
	}

	// set the report id and finish the report
	report.ReportID = reportId
	err = r.finishReport(report)
	if err != nil {
		logger.Errorf("failed to finish report, error '%v'", err)
		return err
	}

	return nil
}

// finishReport will finish the report with NCMEC
func (r *Reporter) finishReport(report database.NCMECReport) error {
	// convenience variables
	logger := r.staticLogger

	// finish the report with NCMEC
	var reportErr string
	res, err := r.staticClient.finishReport(report.ReportID)
	if err == nil && res.ResponseCode != ncmecStatusOK {
		err = fmt.Errorf("unexpected response code %v when finishing report '%v'", res.ResponseCode, report.ID.Hex())
	}
	if err != nil {
		reportErr = err.Error()
		logger.Errorf("failed to finish report %v, err '%v'", report.ReportID, err)
	}

	// update the email and set the report err and reported flag
	err = r.staticAbuseDatabase.UpdateReportNoLock(report, bson.M{
		"$set": bson.M{
			"filed":     err == nil,
			"filed_at":  time.Now().UTC(),
			"filed_err": reportErr,

			"report_id": report.ReportID,
		},
	})
	if err != nil {
		logger.Errorf("failed to update report %v, err '%v'", report.ID, err)
		return err
	}
	return nil
}

// openReport will open a report with NCMEC for the given email, it will
// decorate the abuse email with the report id
func (r *Reporter) openReport(entity database.NCMECReport) (uint64, error) {
	// convenience variables
	logger := r.staticLogger

	// unmarshal the report
	var report report
	err := xml.Unmarshal([]byte(entity.Report), &report)
	if err != nil {
		return 0, fmt.Errorf("faild to unmarshal report, err %v", err)
	}

	// ensure the attributes are set
	report.Xsi = "http://www.w3.org/2001/XMLSchema-instance"
	report.NoNamespaceSchemaLocation = "https://report.cybertip.org/ispws/xsd"

	// open the report
	reportedAt := time.Now().UTC()
	resp, err := r.staticClient.openReport(report)
	if err == nil && resp.ResponseCode != ncmecStatusOK {
		err = fmt.Errorf("unexpected response code %v when opening report '%v'", resp.ResponseCode, entity.ID.Hex())
	}
	if err != nil {
		// update the email and set the report err
		updateErr := r.staticAbuseDatabase.UpdateReportNoLock(entity, bson.M{
			"$set": bson.M{
				"filed_err": err.Error(),
			},
		})
		if updateErr != nil {
			err = errors.Compose(err, updateErr)
		}
		logger.Errorf("failed to open report, err '%v'", err)
		return 0, err
	}
	reportId := resp.ReportId

	// update the email and set the report id
	err = r.staticAbuseDatabase.UpdateReportNoLock(entity, bson.M{
		"$set": bson.M{
			"filed_at":  reportedAt,
			"report_id": reportId,
		},
	})
	if err != nil {
		logger.Errorf("failed to update report '%v', err '%v'", entity.ID.Hex(), err)
		// we don't return the error here, instead we return the report id so we
		// can try and "finish" the report with NCMEC, if that succeeds and we
		// can mark this email as reported it does not have to be retried
	}

	return reportId, nil
}

// threadedBuildReports will periodically fetch messages that have been tagged
// as csam and have not been converted into NCMEC reports yet.
func (r *Reporter) threadedBuildReports() {
	// convenience variables
	logger := r.staticLogger

	// create a new ticker
	ticker := time.NewTicker(reportingFrequency)

	// start the loop
	for {
		logger.Debugln("threadedBuildReports loop iteration triggered")
		r.buildReports()

		select {
		case <-r.staticStopChan:
			logger.Debugln("Reporter stop channel closed")
			return
		case <-ticker.C:
		}
	}
}

// threadedFileReports will periodically fetch reports that have not been
// successfully reported to NCMEC yet.
func (r *Reporter) threadedFileReports() {
	// convenience variables
	logger := r.staticLogger

	// create a new ticker
	ticker := time.NewTicker(ncmecFileFrequency)

	// start the loop
	for {
		func() {
			logger.Debugln("threadedFileReports loop iteration triggered")

			// check the status endpoint before filing reports
			res, err := r.staticClient.status()
			if err != nil {
				logger.Errorf("unexpected response from NCMEC API, err %v, skipping filing reports", err)
				return
			}
			if res.ResponseCode != ncmecStatusOK {
				logger.Errorf("unexpected status response from NCMEC API, status %v, skipping filing reports", res.ResponseCode)
				return
			}

			r.fileReports()
		}()

		select {
		case <-r.staticStopChan:
			logger.Debugln("Reporter stop channel closed")
			return
		case <-ticker.C:
		}
	}
}
