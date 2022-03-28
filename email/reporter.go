package email

import (
	"abuse-scanner/database"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"gitlab.com/NebulousLabs/errors"
	"go.mongodb.org/mongo-driver/bson"
)

const (
	// reportingFrequency defines the frequency with which we scan the database
	// to report csam reports to NCMEC
	reportingFrequency = 30 * time.Second

	// maxShutdownTimeout is the amount of time we wait on the waitgroup when
	// Stop is being called before returning an error that indicates an unclean
	// shutdown.
	maxShutdownTimeout = time.Minute
)

type (
	// Reporter is an object that will periodically scan the database for CSAM
	// abuse reports that have not been reported to NCMEC yet.
	Reporter struct {
		staticClient    *NCMECClient
		staticDatabase  *database.AbuseScannerDB
		staticLogger    *logrus.Entry
		staticPortalURL string
		staticReporter  NCMECReporter
		staticStopChan  chan struct{}
		staticWaitGroup sync.WaitGroup
	}
)

// NewReporter creates a new reporter.
func NewReporter(database *database.AbuseScannerDB, creds NCMECCredentials, portalURL string, reporter NCMECReporter, logger *logrus.Logger) *Reporter {
	return &Reporter{
		staticClient:    NewNCMECClient(creds),
		staticDatabase:  database,
		staticLogger:    logger.WithField("module", "Reporter"),
		staticPortalURL: portalURL,
		staticReporter:  reporter,
		staticStopChan:  make(chan struct{}),
	}
}

// Start initializes the reporter process.
func (r *Reporter) Start() error {
	r.staticWaitGroup.Add(1)
	go func() {
		r.threadedReportMessages()
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

// emailToReports returns a report containing every unique skylink in the
// original email report, note that only csam links will be turned into a report
// to NCMEC.
func (r *Reporter) emailToReport(email database.AbuseEmail) (report, error) {
	// sanity check it's parsed
	if !email.Parsed {
		return report{}, errors.New("email has to be parsed")
	}

	// sanity check it's csam
	pr := email.ParseResult
	if !pr.HasTag("csam") {
		return report{}, errors.New("email has to contain csam")
	}

	// construct the urls
	urls := make([]string, len(pr.Skylinks))
	for i, skylink := range pr.Skylinks {
		urls[i] = fmt.Sprintf("%s/%s", r.staticPortalURL, skylink)
	}

	return report{
		Xsi:                       "http://www.w3.org/2001/XMLSchema-instance",
		NoNamespaceSchemaLocation: "https://report.cybertip.org/ispws/xsd",

		IncidentSummary: ncmecIncidentSummary{
			IncidentType:     "Child Pornography (possession, manufacture, and distribution)",
			IncidentDateTime: email.InsertedAt.Format("2006-01-02T15:04:05Z"),
		},
		InternetDetails: ncmecInternetDetails{
			ncmecWebPageIncident{
				ThirdPartyHostedContent: true,
				Url:                     urls,
			},
		},
		Reporter: r.staticReporter,
	}, nil
}

// finishReport will finish the report with NCMEC
func (r *Reporter) finishReport(email database.AbuseEmail) error {
	// convenience variables
	logger := r.staticLogger

	// finish the report with NCMEC
	var reportErr string
	res, err := r.staticClient.finishReport(email.NCMECReportId)
	if err == nil && res.ResponseCode != ncmecStatusOK {
		err = fmt.Errorf("unexpected response code %v when finishing report for email '%v'", res.ResponseCode, email.ID.Hex())
	}
	if err != nil {
		reportErr = err.Error()
		logger.Errorf("failed to finish report %v, err '%v'", email.NCMECReportId, err)
	}

	// update the email and set the report err and reported flag
	err = r.staticDatabase.UpdateNoLock(email, bson.M{
		"$set": bson.M{
			"reported": err == nil,

			"ncmec_report_id":  email.NCMECReportId,
			"ncmec_report_err": reportErr,
		},
	})
	if err != nil {
		logger.Errorf("failed to update email %v with report id %v, err '%v'", email.MessageID, email.NCMECReportId, err)
		return err
	}
	return nil
}

// openReport will open a report with NCMEC for the given email, it will
// decorate the abuse email with the report id
func (r *Reporter) openReport(email database.AbuseEmail) (uint64, error) {
	// convenience variables
	logger := r.staticLogger

	// convert the abuse email into a NCMEC report
	report, err := r.emailToReport(email)
	if err != nil {
		return 0, err
	}

	// open the report
	reportedAt := time.Now().UTC()
	resp, err := r.staticClient.openReport(report)
	if err == nil && resp.ResponseCode != ncmecStatusOK {
		err = fmt.Errorf("unexpected response code %v when opening report for email '%v'", resp.ResponseCode, email.ID.Hex())
	}
	if err != nil {
		// update the email and set the report err
		err = errors.Compose(err, r.staticDatabase.UpdateNoLock(email, bson.M{
			"$set": bson.M{
				"ncmec_report_err": err.Error(),
			},
		}))
		logger.Errorf("failed to open report, err '%v'", err)
		return 0, err
	}
	reportId := resp.ReportId

	// update the email and set the report id
	err = r.staticDatabase.UpdateNoLock(email, bson.M{
		"$set": bson.M{
			"reported_at":     reportedAt,
			"ncmec_report_id": reportId,
		},
	})
	if err != nil {
		logger.Errorf("failed to update email %v with report id %v, err '%v'", email.MessageID, reportId, err)
		return reportId, nil
	}

	return reportId, nil
}

// reportEmail will report the given email to NCMEC, it does so by interacting
// with the NCMEC API.
func (r *Reporter) reportEmail(email database.AbuseEmail) error {
	// convenience variables
	logger := r.staticLogger

	// if the email has an NCMEC report id, it means something went wrong when
	// trying to finish the report last time, so we try again.
	if email.NCMECReportId != 0 {
		return r.finishReport(email)
	}

	// otherwise open a report with NCMEC
	reportId, err := r.openReport(email)
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
	email.NCMECReportId = reportId
	err = r.finishReport(email)
	if err != nil {
		logger.Errorf("failed to open report, error '%v'", err)
		return err
	}

	return nil
}

// reportMessages fetches all unreported messages from the database and reports
// them to NCMEC. Reporting only applies to emails which have been tagged with
// CSAM, we report those messages and the content we find inside them to NCMEC.
func (r *Reporter) reportMessages() {
	// convenience variables
	abuseDB := r.staticDatabase
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
		logger.Debugf("Found %v unreported messages", numUnreported)
		return
	}

	logger.Infof("Found %v unreported messages", numUnreported)

	// loop all emails and report them
	for _, email := range toReport {
		err := r.reportEmail(email)
		if err != nil {
			logger.Errorf("Failed to report email %v, error %v", email.UID, err)
		}
	}
}

// threadedReportMessages will periodically fetch email messages that have not
// been tagged as csam and have not been reported to NCMEC yet.
func (r *Reporter) threadedReportMessages() {
	// convenience variables
	logger := r.staticLogger

	// create a new ticker
	ticker := time.NewTicker(reportingFrequency)

	// start the loop
	for {
		logger.Debugln("threadedReportMessages loop iteration triggered")
		r.reportMessages()

		select {
		case <-r.staticStopChan:
			logger.Debugln("Reporter stop channel closed")
			return
		case <-ticker.C:
		}
	}
}
