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
		staticStopChan  chan struct{}
		staticWaitGroup sync.WaitGroup
	}
)

// NewReporter creates a new reporter.
func NewReporter(database *database.AbuseScannerDB, creds NCMECCredentials, logger *logrus.Logger) *Reporter {
	return &Reporter{
		staticClient:   NewNCMECClient(creds),
		staticDatabase: database,
		staticLogger:   logger.WithField("module", "Reporter"),
		staticStopChan: make(chan struct{}),
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
	case <-time.After(time.Minute):
		return errors.New("unclean reporter shutdown")
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

// reportEmail will report the given email to NCMEC, it does so by interacting
// with the NCMEC API.
func (r *Reporter) reportEmail(email database.AbuseEmail) error {
	// convenience variables
	logger := r.staticLogger

	// convert the abuse email into a NCMEC report
	report, err := emailToReport(email)
	if err != nil {
		return err
	}

	// open the report
	reportedAt := time.Now().UTC()
	resp, err := r.staticClient.openReport(report)
	if err == nil && resp.ResponseCode != 0 {
		err = fmt.Errorf("unexpected response code %v when opening report for email '%v'", resp.ResponseCode, email.ID.Hex())
	}
	if err != nil {
		logger.Errorf("failed to open report, err '%v'", err)
		return err
	}
	reportId := resp.ReportId

	// defer an update to the email with some information about the NCMEC report
	var reportErr error
	defer func() {
		if err := r.staticDatabase.UpdateNoLock(email, bson.D{
			{"$set", bson.D{
				{"ncmec_report_id", reportId},
				{"ncmec_report_err", reportErr},
				{"ncmec_reported_at", reportedAt},
			}},
		}); err != nil {
			logger.Errorf("failed to update email %v with report id %v, err '%v'", email.MessageID, reportId, err)
		}
	}()

	// finish the report
	var reportRes reportDoneResponse
	reportRes, reportErr = r.staticClient.finishReport(reportId)
	if reportErr == nil && reportRes.ResponseCode != 0 {
		reportErr = fmt.Errorf("unexpected response code %v when finishing report for email '%v'", resp.ResponseCode, email.ID.Hex())
	}
	if reportErr != nil {
		logger.Errorf("failed to finish report %v, err '%v'", reportId, reportErr)
		return reportErr
	}

	return nil
}

// emailToReports returns a report containing every unique skylink in the
// original email report, note that only csam links will be turned into a report
// to NCMEC.
func emailToReport(email database.AbuseEmail) (report, error) {
	// sanity check it's parsed
	if !email.Parsed {
		return report{}, errors.New("email has to be parsed")
	}

	// sanity check it's csam
	pr := email.ParseResult
	if !pr.HasTag("csam") {
		return report{}, errors.New("email has to contain csam")
	}

	return report{
		Xsi:                       "http://www.w3.org/2001/XMLSchema-instance",
		NoNamespaceSchemaLocation: "https://report.cybertip.org/ispws/xsd",

		IncidentSummary: ncmecIncidentSummary{
			IncidentType:     "Child Pornography (possession and distribution)",
			IncidentDateTime: email.InsertedAt.Format("2006-01-02T15:04:05Z"),
		},
		InternetDetails: ncmecInternetDetails{
			ncmecWebPageIncident{
				// TODO: fix this should be full url
				Url: pr.Skylinks,
			},
		},
		Reporter: ncmecReporter{
			ReportingPerson: ncmecReportingPerson{
				FirstName: pr.Reporter.Name,
				LastName:  pr.Reporter.Name,
				Email:     pr.Reporter.Email,
			},
		},
	}, nil
}
