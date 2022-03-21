package email

import (
	"abuse-scanner/database"
	"context"
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.sia.tech/siad/build"
)

// TestReporter contains a set of unit tests that cover the reporter struct.
func TestReporter(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	t.Parallel()

	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "ReportMessages",
			test: testReportMessages,
		},
	}
	for _, test := range tests {
		t.Run(test.name, test.test)
	}
}

// testReportMessages verifies the messages that contain csam get reported
func testReportMessages(t *testing.T) {
	t.Parallel()

	// os.Setenv("NCMEC_USERNAME", "[ENTER_USERNAME]")
	// os.Setenv("NCMEC_PASSWORD", "[ENTER_PASSWORD]")
	// os.Setenv("NCMEC_DEBUG", "true")

	// load credentials from env
	creds, err := LoadNCMECCredentials()
	if err != nil {
		t.Log("NCMEC credentials not found, skipping...")
		t.SkipNow()
	}

	// ensure it's a debug client
	if !creds.Debug {
		t.Fatal("never run in production mode")
	}

	// create a context w/timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// create a null logger
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// create a database
	db, err := database.NewTestDatabase(ctx, t.Name(), logger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	err = db.Purge(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// create a reporter
	reporter := NewReporter(db, creds, logger)

	// insert an email to report
	email := database.AbuseEmail{
		ID:  primitive.NewObjectID(),
		UID: "INBOX-0",

		Parsed:    true,
		Blocked:   true,
		Reported:  false,
		Finalized: false,

		ParseResult: database.AbuseReport{
			Tags:     []string{"csam"},
			Skylinks: []string{"AADhDhfUZizFdo6f6DG03JTiNQmgxTt96UnjJfcvnViJCC"}},

		InsertedAt: time.Now().UTC(),
	}
	err = db.InsertOne(email)
	if err != nil {
		t.Fatal(err)
	}

	// assert there's one unreported email
	unreported, err := db.FindUnreported()
	if err != nil {
		t.Fatal(err)
	}
	if len(unreported) != 1 {
		t.Fatalf("unexpected number of unreported emails, %v != 1", len(unreported))
	}

	// start the reporter
	err = reporter.Start()
	if err != nil {
		t.Fatal(err)
	}

	// defer stop
	defer func() {
		if err := reporter.Stop(); err != nil {
			t.Fatal(err)
		}
	}()

	// assert there's no unreported emails left in a retry
	err = build.Retry(100, 100*time.Millisecond, func() error {
		unreported, err := db.FindUnreported()
		if err != nil {
			t.Fatal(err)
		}
		if len(unreported) != 0 {
			return fmt.Errorf("unexpected number of unreported emails, %v != 0", len(unreported))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// find our email
	reported, err := db.FindOne(email.UID)
	if err != nil {
		t.Fatal(err)
	}

	// assert the fields are set to the values we expect
	if !reported.Reported {
		t.Fatal("unexpected reported field", reported.Reported)
	}
	if reported.ReportedAt == (time.Time{}) {
		t.Fatal("unexpected reported at", reported.ReportedAt)
	}
	if reported.NCMECReportId == 0 {
		t.Fatal("unexpected NCMEC report id", reported.NCMECReportId)
	}
	if reported.NCMECReportErr != "" {
		t.Fatal("unexpected NCMEC report err", reported.NCMECReportErr)
	}
}

// TestEmailToReport is a unit test that covers the emailToReport helper.
func TestEmailToReport(t *testing.T) {
	t.Parallel()

	// create a dummy email
	now := time.Now().UTC()
	email := database.AbuseEmail{
		From:      "someone@gmail.com",
		Subject:   "Abuse Subject",
		MessageID: "<msg_uid>@gmail.com",

		ParseResult: database.AbuseReport{
			Skylinks: []string{
				"AADhDhfUZizFdo6f6DG03JTiNQmgxTt96UnjJfcvnViJCC",
				"AABa7mP11o9H6xEHPGmIXP__F-7GcegHIwpxeqEMTCzBCC",
				"_ATzhlAwQbJ-GmrsFCxM7la9Mn_x7WgOrhi-ILrd7PMFCC",
			},
		},
		Parsed:    false,
		Blocked:   true,
		Finalized: false,

		InsertedBy: "dev.siasky.net",
		InsertedAt: now,
	}

	// generate a report - test error flow
	actual, err := emailToReport(email)
	if err == nil || !strings.Contains(err.Error(), "email has to be parsed") {
		t.Fatal(err)
	}
	email.Parsed = true
	actual, err = emailToReport(email)
	if err == nil || !strings.Contains(err.Error(), "email has to contain csam") {
		t.Fatal(err)
	}
	email.ParseResult.Tags = []string{"csam"}

	// generate a report
	actual, err = emailToReport(email)
	if err != nil {
		t.Fatal(err)
	}

	// draft the report we expect
	expected := report{
		Xsi:                       "http://www.w3.org/2001/XMLSchema-instance",
		NoNamespaceSchemaLocation: "https://report.cybertip.org/ispws/xsd",

		IncidentSummary: ncmecIncidentSummary{
			IncidentType:     "Child Pornography (possession, manufacture, and distribution)",
			IncidentDateTime: now.Format("2006-01-02T15:04:05Z"),
		},
		InternetDetails: ncmecInternetDetails{
			ncmecWebPageIncident{
				ThirdPartyHostedContent: true,
				Url: []string{
					"https://siasky.net/AADhDhfUZizFdo6f6DG03JTiNQmgxTt96UnjJfcvnViJCC",
					"https://siasky.net/AABa7mP11o9H6xEHPGmIXP__F-7GcegHIwpxeqEMTCzBCC",
					"https://siasky.net/_ATzhlAwQbJ-GmrsFCxM7la9Mn_x7WgOrhi-ILrd7PMFCC",
				},
			},
		},
		Reporter: ncmecReporter{
			ReportingPerson: ncmecReportingPerson{
				FirstName: "Skynet",
				LastName:  "Team",
				Email:     "abuse@siasky.net",
			},
		},
	}

	// assert the report looks exactly as we suspect it
	if !reflect.DeepEqual(expected, actual) {
		t.Fatal("unexpected report", actual)
	}
}
