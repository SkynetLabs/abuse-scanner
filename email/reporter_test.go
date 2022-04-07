package email

import (
	"abuse-scanner/accounts"
	"abuse-scanner/database"
	"context"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.sia.tech/siad/build"
)

const (
	// skylinks used in testing
	sl1 = "AADhDhfUZizFdo6f6DG03JTiNQmgxTt96UnjJfcvnViJCC"
	sl2 = "BBDhDhfUZizFdo6f6DG03JTiNQmgxTt96UnjJfcvnViJDD"
	sl3 = "CCDhDhfUZizFdo6f6DG03JTiNQmgxTt96UnjJfcvnViJEE"
	sl4 = "DDDhDhfUZizFdo6f6DG03JTiNQmgxTt96UnjJfcvnViJFF"
)

var (
	// timestamps used in testing
	ul1 = time.Now().Add(-time.Hour).UTC()
	ul2 = time.Now().Add(-2 * time.Hour).UTC()
	ul3 = time.Now().Add(-3 * time.Hour).UTC()
)

type (
	// mockAccountsClient is a simple struct that allows mocking the accounts
	// API.
	mockAccountsClient struct{}
)

// UploadInfoGET mocks the API response
func (m mockAccountsClient) UploadInfoGET(skylink string) ([]accounts.UploadInfo, error) {
	switch skylink {
	case sl1:
		return []accounts.UploadInfo{
			{
				Skylink:   sl1,
				IP:        "81.196.117.164",
				CreatedAt: ul1,
				UploaderInfo: accounts.UploaderInfo{
					Sub:   "user_1_sub",
					Email: "user.one@gmail.com",
				},
			},
		}, nil
	case sl2:
		return []accounts.UploadInfo{
			{
				Skylink:   sl2,
				IP:        "", // no IP
				CreatedAt: ul2,
				UploaderInfo: accounts.UploaderInfo{
					Sub:   "user_1_sub",
					Email: "user.one@gmail.com",
				},
			},
		}, nil
	case sl3:
		return []accounts.UploadInfo{
			{
				Skylink:   sl3,
				IP:        "13.192.32.50",
				CreatedAt: ul3,
				UploaderInfo: accounts.UploaderInfo{
					Sub:      "user_2_sub",
					Email:    "user.two@gmail.com",
					StripeID: "stripe_id_user_2",
				},
			},
		}, nil
	case sl4:
		// mock no info on sl4
		return nil, nil
	}

	return nil, nil
}

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
			name: "Reporter",
			test: testReporter,
		},
	}
	for _, test := range tests {
		t.Run(test.name, test.test)
	}
}

// testReporter verifies the messages that contain csam get corresponding NCMEC
// reports in the database and those reports get filed with NCMEC.
//
// NOTE: this test covers the full functionality of the reporter
func testReporter(t *testing.T) {
	t.Parallel()

	os.Setenv("NCMEC_USERNAME", "")
	os.Setenv("NCMEC_PASSWORD", "")
	os.Setenv("NCMEC_DEBUG", "")

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

	// create the abuse databases
	abuseDBName := t.Name() + "_AbuseDB"
	abuseDB, err := database.NewTestAbuseScannerDB(ctx, abuseDBName)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := abuseDB.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	// create a reporter
	accountsMock := mockAccountsClient{}
	reporter := newTestReporter()
	r := NewReporter(abuseDB, accountsMock, creds, "https://siasky.net", reporter, logger)

	// insert an email to report
	insertedAt := time.Now().UTC()
	email := database.AbuseEmail{
		ID:  primitive.NewObjectID(),
		UID: "INBOX-0",

		Parsed:    true,
		Blocked:   true,
		Finalized: true,
		Reported:  false,

		ParseResult: database.AbuseReport{
			Tags: []string{"csam"},
			Skylinks: []string{
				sl1,
				sl2,
				sl3,
				sl4,
			}},

		InsertedAt: insertedAt,
	}
	err = abuseDB.InsertOne(email)
	if err != nil {
		t.Fatal(err)
	}

	// assert there's one unreported email
	unreported, err := abuseDB.FindUnreported()
	if err != nil {
		t.Fatal(err)
	}
	if len(unreported) != 1 {
		t.Fatalf("unexpected number of unreported emails, %v != 1", len(unreported))
	}

	// start the reporter
	err = r.Start()
	if err != nil {
		t.Fatal(err)
	}

	// defer stop
	defer func() {
		if err := r.Stop(); err != nil {
			t.Fatal(err)
		}
	}()

	// assert there's no unreported emails left in a retry
	err = build.Retry(100, 100*time.Millisecond, func() error {
		unreported, err := abuseDB.FindUnreported()
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

	// assert there's no unfiled reports left in a retry
	err = build.Retry(100, 100*time.Millisecond, func() error {
		unfiled, err := abuseDB.FindUnfiledReports()
		if err != nil {
			t.Fatal(err)
		}
		if len(unfiled) != 0 {
			return fmt.Errorf("unexpected number of unfiled reports, %v != 0", len(unfiled))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// find our email
	reported, err := abuseDB.FindOne(email.UID)
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

	// draft the 3 reports we expect
	expected1 := report{
		IncidentSummary: ncmecIncidentSummary{
			IncidentType:     "Child Pornography (possession, manufacture, and distribution)",
			IncidentDateTime: insertedAt.Format(time.RFC3339),
		},
		InternetDetails: ncmecInternetDetails{
			ncmecWebPageIncident{
				ThirdPartyHostedContent: true,
				Url: []string{
					"https://siasky.net/AADhDhfUZizFdo6f6DG03JTiNQmgxTt96UnjJfcvnViJCC",
					"https://siasky.net/BBDhDhfUZizFdo6f6DG03JTiNQmgxTt96UnjJfcvnViJDD",
				},
			},
		},
		Reporter: newTestReporter(),
		Uploader: ncmecReportedPerson{
			UserReported: ncmecPerson{
				Email: "user.one@gmail.com",
			},
			IPCaptureEvent: []ncmecIPCaptureEvent{
				{
					IPAddress: "81.196.117.164",
					EventName: "Upload",
					Date:      ul1.Format(time.RFC3339),
				},
			},
		},
	}
	expected2 := report{
		IncidentSummary: ncmecIncidentSummary{
			IncidentType:     "Child Pornography (possession, manufacture, and distribution)",
			IncidentDateTime: insertedAt.Format(time.RFC3339),
		},
		InternetDetails: ncmecInternetDetails{
			ncmecWebPageIncident{
				ThirdPartyHostedContent: true,
				Url: []string{
					"https://siasky.net/CCDhDhfUZizFdo6f6DG03JTiNQmgxTt96UnjJfcvnViJEE",
				},
			},
		},
		Reporter: reporter,
		Uploader: ncmecReportedPerson{
			UserReported: ncmecPerson{
				Email: "user.two@gmail.com",
			},
			IPCaptureEvent: []ncmecIPCaptureEvent{
				{
					IPAddress: "13.192.32.50",
					EventName: "Upload",
					Date:      ul3.Format(time.RFC3339),
				},
			},
			AdditionalInfo: "Credit Card Info on file.",
		},
	}
	expected3 := report{
		IncidentSummary: ncmecIncidentSummary{
			IncidentType:     "Child Pornography (possession, manufacture, and distribution)",
			IncidentDateTime: insertedAt.Format(time.RFC3339),
		},
		InternetDetails: ncmecInternetDetails{
			ncmecWebPageIncident{
				ThirdPartyHostedContent: true,
				Url: []string{
					"https://siasky.net/DDDhDhfUZizFdo6f6DG03JTiNQmgxTt96UnjJfcvnViJFF",
				},
			},
		},
		Reporter: reporter,
	}

	// find NCMEC reports
	ncmecReports, err := abuseDB.FindReports(email.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ncmecReports) != 3 {
		t.Fatalf("unexpected number of reports, %v != 3", len(ncmecReports))
	}

	// unmarshal them into actual reports
	var reports []report
	for _, ncmecReport := range ncmecReports {
		var r report
		err := xml.Unmarshal([]byte(ncmecReport.Report), &r)
		if err != nil {
			t.Fatal(err)
		}
		reports = append(reports, r)
	}

	for _, report := range reports {
		if !(reflect.DeepEqual(report, expected1) ||
			reflect.DeepEqual(report, expected2) ||
			reflect.DeepEqual(report, expected3)) {
			buf, _ := xml.MarshalIndent(report, "", "\t")
			t.Fatal("unexpected report", string(buf))
		}
	}
}

// newTestReporter returns a reporter object for use in testing.
func newTestReporter() NCMECReporter {
	return NCMECReporter{
		ReportingPerson: ncmecPerson{
			FirstName: "SkynetLabs",
			LastName:  "Inc.",
			Email:     "abuse@skynetlabs.com",
		},
	}
}
