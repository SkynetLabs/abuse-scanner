package email

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestNCMECClient contains a couple of unit tests that verify the functionality
// of the NCMEC client.
func TestNCMECClient(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	t.Parallel()

	os.Setenv("NCMEC_USERNAME", "Siasky")
	os.Setenv("NCMEC_PASSWORD", "Ug7=Ba3=Qg2@")
	os.Setenv("NCMEC_DEBUG", "true")

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

	// instantiate the client
	client := NewNCMECClient(creds)

	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "finishReport",
			test: func(t *testing.T) { testFinishReport(t, client) },
		},
		{
			name: "openReport",
			test: func(t *testing.T) { testOpenReport(t, client) },
		},
		{
			name: "status",
			test: func(t *testing.T) { testStatus(t, client) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, test.test)
	}
}

// testFinishReport is a unit test that verifies whether we can finish a report
func testFinishReport(t *testing.T, c *NCMECClient) {
	// open a report
	now := time.Now().UTC().Add(-time.Hour)
	report := newTestReport(now)
	res, err := c.openReport(report)
	if err != nil {
		t.Fatal(err)
	}

	// finish the report
	ress, err := c.finishReport(res.ReportId)
	if err != nil {
		t.Fatal(err)
	}

	// assert the report was finished
	if ress.ResponseCode != ncmecStatusOK {
		t.Fatalf("unexpected response code, %v != %v", ress.ResponseCode, ncmecStatusOK)
	}
	if ress.ReportId != res.ReportId {
		t.Fatalf("unexpected report id, %v != %v", ress.ReportId, res.ReportId)
	}
}

// testOpenReport is a unit test that verifies we can open a report with NCMEC
func testOpenReport(t *testing.T, c *NCMECClient) {
	// open a report
	now := time.Now().UTC().Add(time.Hour)
	report := newTestReport(now)
	res, err := c.openReport(report)
	if err != nil {
		t.Fatal(err)
	}

	// assert the response, we expect it to have failed because the invalid
	// (future) date
	if res.ResponseCode != ncmecStatusValidationFailed {
		t.Fatalf("unexpected response code, %v != %v", res.ResponseCode, ncmecStatusValidationFailed)
	}
	if !strings.Contains(res.ResponseDescription, "must be a past date") {
		t.Fatalf("unexpected response description '%s'", res.ResponseDescription)
	}
	if res.ReportId != 0 {
		t.Fatalf("unexpected report id, %v", res.ReportId)
	}

	// open a report in the past
	now = time.Now().UTC().Add(-time.Hour)
	report = newTestReport(now)
	res, err = c.openReport(report)
	if err != nil {
		t.Fatal(err)
	}

	// assert the response
	if res.ResponseCode != ncmecStatusOK {
		t.Fatalf("unexpected response code, %v != %v", res.ResponseCode, ncmecStatusOK)
	}
	if res.ResponseDescription != "Success" {
		t.Fatalf("unexpected response description '%s'", res.ResponseDescription)
	}
	if res.ReportId <= 0 {
		t.Fatalf("unexpected report id, %v", res.ReportId)
	}
}

// testStatus is a unit test that verifies we can communicate with the NCMEC
// server
func testStatus(t *testing.T, c *NCMECClient) {
	// get the status
	res, err := c.status()
	if err != nil {
		t.Fatal(err)
	}

	// assert the response
	if res.ResponseCode != ncmecStatusOK {
		t.Fatalf("unexpected response code, %v != %v", res.ResponseCode, ncmecStatusOK)
	}
}

// newTestReport returns a test report object
func newTestReport(date time.Time) report {
	return report{
		Xsi:                       "http://www.w3.org/2001/XMLSchema-instance",
		NoNamespaceSchemaLocation: "https://report.cybertip.org/ispws/xsd",

		IncidentSummary: ncmecIncidentSummary{
			IncidentType:     "Child Pornography (possession, manufacture, and distribution)",
			IncidentDateTime: date.Format("2006-01-02T15:04:05Z"),
		},
		InternetDetails: ncmecInternetDetails{
			ncmecWebPageIncident{
				Url: []string{"http://badsite.com/baduri.html"},
			},
		},
		Reporter: NCMECReporter{
			ReportingPerson: ncmecReportingPerson{
				FirstName: "John",
				LastName:  "Smith",
				Email:     "jsmith@example.com",
			},
		},
	}
}
