package email

import (
	"abuse-scanner/database"
	"fmt"
	"net/smtp"
	"testing"
	"time"

	uuid "github.com/nu7hatch/gouuid"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	// testEmailTo is the email to which the abuse emails are sent in unit tests
	testEmailTo = ""

	// testPassword is the email app password used in unit tests
	testPassword = ""

	// testUsername is the email username used in unit tests
	testUsername = ""
)

// TestFinalizer is a collection of unit tests that verify the functionality of
// the finalizer.
func TestFinalizer(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	t.Parallel()

	t.Run("SendAutomatedReply", testSendAutomatedReply)
	t.Run("SendAbuseReport", testSendAbuseReport)
}

// testSendAutomatedReply sends the automated reply for a test email, this unit
// test gets skipped by default but is committed for debugging purposes
func testSendAutomatedReply(t *testing.T) {
	auth := smtp.PlainAuth("", testUsername, testPassword, "smtp.gmail.com")

	email := newTestEmail()
	email.ReplyTo = testEmailTo
	err := sendAutomatedReply(auth, email)
	if err != nil {
		t.Fatal(err)
	}
}

// testSendAbuseReport sends the abuse report for a test email, this unit test
// gets skipped by default but is committed for debugging purposes
func testSendAbuseReport(t *testing.T) {
	// NOTE: enter your email credentials here to send the test email
	creds := Credentials{
		Address:  "imap.gmail.com:993",
		Username: testUsername,
		Password: testPassword,
	}

	abuseEmail := creds.Username
	abuseMailbox := "INBOX"

	// NOTE: this test is skipped by default, it is committed for debugging and
	// manual testing purposes
	if creds.Username == "" || creds.Password == "" {
		t.SkipNow()
	}

	client, err := NewClient(creds)
	if err != nil {
		t.Fatal(err)
	}

	email := newTestEmail()
	email.ReplyTo = testEmailTo
	err = sendAbuseReport(client, email, abuseMailbox, abuseEmail)
	if err != nil {
		t.Fatal(err)
	}
}

// newTestEmail returns a dummy abuse email used for testing
func newTestEmail() database.AbuseEmail {
	// generate a uuid as message id
	var u *uuid.UUID
	u, err := uuid.NewV4()
	if err != nil {
		panic(err)
	}
	messageID := fmt.Sprintf("Message-ID: <%s@abusescanner>", u)

	// generate a message body
	messageBody := `Hello,
	Please be informed that we have located another phishing content located at the following URLs:
	hxxps:// siasky [.] net/BAEE7l0IkIVcVEHDgRCcNkRYS8keZKr9v_ffxf9_614m6g`

	return database.AbuseEmail{
		ID:        primitive.NewObjectID(),
		UID:       "INBOX-1-1",
		UIDRaw:    1,
		Body:      []byte(messageBody),
		MessageID: messageID,
		Subject:   "Phishing Report",

		From:    "john.doe@example.com",
		ReplyTo: "john.doe@example.com",
		To:      "report@example.com",

		InsertedBy: "server.siasky.net",

		Skip: false,

		Parsed:   true,
		ParsedAt: time.Now().UTC(),
		ParsedBy: "server.siasky.net",
		ParseResult: database.AbuseReport{
			Reporter: database.AbuseReporter{
				Name:  "John Doe",
				Email: "john.doe@example.com",
			},
			Skylinks: []string{"BAEE7l0IkIVcVEHDgRCcNkRYS8keZKr9v_ffxf9_614m6g"},
			Sponsor:  "skynetlabs.com",
			Tags:     []string{"phishing"},
		},

		Blocked:     true,
		BlockedAt:   time.Now().UTC(),
		BlockedBy:   "server.siasky.net",
		BlockResult: []string{database.AbuseStatusBlocked},

		Finalized:   false,
		FinalizedAt: time.Time{},
		FinalizedBy: "server.siasky.net",

		Reported:   false,
		ReportedAt: time.Time{},
	}
}
