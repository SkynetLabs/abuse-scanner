package email

import (
	"testing"

	"github.com/emersion/go-imap"
)

// TestFetcher is a collection of unit tests that verify the functionality of
// the Fetcher
func TestFetcher(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	t.Parallel()

	t.Run("ExtractField", testExtractField)
}

// testExtractField is a unit test that covers the extractField helper
func testExtractField(t *testing.T) {
	env := &imap.Envelope{}
	address := &imap.Address{
		HostName:    "example.com",
		MailboxName: "john.doe",
	}

	// empty case
	for _, field := range []string{"unknown", "From", "To", "ReplyTo"} {
		if extractField(field, env) != "" {
			t.Fatal("unexpected field value")
		}
	}

	// from case
	env.From = []*imap.Address{address}
	if extractField("From", env) != address.Address() {
		t.Fatal("unexpected field value")
	}

	// to case
	env.To = []*imap.Address{address}
	if extractField("To", env) != address.Address() {
		t.Fatal("unexpected field value")
	}

	// reply-to case
	env.ReplyTo = []*imap.Address{address}
	if extractField("ReplyTo", env) != address.Address() {
		t.Fatal("unexpected field value")
	}
}
