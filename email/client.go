package email

import (
	"github.com/emersion/go-imap/client"
)

const (
	// MailboxInbox is the name of the inbox
	MailboxInbox = "INBOX"

	// MailboxAbuseScanner is the name of the Abuse Scanner folder
	MailboxAbuseScanner = "Abuse Scanner"
)

// NewClient returns an authenticated email client
func NewClient(mailServer, username, password string) (*client.Client, error) {
	// connect to server
	c, err := client.DialTLS(mailServer, nil)
	if err != nil {
		return nil, err
	}

	// authenticate
	if err := c.Login(username, password); err != nil {
		return nil, err
	}

	return c, nil
}
