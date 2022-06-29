package email

import (
	"github.com/emersion/go-imap/client"
	"gitlab.com/NebulousLabs/errors"
)

var (
	// ErrTooManyConnections is returned by the IMAP server if the connection
	// can't be established because there are too many simultaneous connections.
	// By default, Gmail's IMAP server uses a limit of only 15 connections.
	ErrTooManyConnections = errors.New("Too many simultaneous connections")
)

type (
	// Credentials contains all the necessary information to create a new client
	Credentials struct {
		Address  string
		Username string
		Password string

		AppPassword string
	}
)

// NewClient returns an authenticated email client
func NewClient(credentials Credentials) (*client.Client, error) {
	// connect to server
	c, err := client.DialTLS(credentials.Address, nil)
	if err != nil {
		return nil, err
	}

	// authenticate
	if err := c.Login(credentials.Username, credentials.Password); err != nil {
		return nil, err
	}

	return c, nil
}
