package email

import (
	"abuse-scanner/database"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/emersion/go-imap/client"
	"github.com/sirupsen/logrus"
	"gitlab.com/NebulousLabs/errors"
)

const (
	// finalizeFrequency defines the frequency with which we finalize reports
	finalizeFrequency = 30 * time.Second
)

type (
	// Finalizer is an object that will periodically scan the database for abuse
	// reports that have not been finalized yet.
	Finalizer struct {
		staticContext     context.Context
		staticDatabase    *database.AbuseScannerDB
		staticEmailClient *client.Client
		staticMailboxSrc  string
		staticMailboxDst  string
		staticLogger      *logrus.Logger
	}
)

// NewFinalizer creates a new finalizer.
func NewFinalizer(ctx context.Context, database *database.AbuseScannerDB, emailClient *client.Client, mailboxSrc, mailboxDst string, logger *logrus.Logger) *Finalizer {
	return &Finalizer{
		staticContext:     ctx,
		staticDatabase:    database,
		staticEmailClient: emailClient,
		staticMailboxSrc:  mailboxSrc,
		staticMailboxDst:  mailboxDst,
		staticLogger:      logger,
	}
}

// Start initializes the finalization process.
func (f *Finalizer) Start() error {
	// select the mailbox
	// _, err := f.staticEmailClient.Select(f.staticMailboxSrc, false)
	// if err != nil {
	// 	return errors.AddContext(err, fmt.Sprintf("Failed selecting mailbox '%v'", f.staticMailboxSrc))
	// }

	go f.threadedFinalizeMessages()
	return nil
}

// threadedFinalizeMessages will periodically fetch email messages that have not
// been finalized yet and process them.
func (f *Finalizer) threadedFinalizeMessages() {
	// convenience variables
	logger := f.staticLogger
	abuseDB := f.staticDatabase
	emailClient := f.staticEmailClient
	first := true

	// start the loop
	for {
		// sleep until next iteration, sleeping at the start of the for loop
		// allows to 'continue' on error.
		if !first {
			select {
			case <-f.staticContext.Done():
				return
			case <-time.After(finalizeFrequency):
			}
		}
		first = false

		logger.Debugln("Finalizing reports...")

		// fetch all unfinalized emails
		toFinalize, err := abuseDB.FindUnfinalized()
		if err != nil {
			logger.Errorf("Failed fetching unparsed emails, error %v", err)
			continue
		}

		logger.Debugf("Found %v unfinalized messages\n", len(toFinalize))

		// loop all emails and parse them
		for _, email := range toFinalize {
			if len(email.BlockResult) != len(email.ParseResult.Skylinks) {
				logger.Debugf("Found mismatching blockresult and parseresult length, %v != %v, email with id %v\n", len(email.BlockResult), len(email.ParseResult.Skylinks), email.ID.String())
				continue
			}
			err = func() (err error) {
				lock := abuseDB.NewLock(email.UID)
				err = lock.Lock()
				if err != nil {
					return errors.AddContext(err, "could not acquire lock")
				}
				defer func() {
					unlockErr := lock.Unlock()
					if unlockErr != nil {
						err = errors.Compose(err, errors.AddContext(unlockErr, "could not release lock"))
						return
					}
				}()

				// copy the original email
				// seqSet := new(imap.SeqSet)
				// seqSet.AddNum(email.UIDRaw)
				// err = emailClient.UidCopy(seqSet, "Abuse Scanner")
				// if err != nil {
				// 	return errors.AddContext(err, "could not copy email")
				// }

				// append an email with the abuse report result
				msg := fmt.Sprintf("Subject: SCANNED (%v): %s\n", time.Now().Unix(), email.Subject)
				msg += "From:abuse-scanner@siasky.net\n"
				msg += "To:devs@siasky.net\n\n"
				msg += email.String()

				reader := strings.NewReader(msg)
				err = emailClient.Append("Abuse Scanner", nil, time.Now(), reader)

				// update the email
				email.Finalized = true
				err = abuseDB.UpdateNoLock(email)
				if err != nil {
					return errors.AddContext(err, "could not update email")
				}

				return nil
			}()
			if err != nil {
				logger.Errorf("Failed to finalize email %v, error %v", email.UID, err)
			}
		}
	}
}

// finalizeReport will finalize the report
func (f *Finalizer) finalizeReport(report database.AbuseReport) error {
	return nil
}
