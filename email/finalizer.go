package email

import (
	"abuse-scanner/database"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/emersion/go-imap/client"
	uuid "github.com/nu7hatch/gouuid"
	"github.com/sirupsen/logrus"
	"gitlab.com/NebulousLabs/errors"
)

const (
	// finalizeFrequency defines the frequency with which we finalize reports
	finalizeFrequency = 20 * time.Second

	// scannerEmailAddress is the from email we use when sending abuse reports
	scannerEmailAddress = "abuse-scanner@siasky.net"
)

type (
	// Finalizer is an object that will periodically scan the database for abuse
	// reports that have not been finalized yet.
	Finalizer struct {
		staticContext     context.Context
		staticDatabase    *database.AbuseScannerDB
		staticEmailClient *client.Client
		staticMailbox     string
		staticLogger      *logrus.Entry
	}
)

// NewFinalizer creates a new finalizer.
func NewFinalizer(ctx context.Context, database *database.AbuseScannerDB, emailClient *client.Client, mailbox string, logger *logrus.Logger) *Finalizer {
	return &Finalizer{
		staticContext:     ctx,
		staticDatabase:    database,
		staticEmailClient: emailClient,
		staticMailbox:     mailbox,
		staticLogger:      logger.WithField("module", "Finalizer"),
	}
}

// Start initializes the finalization process.
func (f *Finalizer) Start() error {
	go f.threadedFinalizeMessages()
	return nil
}

// threadedFinalizeMessages will periodically fetch email messages that have not
// been finalized yet and process them.
func (f *Finalizer) threadedFinalizeMessages() {
	// convenience variables
	logger := f.staticLogger
	abuseDB := f.staticDatabase
	first := true

	// start the loop
	for {
		// sleep until next iteration, sleeping at the start of the for loop
		// allows to 'continue' on error.
		if !first {
			select {
			case <-f.staticContext.Done():
				logger.Debugln("Finalizer context done")
				return
			case <-time.After(finalizeFrequency):
			}
		}
		first = false

		logger.Debugln("Triggered")

		// fetch all unfinalized emails
		toFinalize, err := abuseDB.FindUnfinalized()
		if err != nil {
			logger.Errorf("Failed fetching unparsed emails, error %v", err)
			continue
		}

		// log unfinalized message count
		numUnfinalized := len(toFinalize)
		if numUnfinalized == 0 {
			logger.Debugf("Found %v unfinalized messages\n", numUnfinalized)
		} else {
			logger.Infof("Found %v unfinalized messages\n", numUnfinalized)
		}

		// loop all emails and parse them
		for _, email := range toFinalize {
			if len(email.BlockResult) != len(email.ParseResult.Skylinks) {
				logger.Errorf("blockresult vs parseresult length, %v != %v, email with id %v\n", len(email.BlockResult), len(email.ParseResult.Skylinks), email.ID.String())
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

				// finalize the email
				err = f.finalizeEmail(email)
				if err != nil {
					return err
				}

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

// finalizeEmail will finalize the given abuse email
func (f *Finalizer) finalizeEmail(email database.AbuseEmail) error {
	// convenience variables
	logger := f.staticLogger
	emailClient := f.staticEmailClient

	// generate a uuid as message id
	u, err := uuid.NewV4()
	if err != nil {
		logger.Errorf("failed to generate uid, err %v", err)
		return err
	}

	// append an email with the abuse report result
	msg := fmt.Sprintf("Subject: Re: %s\n", email.Subject)
	msg += fmt.Sprintf("Message-ID: <%s@abusescanner.gmail.com\n", u)
	msg += fmt.Sprintf("References: %s\n", email.MessageID)
	msg += fmt.Sprintf("In-Reply-To: %s\n", email.MessageID)
	msg += fmt.Sprintf("From:%s\n", scannerEmailAddress)
	msg += "To:devs@siasky.net\n\n"
	msg += email.String()
	reader := strings.NewReader(msg)
	return emailClient.Append(f.staticMailbox, nil, time.Now(), reader)
}
