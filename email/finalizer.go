package email

import (
	"abuse-scanner/database"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/client"
	uuid "github.com/nu7hatch/gouuid"
	"github.com/sirupsen/logrus"
	"gitlab.com/NebulousLabs/errors"
	"go.mongodb.org/mongo-driver/bson"
)

const (
	// finalizeFrequency defines the frequency with which we finalize reports
	finalizeFrequency = 30 * time.Second

	// scannerEmailAddress is the from email we use when sending abuse reports
	scannerEmailAddress = "abuse-scanner@siasky.net"
)

type (
	// Finalizer is an object that will periodically scan the database for abuse
	// reports that have not been finalized yet.
	Finalizer struct {
		staticContext          context.Context
		staticDatabase         *database.AbuseScannerDB
		staticEmailCredentials Credentials
		staticLogger           *logrus.Entry
		staticMailbox          string
		staticMailaddress      string
		staticWaitGroup        sync.WaitGroup
	}
)

// NewFinalizer creates a new finalizer.
func NewFinalizer(ctx context.Context, database *database.AbuseScannerDB, emailCredentials Credentials, mailaddress, mailbox string, logger *logrus.Logger) *Finalizer {
	return &Finalizer{
		staticContext:          ctx,
		staticDatabase:         database,
		staticEmailCredentials: emailCredentials,
		staticLogger:           logger.WithField("module", "Finalizer"),
		staticMailaddress:      mailaddress,
		staticMailbox:          mailbox,
	}
}

// Start initializes the finalization process.
func (f *Finalizer) Start() error {
	f.staticWaitGroup.Add(1)
	go func() {
		f.threadedFinalizeMessages()
		f.staticWaitGroup.Done()
	}()
	return nil
}

// Stop waits for the finalizer's waitgroup and times out after one minute.
func (f *Finalizer) Stop() error {
	c := make(chan struct{})
	go func() {
		defer close(c)
		f.staticWaitGroup.Wait()
	}()
	select {
	case <-c:
		return nil
	case <-time.After(time.Minute):
		return errors.New("unclean finalizer shutdown")
	}
}

// finalizeEmail will finalize the given email, it does so by responding to the
// email with a report that shows an overview of what skylinks were found and
// whether or not they got blocked successfully.
func (f *Finalizer) finalizeEmail(client *client.Client, email database.AbuseEmail) error {
	// sanity check every skylink has a blocked status
	if len(email.BlockResult) != len(email.ParseResult.Skylinks) {
		return fmt.Errorf("blockresult vs parseresult length, %v != %v, email with id %v", len(email.BlockResult), len(email.ParseResult.Skylinks), email.ID.String())
	}

	// convenience variables
	abuseDB := f.staticDatabase
	logger := f.staticLogger

	// acquire a lock
	lock := abuseDB.NewLock(email.UID)
	err := lock.Lock()
	if err != nil {
		return errors.AddContext(err, "could not acquire lock")
	}

	// defer the unlock
	defer func() {
		unlockErr := lock.Unlock()
		if unlockErr != nil {
			err = errors.Compose(err, errors.AddContext(unlockErr, "could not release lock"))
			return
		}
	}()

	// generate a uuid as message id
	u, err := uuid.NewV4()
	if err != nil {
		logger.Errorf("failed to generate uid, err %v", err)
		return err
	}

	// construct the email message
	msg := fmt.Sprintf("Subject: Re: %s\n", email.Subject)
	msg += fmt.Sprintf("Message-ID: <%s@abusescanner\n", u)
	msg += fmt.Sprintf("References: %s\n", email.MessageID)
	msg += fmt.Sprintf("In-Reply-To: %s\n", email.MessageID)
	msg += fmt.Sprintf("From: SCANNED <%s>\n", scannerEmailAddress)
	msg += fmt.Sprintf("To:%s\n", f.staticMailaddress)
	msg += ""
	msg += email.String()
	reader := strings.NewReader(msg)

	// append an email with the abuse report result
	err = client.Append(f.staticMailbox, nil, time.Now(), reader)
	if err != nil {
		return err
	}

	// update the email
	err = abuseDB.UpdateNoLock(email, bson.D{
		{"$set", bson.D{
			{"finalized", true},
			{"finalized_at", time.Now().UTC()},
		}},
	})
	if err != nil {
		return errors.AddContext(err, "could not update email")
	}

	return nil
}

// threadedFinalizeMessages will periodically fetch email messages that have not
// been finalized yet and process them.
func (f *Finalizer) threadedFinalizeMessages() {
	// convenience variables
	abuseDB := f.staticDatabase
	logger := f.staticLogger

	ticker := time.NewTicker(finalizeFrequency)

	// start the loop
	for {
		logger.Debugln("Triggered")
		func() {
			// create an email client
			client, err := NewClient(f.staticEmailCredentials)
			if err != nil && strings.Contains(err.Error(), ErrTooManyConnections.Error()) {
				logger.Debugf("Skipped due to Too Many Connections (expected)")
				return
			} else if err != nil {
				logger.Errorf("Failed to initialize email client, err %v", err)
				return
			}

			// defer a logout
			defer func() {
				err := client.Logout()
				if err != nil {
					logger.Errorf("Failed to close email client, err: %v", err)
				}
			}()

			// fetch all unfinalized emails
			toFinalize, err := abuseDB.FindUnfinalized()
			if err != nil {
				logger.Errorf("Failed fetching unparsed emails, error %v", err)
				return
			}

			// log unfinalized message count
			numUnfinalized := len(toFinalize)
			if numUnfinalized == 0 {
				logger.Debugf("Found %v unfinalized messages", numUnfinalized)
				return
			}

			logger.Infof("Found %v unfinalized messages", numUnfinalized)

			// loop all emails and parse them
			for _, email := range toFinalize {
				err := f.finalizeEmail(client, email)
				if err != nil {
					logger.Errorf("Failed to finalize email %v, error %v", email.UID, err)
				}
			}
		}()

		select {
		case <-f.staticContext.Done():
			logger.Debugln("Finalizer context done")
			return
		case <-ticker.C:
		}
	}
}
