package email

import (
	"abuse-scanner/database"
	"context"
	"fmt"
	"net/smtp"
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
		staticEmailAddress     string
		staticEmailAuth        smtp.Auth
		staticEmailCredentials Credentials
		staticLogger           *logrus.Entry
		staticMailbox          string
		staticServerDomain     string
		staticWaitGroup        sync.WaitGroup
	}
)

// NewFinalizer creates a new finalizer.
func NewFinalizer(ctx context.Context, database *database.AbuseScannerDB, emailCredentials Credentials, emailAddress, mailbox, serverDomain string, logger *logrus.Logger) *Finalizer {
	return &Finalizer{
		staticContext:          ctx,
		staticDatabase:         database,
		staticEmailAddress:     emailAddress,
		staticEmailAuth:        smtp.PlainAuth("", scannerEmailAddress, emailCredentials.Password, "smtp.gmail.com"),
		staticEmailCredentials: emailCredentials,
		staticLogger:           logger.WithField("module", "Finalizer"),
		staticMailbox:          mailbox,
		staticServerDomain:     serverDomain,
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
func (f *Finalizer) finalizeEmail(client *client.Client, email database.AbuseEmail) (err error) {
	// sanity check every skylink has a blocked status
	if len(email.BlockResult) != len(email.ParseResult.Skylinks) {
		return fmt.Errorf("blockresult vs parseresult length, %v != %v, email with id %v", len(email.BlockResult), len(email.ParseResult.Skylinks), email.ID.String())
	}

	// convenience variables
	abuseDB := f.staticDatabase
	logger := f.staticLogger

	// acquire a lock
	lock := abuseDB.NewLock(email.UID)
	err = lock.Lock()
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

	// now that we have the lock, check whether the email has not yet been
	// finalized by another process, if so we just return
	current, err := abuseDB.FindOne(email.UID)
	if err != nil {
		return errors.AddContext(err, "could not find email")
	}
	if current.Finalized {
		return nil
	}

	// generate a uuid as message id
	err = sendAbuseReport(client, email, f.staticMailbox, f.staticEmailAddress)
	if err != nil {
		logger.Errorf("failed to send abuse report, err %v", err)
		return err
	}

	// respond to the original sender, only if the abuse email was handled successfully
	if email.Success() {
		err = sendAutomatedReply(f.staticEmailAuth, email)
		if err != nil {
			// simply log the error, we don't return it here
			logger.Errorf("failed to send automated reply, err %v", err)
		}
	}

	// update the email
	err = abuseDB.UpdateNoLock(email, bson.M{
		"$set": bson.M{
			"finalized":    true,
			"finalized_by": f.staticServerDomain,
			"finalized_at": time.Now().UTC(),
		},
	})
	if err != nil {
		return errors.AddContext(err, "could not update email")
	}

	return nil
}

// finalizeMessages fetches all unfinalized messages from the database and
// finalizes them. Finalizing means responding to the original abuse email with
// an overview of what skylinks the abuse scanner discovered and what skylinks
// have been blocked.
func (f *Finalizer) finalizeMessages() {
	// convenience variables
	abuseDB := f.staticDatabase
	logger := f.staticLogger
	mailbox := f.staticMailbox

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
	toFinalize, err := abuseDB.FindUnfinalized(mailbox)
	if err != nil {
		logger.Errorf("Failed fetching unfinalized emails, error %v", err)
		return
	}

	// log unfinalized message count
	numUnfinalized := len(toFinalize)
	if numUnfinalized == 0 {
		logger.Debugf("Found %v unfinalized messages", numUnfinalized)
		return
	}

	logger.Infof("Found %v unfinalized messages", numUnfinalized)

	// loop all emails and finalize them
	for _, email := range toFinalize {
		err := f.finalizeEmail(client, email)
		if err != nil {
			logger.Errorf("Failed to finalize email %v, error %v", email.UID, err)
		}
	}
}

// threadedFinalizeMessages will periodically fetch email messages that have not
// been finalized yet and process them.
func (f *Finalizer) threadedFinalizeMessages() {
	// convenience variables
	logger := f.staticLogger

	// create a new ticker
	ticker := time.NewTicker(finalizeFrequency)

	// start the loop
	for {
		logger.Debugln("threadedFinalizeMessages loop iteration triggered")
		f.finalizeMessages()

		select {
		case <-f.staticContext.Done():
			logger.Debugln("Finalizer context done")
			return
		case <-ticker.C:
		}
	}
}

// sendAbuseReport sends the abuse report for the given abuse email to the given
// email address. This is extracted in a standalone function for unit testing
// purposes.
func sendAbuseReport(client *client.Client, email database.AbuseEmail, mailbox, to string) error {
	// generate a uuid as message id
	var u *uuid.UUID
	u, err := uuid.NewV4()
	if err != nil {
		return errors.AddContext(err, "failed to generate uid")
	}

	// construct the email message
	msg := fmt.Sprintf("Subject: Re: %s\n", email.Subject)
	msg += fmt.Sprintf("Message-ID: <%s@abusescanner>\n", u)
	msg += fmt.Sprintf("References: %s\n", email.MessageID)
	msg += fmt.Sprintf("In-Reply-To: %s\n", email.MessageID)
	msg += fmt.Sprintf("From: SCANNED <%s>\n", scannerEmailAddress)
	msg += fmt.Sprintf("To: %s\n", to)
	msg += ""
	msg += email.String()
	reader := strings.NewReader(msg)

	// append an email with the abuse report result
	err = client.Append(mailbox, nil, time.Now().UTC(), reader)
	if err != nil {
		return err
	}
	return nil
}

// sendAutomatedReply sends the automated reply for the given abuse email to the
// original email sender. This is extracted in a standalone function for unit
// testing purposes.
func sendAutomatedReply(auth smtp.Auth, email database.AbuseEmail) error {
	// generate a uuid as message id
	var u *uuid.UUID
	u, err := uuid.NewV4()
	if err != nil {
		return errors.AddContext(err, "failed to generate uid")
	}

	// construct the email message
	msg := fmt.Sprintf("Subject: Re: %s\n", email.Subject)
	msg += fmt.Sprintf("Message-ID: <%s@abusescanner>\n", u)
	msg += fmt.Sprintf("References: %s\n", email.MessageID)
	msg += fmt.Sprintf("In-Reply-To: %s\n", email.MessageID)
	msg += fmt.Sprintf("From: <%s>\n", email.To)
	msg += fmt.Sprintf("To:%s\n", email.Sender())
	msg += ""
	msg += email.Response()

	// send the automated response
	err = smtp.SendMail("smtp.gmail.com:587", auth, email.To, []string{email.Sender()}, []byte(msg))
	if err != nil {
		return err
	}
	return nil
}
