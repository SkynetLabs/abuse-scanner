package email

import (
	"abuse-scanner/database"
	"context"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"gitlab.com/NebulousLabs/errors"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

const (
	// fetchFrequency defines the frequency with which we fetch new emails
	fetchFrequency = 30 * time.Second
)

type (
	// Fetcher is an object that will periodically scan an inbox and persist the
	// missing messages in the database.
	Fetcher struct {
		staticContext                context.Context
		staticDatabase               *database.AbuseScannerDB
		staticEmailClient            *client.Client
		staticEmailClientReconnectFn ReconnectFn
		staticLogger                 *logrus.Entry
		staticMailbox                string
		staticWaitGroup              sync.WaitGroup
	}

	// ReconnectFn is a helper type that describes a function that reconnects
	// the email client in case it has dropped its connection.
	ReconnectFn func() error
)

// NewFetcher creates a new fetcher.
func NewFetcher(ctx context.Context, database *database.AbuseScannerDB, emailClient *client.Client, mailbox string, reconnectFn ReconnectFn, logger *logrus.Logger) *Fetcher {
	return &Fetcher{
		staticContext:                ctx,
		staticDatabase:               database,
		staticEmailClient:            emailClient,
		staticEmailClientReconnectFn: reconnectFn,
		staticLogger:                 logger.WithField("module", "Fetcher"),
		staticMailbox:                mailbox,
	}
}

// Start initializes the fetch process.
func (f *Fetcher) Start() error {
	// list mailboxes
	mailboxes, err := f.listMailboxes()
	if err != nil {
		return err
	}

	// check whether the mailbox exists
	found := false
	for _, m := range mailboxes {
		if m == f.staticMailbox {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("mailbox '%v' not found", f.staticMailbox)
	}

	f.staticWaitGroup.Add(1)
	go func() {
		f.threadedFetchMessages()
		f.staticWaitGroup.Done()
	}()
	return nil
}

// Stop waits for the fetcher's waitgroup and times out after one minute.
func (f *Fetcher) Stop() error {
	c := make(chan struct{})
	go func() {
		defer close(c)
		f.staticWaitGroup.Wait()
	}()
	select {
	case <-c:
		return nil
	case <-time.After(time.Minute):
		return errors.New("unclean fetcher shutdown")
	}
}

// listMailboxes returns all IMAP mailboxes
func (f *Fetcher) listMailboxes() ([]string, error) {
	// convenience variables
	email := f.staticEmailClient

	// list all mailboxes
	mailboxesChan := make(chan *imap.MailboxInfo, 10)
	done := make(chan error, 1)
	go func() {
		done <- email.List("", "*", mailboxesChan)
	}()

	// add all inboxes to an array
	mailboxes := make([]string, 0)
	for m := range mailboxesChan {
		mailboxes = append(mailboxes, m.Name)
	}

	// check whether an error occurred
	err := <-done
	if err != nil {
		return nil, err
	}
	return mailboxes, nil
}

// threadedFetchMessages will periodically fetch new messages from the mailbox.
func (f *Fetcher) threadedFetchMessages() {
	// convenience variables
	logger := f.staticLogger

	ticker := time.NewTicker(fetchFrequency)
	first := true

	// start the loop
	for {
		// sleep until next iteration, sleeping at the start of the for loop
		// allows to 'continue' on error.
		if !first {
			select {
			case <-f.staticContext.Done():
				logger.Debugln("Fetcher context done")
				return
			case <-ticker.C:
			}
		}
		first = false

		logger.Debugln("Triggered")

		// select the mailbox in every iteration (the uid validity might change)
		mailbox, err := f.staticEmailClient.Select(f.staticMailbox, false)
		if err == client.ErrNotLoggedIn {
			logger.Debugln("Client not logged in, try reconnecting...")
			err = f.staticEmailClientReconnectFn()
			if err == nil {
				logger.Debugln("reconnect succeeded, selecting mailbox")
				mailbox, err = f.staticEmailClient.Select(f.staticMailbox, false)
			}
		}
		if err != nil {
			logger.Errorf("Failed selecting mailbox %v, error %v", f.staticMailbox, err)
			continue
		}

		// get all message ids
		msgs, err := f.getMessageIds()
		if err != nil {
			logger.Errorf("Failed listing messages, error %v", err)
			continue
		}

		// get missing messages
		missing, err := f.getMessagesToFetch(mailbox, msgs)
		if err != nil {
			logger.Errorf("Failed listing messages, error %v", err)
		}

		// log missing messages count
		numMissing := len(missing)
		if numMissing == 0 {
			logger.Debugf("Found %v missing messages", numMissing)
			continue
		}
		logger.Infof("Found %v missing messages", numMissing)

		// fetch messages
		for _, msgUid := range missing {
			seqSet := new(imap.SeqSet)
			seqSet.AddNum(msgUid)
			err := f.fetchMessages(mailbox, seqSet)
			if err != nil {
				logger.Errorf("Failed fetching message %v, error %v", msgUid, err)
			}
		}
	}
}

// getMessageIds lists all messages in the current mailbox
func (f *Fetcher) getMessageIds() ([]uint32, error) {
	// convenience variables
	email := f.staticEmailClient
	logger := f.staticLogger

	// construct seq set
	seqset, err := imap.ParseSeqSet("1:*")
	if err != nil {
		return nil, err
	}

	// fetch all messages
	messageChan := make(chan *imap.Message)
	go func() {
		err = email.Fetch(seqset, []imap.FetchItem{imap.FetchUid}, messageChan)
		if err != nil {
			logger.Errorf("Failed listing messages, error: %v\n", err)
		}
	}()

	// build the map
	var ids []uint32
	for msg := range messageChan {
		ids = append(ids, msg.Uid)
	}
	return ids, nil
}

// getMessagesToFetch returns which messages are not in our database
//
// TODO: improve performance, there's no need to do N findOne's
func (f *Fetcher) getMessagesToFetch(mailbox *imap.MailboxStatus, msgs []uint32) ([]uint32, error) {
	// convenience variables
	database := f.staticDatabase
	logger := f.staticLogger

	// create an array to hold the messages that are missing
	toFetch := make([]uint32, 0, len(msgs))
	for _, msgUid := range msgs {
		uid := buildMessageUID(mailbox, msgUid)
		email, err := database.FindOne(uid)
		if err != nil {
			logger.Errorf("failed to find message '%v', error: %v", msgUid, err)
			continue
		}

		// if the message is missing, append it to the list of msg uids to fetch
		if email == nil {
			toFetch = append(toFetch, msgUid)
		}
	}
	return toFetch, nil
}

// fetchMessages fetches all messages in the given seq set and persists them in // the database
func (f *Fetcher) fetchMessages(mailbox *imap.MailboxStatus, toFetch *imap.SeqSet) error {
	// convenience variables
	email := f.staticEmailClient
	logger := f.staticLogger

	messageChan := make(chan *imap.Message)
	section, err := imap.ParseBodySectionName("BODY[]")
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		done <- email.UidFetch(toFetch, []imap.FetchItem{imap.FetchEnvelope, section.FetchItem()}, messageChan)
	}()

	toUnsee := new(imap.SeqSet)
	for msg := range messageChan {
		// skip messages that have been sent by the abuse scanner itself, since
		// we reply to the original email those replies are picked up by the
		// scanner as well
		if isFromAbuseScanner(msg) {
			logger.Debugf("skip message from abuse scanner (expected)")
			err := f.persistSkipMessage(mailbox, msg)
			if err != nil {
				logger.Errorf("Failed to persist skip message, error: %v\n", err)
			}
			continue
		}

		// skip messages without body
		//
		// TODO: side-effect from UidFetch and can probably be avoided
		if !hasBody(msg) {
			logger.Debugf("skip message due to not having a body (expected)")
			err := f.persistSkipMessage(mailbox, msg)
			if err != nil {
				logger.Errorf("Failed to persist skip message, error: %v\n", err)
			}
			continue
		}

		toUnsee.AddNum(msg.Uid)
		err := f.persistMessage(mailbox, msg, section)
		if err != nil {
			logger.Errorf("Failed to persist %v, error: %v\n", msg.Uid, err)
		}
	}

	// unsee messages
	flags := []interface{}{imap.SeenFlag}
	err = email.UidStore(toUnsee, "-FLAGS.SILENT", flags, nil)
	if err != nil && !strings.Contains(err.Error(), "Could not parse command") {
		logger.Debugf("Failed to unsee messages, error: %v\n", err)
	} else {
		logger.Debugln("Successfully unseen messages")
	}

	// return the (possible) error value from the done channel
	return <-done
}

// persistMessage will persist the given message in the abuse scanner database
func (f *Fetcher) persistMessage(mailbox *imap.MailboxStatus, msg *imap.Message, section *imap.BodySectionName) error {
	// convenience variables
	abuseDB := f.staticDatabase

	// build the uid
	uid := buildMessageUID(mailbox, msg.Uid)

	// read the entire message body
	bodyLit := msg.GetBody(section)
	if bodyLit == nil {
		return fmt.Errorf("msg %v has no body", uid)
	}
	body, err := ioutil.ReadAll(bodyLit)
	if err != nil {
		return errors.AddContext(err, "could not read msg body")
	}

	// parse the 'from'
	from := "unknown"
	if len(msg.Envelope.From) > 0 {
		from = msg.Envelope.From[0].Address()
	}

	// create the email entity from the message
	email := database.AbuseEmail{
		ID:        primitive.NewObjectID(),
		UID:       uid,
		UIDRaw:    msg.Uid,
		Body:      body,
		From:      from,
		Subject:   msg.Envelope.Subject,
		MessageID: msg.Envelope.MessageId,

		Parsed:    false,
		Blocked:   false,
		Finalized: false,

		InsertedAt: time.Now().UTC(),
	}

	// insert the message in the database
	err = abuseDB.InsertOne(email)
	if err != nil {
		return errors.AddContext(err, "could not insert email")
	}
	return nil
}

// persistSkipMessage will persist the given message as finalized in the abuse
// scanner database, this ensures the message won't be considered 'missing'
func (f *Fetcher) persistSkipMessage(mailbox *imap.MailboxStatus, msg *imap.Message) error {
	// convenience variables
	abuseDB := f.staticDatabase

	// build the uid
	uid := buildMessageUID(mailbox, msg.Uid)

	// skip if it already exists
	exists, err := abuseDB.Exists(uid)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	// create the email entity from the message
	email := database.AbuseEmail{
		ID:     primitive.NewObjectID(),
		UID:    uid,
		UIDRaw: msg.Uid,

		Parsed:    true,
		Blocked:   true,
		Finalized: true,

		Skip: true,

		InsertedAt: time.Now().UTC(),
	}

	// insert the message in the database
	err = abuseDB.InsertOne(email)
	if err != nil {
		return errors.AddContext(err, "could not insert email")
	}
	return nil
}

// buildMessageUID is a helper function that builds a unique id for the message
func buildMessageUID(mailbox *imap.MailboxStatus, msgUid uint32) string {
	return fmt.Sprintf("%v-%v-%v", mailbox.Name, mailbox.UidValidity, msgUid)
}

// isFromAbuseScanner returns true if the given message was sent by the abuse
// scanner itself
func isFromAbuseScanner(msg *imap.Message) bool {
	if msg.Envelope == nil {
		return false
	}
	if len(msg.Envelope.From) != 1 {
		return false
	}
	return msg.Envelope.From[0].Address() == scannerEmailAddress
}

// hasBody returns true if the given message has a body
func hasBody(msg *imap.Message) bool {
	sectionName, err := imap.ParseBodySectionName(imap.FetchItem("BODY[]"))
	if err != nil {
		return false
	}
	bodyLit := msg.GetBody(sectionName)
	if bodyLit == nil {
		return false
	}
	return true
}
