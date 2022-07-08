package email

import (
	"abuse-scanner/database"
	"context"
	"fmt"
	"io"
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

	// mailMaxBodySize is the maximum amount of bytes read from the email body
	mailMaxBodySize = 1 << 23 // 8MiB
)

type (
	// Fetcher is an object that will periodically scan an inbox and persist the
	// missing messages in the database.
	Fetcher struct {
		staticContext          context.Context
		staticDatabase         *database.AbuseScannerDB
		staticEmailCredentials Credentials
		staticLogger           *logrus.Entry
		staticMailbox          string
		staticServerDomain     string
		staticWaitGroup        sync.WaitGroup
	}
)

// NewFetcher creates a new fetcher.
func NewFetcher(ctx context.Context, database *database.AbuseScannerDB, emailCredentials Credentials, mailbox, serverDomain string, logger *logrus.Logger) *Fetcher {
	return &Fetcher{
		staticContext:          ctx,
		staticDatabase:         database,
		staticEmailCredentials: emailCredentials,
		staticLogger:           logger.WithField("module", "Fetcher"),
		staticMailbox:          mailbox,
		staticServerDomain:     serverDomain,
	}
}

// Start initializes the fetch process.
func (f *Fetcher) Start() error {
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

// threadedFetchMessages will periodically fetch new messages from the mailbox.
func (f *Fetcher) threadedFetchMessages() {
	// convenience variables
	logger := f.staticLogger

	// create a ticker
	ticker := time.NewTicker(fetchFrequency)

	// log information about the mailbox we're fetching from
	logger.Infof("Fetching messages for '%v' from mailbox '%v'", f.staticEmailCredentials.Username, f.staticMailbox)

	// start the loop
	for {
		logger.Debugln("threadedFetchMessages loop iteration triggered")
		f.fetchMessages()

		// sleep until next iteration
		select {
		case <-f.staticContext.Done():
			logger.Debugln("Fetcher context done")
			return
		case <-ticker.C:
		}
	}
}

// fetchMessages connects to the mailbox and downloads messages it has not seen
// yet. It will store these as abuse emails in the database.
func (f *Fetcher) fetchMessages() {
	// convenience variables
	logger := f.staticLogger

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

	// select the mailbox, we have to do this in every iteration as the
	// uid validity might change
	mailbox, err := client.Select(f.staticMailbox, false)
	if err != nil {
		logger.Errorf("Failed to select mailbox %v, err: %v", f.staticMailbox, err)
		return
	}

	// return early if the mailbox has no messages
	if mailbox.Messages == 0 {
		logger.Debugf("No messages in mailbox %v", f.staticMailbox)
		return
	}

	// get all message ids
	msgs, err := f.getMessageIds(client)
	if err != nil {
		logger.Errorf("Failed getting messages ids, err: %v", err)
		return
	}

	// get missing messages
	missing, err := f.getMessagesToFetch(mailbox, msgs)
	if err != nil {
		logger.Errorf("Failed listing messages, err: %v", err)
		return
	}

	// log missing messages count
	numMissing := len(missing)
	if numMissing == 0 {
		logger.Debugf("Found %v missing messages", numMissing)
		return
	}

	// fetch messages
	logger.Infof("Found %v missing messages", numMissing)
	for _, msgUid := range missing {
		seqSet := new(imap.SeqSet)
		seqSet.AddNum(msgUid)
		err := f.fetchMessagesByUid(client, mailbox, seqSet)
		if err != nil {
			logger.Errorf("Failed fetching message %v, err: %v", msgUid, err)
		}
	}
}

// fetchMessagesByUid fetches all messages in the given seq set and persists
// them in the database
func (f *Fetcher) fetchMessagesByUid(client *client.Client, mailbox *imap.MailboxStatus, toFetch *imap.SeqSet) error {
	// convenience variables
	logger := f.staticLogger

	messageChan := make(chan *imap.Message)
	section, err := imap.ParseBodySectionName("BODY[]")
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		done <- client.UidFetch(toFetch, []imap.FetchItem{imap.FetchEnvelope, section.FetchItem()}, messageChan)
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
				logger.Errorf("Failed to persist skip message, error: %v", err)
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
				logger.Errorf("Failed to persist skip message, error: %v", err)
			}
			continue
		}

		toUnsee.AddNum(msg.Uid)
		err := f.persistMessage(mailbox, msg, section)
		if err != nil {
			logger.Errorf("Failed to persist %v, error: %v", msg.Uid, err)
		}
	}

	// unsee messages
	flags := []interface{}{imap.SeenFlag}
	err = client.UidStore(toUnsee, "-FLAGS.SILENT", flags, nil)
	if err != nil && !strings.Contains(err.Error(), "Could not parse command") {
		logger.Debugf("Failed to unsee messages, error: %v", err)
	} else {
		logger.Debugln("Successfully unseen messages")
	}

	// return the (possible) error value from the done channel
	return <-done
}

// getMessageIds lists all messages in the current mailbox
func (f *Fetcher) getMessageIds(email *client.Client) ([]uint32, error) {
	// convenience variables
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
			logger.Errorf("Failed listing messages, error: %v", err)
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

// persistMessage will persist the given message in the abuse scanner database
func (f *Fetcher) persistMessage(mailbox *imap.MailboxStatus, msg *imap.Message, section *imap.BodySectionName) error {
	// sanity check parameters
	if mailbox == nil || msg == nil || section == nil {
		return errors.New("missing input parameters")
	}

	// convenience variables
	abuseDB := f.staticDatabase

	// build the uid
	uid := buildMessageUID(mailbox, msg.Uid)

	// read the entire message body
	bodyLit := msg.GetBody(section)
	if bodyLit == nil {
		return fmt.Errorf("msg %v has no body", uid)
	}

	// limit the amount of bytes we read from the body
	bodyReader := io.LimitReader(bodyLit, mailMaxBodySize)

	// read the imap literal into a byte slice
	body, err := ioutil.ReadAll(bodyReader)
	if err != nil {
		return errors.AddContext(err, "could not read msg body")
	}

	// create the email entity from the message
	email := database.AbuseEmail{
		ID:        primitive.NewObjectID(),
		UID:       uid,
		UIDRaw:    msg.Uid,
		Body:      body,
		Subject:   msg.Envelope.Subject,
		MessageID: msg.Envelope.MessageId,

		From:    extractField("From", msg.Envelope),
		ReplyTo: extractField("ReplyTo", msg.Envelope),
		To:      extractField("To", msg.Envelope),

		Parsed:    false,
		Blocked:   false,
		Finalized: false,

		InsertedBy: f.staticServerDomain,
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
	return bodyLit != nil
}

// extractField is a small helper function that takes an envelope and tries to
// extract the requested field, if the field is not found, or if it is empty, an
// empty string is returned
func extractField(field string, envelope *imap.Envelope) string {
	if envelope == nil {
		return ""
	}

	switch field {
	case "From":
		if len(envelope.From) > 0 {
			return envelope.From[0].Address()
		}
	case "To":
		if len(envelope.To) > 0 {
			return envelope.To[0].Address()
		}
	case "ReplyTo":
		if len(envelope.ReplyTo) > 0 {
			return envelope.ReplyTo[0].Address()
		}
	default:
	}

	return ""
}
