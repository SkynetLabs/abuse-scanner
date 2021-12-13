package email

import (
	"abuse-scanner/database"
	"context"
	"fmt"
	"io/ioutil"
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
		staticContext     context.Context
		staticDatabase    *database.AbuseScannerDB
		staticEmailClient *client.Client
		staticLogger      *logrus.Logger
		staticMailbox     string
	}

	// messageIDMap is a helper struct that maps the message uid to its seq num
	messageIDMap map[uint32]uint32
)

// NewFetcher creates a new fetcher.
func NewFetcher(ctx context.Context, database *database.AbuseScannerDB, emailClient *client.Client, mailbox string, logger *logrus.Logger) *Fetcher {
	return &Fetcher{
		staticContext:     ctx,
		staticDatabase:    database,
		staticEmailClient: emailClient,
		staticLogger:      logger,
		staticMailbox:     mailbox,
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
		fmt.Println("mailbox ", m)
		if m == f.staticMailbox {
			found = true
			break
		}
	}
	if !found {
		return errors.New("mailbox not found")
	}

	go f.threadedFetchMessages()
	return nil
}

// listMailboxes returns all mailboxes
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
	first := true

	// start the loop
	for {
		// sleep until next iteration, sleeping at the start of the for loop
		// allows to 'continue' on error.
		if !first {
			select {
			case <-f.staticContext.Done():
				return
			case <-time.After(fetchFrequency):
			}
		}
		first = false

		// select the mailbox in every iteration (the uid validity might change)
		mailbox, err := f.staticEmailClient.Select(f.staticMailbox, false)
		if err != nil {
			logger.Errorf("Failed selecting mailbox %v, error %v", f.staticMailbox, err)
			continue
		}

		// get all message ids
		logger.Debugln("Listing messages...")
		msgs, err := f.getMessageIds()
		if err != nil {
			logger.Errorf("Failed listing messages, error %v", err)
		}

		logger.Debugf("Found %v messages in mailbox %v\n", len(msgs), f.staticMailbox)

		// get missing messages
		missing, err := f.getMessagesToFetch(mailbox, msgs)
		if err != nil {
			logger.Errorf("Failed listing messages, error %v", err)
		}
		logger.Debugf("%v messages missing", len(missing))

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

		// if not append it to the list of ids to fetch
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
	section := &imap.BodySectionName{}
	done := make(chan error, 1)
	go func() {
		done <- email.UidFetch(toFetch, []imap.FetchItem{imap.FetchBody, section.FetchItem(), imap.FetchEnvelope}, messageChan)
	}()

	for msg := range messageChan {
		err := f.persistMessage(mailbox, msg)
		if err != nil {
			logger.Errorf("Failed to persist %v, error: %v\n", msg.SeqNum, err)
		}
	}
	return <-done
}

// persistMessage will persist the given message in the abuse scanner database
func (f *Fetcher) persistMessage(mailbox *imap.MailboxStatus, msg *imap.Message) error {
	// convenience variables
	abuseDB := f.staticDatabase

	// build the uid
	uid := buildMessageUID(mailbox, msg.Uid)

	// parse out the body
	sectionName, err := imap.ParseBodySectionName(imap.FetchItem("BODY[]"))
	if err != nil {
		return errors.AddContext(err, "could not parse msg body")
	}

	// read the entire message body
	bodyLit := msg.GetBody(sectionName)
	if bodyLit == nil {
		return fmt.Errorf("msg %v has no body", uid)
	}
	body, err := ioutil.ReadAll(msg.GetBody(sectionName))
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
		ID:      primitive.NewObjectID(),
		UID:     uid,
		UIDRaw:  msg.Uid,
		Body:    body,
		From:    from,
		Subject: msg.Envelope.Subject,

		Parsed:    false,
		Blocked:   false,
		Finalized: false,

		InsertedAt: time.Now(),
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
