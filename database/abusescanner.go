package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	lock "github.com/square/mongo-lock"
	"gitlab.com/NebulousLabs/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	// AbuseStatusBlocked denotes the blocked status.
	AbuseStatusBlocked = "BLOCKED"

	// AbuseStatusNotBlocked denotes the not blocked status.
	AbuseStatusNotBlocked = "NOT BLOCKED"

	// AbuseDefaultTag is the tag used when there are no tags found in the email
	AbuseDefaultTag = "abusive"

	// collEmails is the name of the collection that contains all email objects
	collEmails = "emails"

	// collLocks is the name of the collection that contains locks
	collLocks = "locks"

	// dbName defines the name of the mongo database
	dbName = "abuse-scanner"

	// lockOwnerName is passed as the 'Owner' when creating a new lock in
	// the db for tus uploads.
	lockOwnerName = "Abuse Scanner"

	// lockTTL is the time-to-live in seconds for a lock
	lockTTL = 300 // 5 minutes
)

var (
	// mongoDefaultTimeout is the default timeout for mongo operations that
	// require a context but where the input arguments don't contain a
	// context.
	mongoDefaultTimeout = time.Minute

	// mongoErrNoDocuments is returned when a database operation completes
	// successfully but it doesn't find or affect any documents.
	mongoErrNoDocuments = errors.New("no documents in result")
)

type (
	// AbuseScannerDB wraps a generic mongo database
	AbuseScannerDB struct {
		MongoDB
		lock.Client
		staticPortalHostName string
	}

	// AbuseEmail represent an object in the emails collection.
	AbuseEmail struct {
		ID        primitive.ObjectID `bson:"_id"`
		UID       string             `bson:"email_uid"`
		UIDRaw    uint32             `bson:"email_uid_raw"`
		Body      []byte             `bson:"email_body"`
		From      string             `bson:"email_from"`
		Subject   string             `bson:"email_subject"`
		MessageID string             `bson:"email_message_id"`

		// fields set by parser
		ParsedAt    time.Time   `bson:"parsed_at"`
		ParseResult AbuseReport `bson:"parseResult"`
		Parsed      bool        `bson:"parsed"`

		// fields set by blocker
		BlockedAt   time.Time `bson:"blocked_at"`
		BlockResult []string  `bson:"blockResult"`
		Blocked     bool

		InsertedAt time.Time `bson:"inserted_at"`
		Finalized  bool
	}

	// AbuseReport contains all information about an abuse report.
	AbuseReport struct {
		Skylinks []string
		Reporter AbuseReporter
		Sponsor  string
		Tags     []string
	}

	// AbuseReporter encapsulates some information about the reporter.
	AbuseReporter struct {
		Name         string
		Email        string
		OtherContact string
	}

	// abuseEmailLock represents a lock on an abuse email.
	abuseEmailLock struct {
		staticClient         *lock.Client
		staticEmailUID       string
		staticPortalHostname string
	}
)

// String returns a string representation of the abuse email
func (a AbuseEmail) String() string {
	var sb strings.Builder
	pr := a.ParseResult
	sb.WriteString("\nAbuse Scanner Report:\n")

	sb.WriteString("\nReporter:\n")
	sb.WriteString(fmt.Sprintf("Name: %v\n", pr.Reporter.Name))
	sb.WriteString(fmt.Sprintf("Email: %v\n", pr.Reporter.Email))

	sb.WriteString("\nTags:\n")
	for _, tag := range pr.Tags {
		sb.WriteString(tag + "\n")
	}

	allBlocked := true
	sb.WriteString("\nSkylinks:\n")
	for i, skylink := range pr.Skylinks {
		var parts []string
		if a.BlockResult[i] == AbuseStatusBlocked {
			parts = []string{AbuseStatusBlocked, skylink}
		} else {
			parts = []string{AbuseStatusNotBlocked, skylink, a.BlockResult[i]}
			allBlocked = false
		}
		switch a.BlockResult[i] {
		case AbuseStatusBlocked:
		default:
		}
		sb.WriteString(fmt.Sprintf("%s\n", strings.Join(parts, " | ")))
	}

	sb.WriteString("\nSummary:\n")
	if len(pr.Skylinks) == 0 {
		sb.WriteString("FAILURE - no skylinks found.\n")
	} else {
		if allBlocked {
			sb.WriteString("SUCCESS\n")
		} else {
			sb.WriteString("FAILURE - not all skylinks blocked.\n")
		}
	}

	return sb.String()
}

// NewAbuseScannerDB returns an instance of the Mongo DB.
func NewAbuseScannerDB(connectionString, portalHostName string, logger *logrus.Logger) (*AbuseScannerDB, error) {
	// create the client
	opts := options.Client().ApplyURI(connectionString)
	client, err := mongo.NewClient(opts)
	if err != nil {
		return nil, err
	}

	// create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	// connect to the client
	err = client.Connect(ctx)
	if err != nil {
		return nil, err
	}

	// get a database handler
	database := client.Database(dbName)

	// ensure the locks collection
	if database.Collection(collLocks) == nil {
		err = database.CreateCollection(ctx, collLocks)
		if err != nil {
			return nil, err
		}
	}

	// create the mongo database
	db := &AbuseScannerDB{
		MongoDB{
			staticClient:   client,
			staticDatabase: database,
			staticLogger:   logger,
			staticName:     dbName,
		},
		*lock.NewClient(database.Collection(collLocks)),
		portalHostName,
	}

	// the lock client creates its own indices
	err = db.CreateIndexes(ctx)
	if err != nil {
		return nil, errors.AddContext(err, "failed to create indices on locks")
	}

	// ensure the schema
	err = db.ensureSchema(ctx, map[string][]mongo.IndexModel{
		collEmails: {
			{
				Keys:    bson.D{{"email_uid", 1}},
				Options: options.Index().SetUnique(true),
			},
			{
				Keys:    bson.D{{"parsed", 1}},
				Options: options.Index(),
			},
			{
				Keys:    bson.D{{"blocked", 1}},
				Options: options.Index(),
			},
			{
				Keys:    bson.D{{"finalized", 1}},
				Options: options.Index(),
			},
		},
	})
	if err != nil {
		return nil, err
	}

	return db, nil
}

// FindOne returns the message with given uid
func (db *AbuseScannerDB) FindOne(emailUid string) (*AbuseEmail, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	collEmails := db.staticDatabase.Collection(collEmails)
	res := collEmails.FindOne(ctx, bson.M{"email_uid": emailUid})
	if isDocumentNotFound(res.Err()) {
		return nil, nil
	}
	if res.Err() != nil {
		return nil, res.Err()
	}

	var email AbuseEmail
	err := res.Decode(&email)
	if err != nil {
		return nil, err
	}
	return &email, nil
}

// FindUnblocked returns the messages that have not been blocked.
func (db *AbuseScannerDB) FindUnblocked() ([]AbuseEmail, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	collEmails := db.staticDatabase.Collection(collEmails)
	cursor, err := collEmails.Find(ctx, bson.M{"blocked": false})
	if err != nil {
		return nil, errors.AddContext(err, "could not retrieve unblocked emails")
	}

	var emails []AbuseEmail
	err = cursor.All(context.Background(), &emails)
	if err != nil {
		db.staticLogger.Error("failed to parse emails", err)
	}

	return emails, nil
}

// FindUnfinalized returns the messages that have not been finalized.
func (db *AbuseScannerDB) FindUnfinalized() ([]AbuseEmail, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	collEmails := db.staticDatabase.Collection(collEmails)
	cursor, err := collEmails.Find(ctx, bson.M{
		"parsed":    true,
		"blocked":   true,
		"finalized": false,
	})
	if err != nil {
		return nil, errors.AddContext(err, "could not retrieve unfinalized emails")
	}

	var emails []AbuseEmail
	err = cursor.All(context.Background(), &emails)
	if err != nil {
		db.staticLogger.Error("failed to parse emails", err)
	}

	return emails, nil
}

// FindUnparsed returns the messages that have not been parsed.
func (db *AbuseScannerDB) FindUnparsed() ([]AbuseEmail, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	collEmails := db.staticDatabase.Collection(collEmails)
	cursor, err := collEmails.Find(ctx, bson.M{"parsed": false})
	if err != nil {
		return nil, errors.AddContext(err, "could not retrieve unparsed emails")
	}

	var emails []AbuseEmail
	for cursor.Next(context.Background()) {
		var email AbuseEmail
		err = cursor.Decode(&email)
		if err != nil {
			db.staticLogger.Error("failed to parse email", err)
			continue
		}
		emails = append(emails, email)
	}

	return emails, nil
}

// InsertOne inserts the given email into the database
func (db *AbuseScannerDB) InsertOne(email AbuseEmail) (err error) {
	lock := db.NewLock(email.UID)

	// acquire a lock on the email UID and defer an unlock
	err = lock.Lock()
	if err != nil {
		return err
	}
	defer func() {
		unLockErr := lock.Unlock()
		err = errors.Compose(err, unLockErr)
	}()

	// create a context with default timeout
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	collEmails := db.staticDatabase.Collection(collEmails)
	_, err = collEmails.InsertOne(ctx, email)
	if err != nil {
		return err
	}

	return nil
}

// NewLock returns a new abuse email lock for an email with given uid.
func (db *AbuseScannerDB) NewLock(emailUID string) *abuseEmailLock {
	return &abuseEmailLock{
		staticClient:         &db.Client,
		staticEmailUID:       emailUID,
		staticPortalHostname: db.staticPortalHostName,
	}
}

// UpdateNoLock will update the given email, this method does not lock the given
// email as it is expected for the caller to have acquired the lock.
func (db *AbuseScannerDB) UpdateNoLock(email AbuseEmail) (err error) {
	fmt.Println("updating email", email.UID)
	fmt.Println("blocked: ", email.Blocked)
	fmt.Println("block result: ", email.BlockResult)
	// create a context with default timeout
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	collEmails := db.staticDatabase.Collection(collEmails)
	_, err = collEmails.ReplaceOne(ctx, bson.M{"email_uid": email.UID}, email)
	if err != nil {
		return err
	}

	return nil
}

// Lock exclusively locks the lock. It returns handler.ErrFileLocked if the
// email is already locked and it will put an expiration time on the lock in
// case the server dies while the file is locked. That way emails won't remain
// locked forever.
func (l *abuseEmailLock) Lock() error {
	client := l.staticClient
	ld := lock.LockDetails{
		Owner: lockOwnerName,
		Host:  l.staticPortalHostname,
		TTL:   lockTTL,
	}

	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	return client.XLock(ctx, l.staticEmailUID, l.staticEmailUID, ld)
}

// Unlock attempts to unlock an email. It will retry doing so for a certain
// time before giving up.
func (l *abuseEmailLock) Unlock() error {
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	var err error
	for {
		_, err = l.staticClient.Unlock(ctx, l.staticEmailUID)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(time.Second):
		}
	}
}

// isDocumentNotFound is a helper function that returns whether the given error
// contains the mongo documents not found error message.
func isDocumentNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), mongoErrNoDocuments.Error())
}
