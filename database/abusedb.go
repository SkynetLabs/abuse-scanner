package database

import (
	"abuse-scanner/test"
	"context"
	"fmt"
	"io/ioutil"
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
	// DBAbuseScanner defines the name of the mongo database used by the scanner
	DBAbuseScanner = "abuse-scanner"

	// collEmails is the name of the collection that contains all email objects
	collEmails = "emails"

	// collLocks is the name of the collection that contains locks
	collLocks = "locks"

	// collNCMECReports is the name of the collection that contains all NCMEC
	// reports.
	collNCMECReports = "ncmec_reports"

	// lockOwnerName is passed as the 'Owner' when creating a new lock in
	// the db for tus uploads.
	lockOwnerName = "Abuse Scanner"

	// lockTTL is the time-to-live in seconds for a lock
	lockTTL = 300 // 5 minutes

	// resourceEmails is the resource name used when locking mails
	resourceEmails = "emails"
)

var (
	// mongoDefaultTimeout is the default timeout for mongo operations that
	// require a context but where the input arguments don't contain a
	// context.
	mongoDefaultTimeout = time.Minute

	// mongoErrCollectionExists is returned when a collection is created using a
	// name that's already taken by a collection that exists.
	mongoErrCollectionExists = errors.New("Collection already exists")

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

	// abuseLock represents a lock on an entity in the abuse database.
	abuseLock struct {
		staticClient         *lock.Client
		staticLockID         string
		staticPortalHostname string
		staticResourceName   string
	}
)

// NewAbuseScannerDB returns an instance of the Mongo DB.
func NewAbuseScannerDB(ctx context.Context, portalHostName, mongoDbName, mongoUri string, mongoCreds options.Credential, logger *logrus.Logger) (*AbuseScannerDB, error) {
	// create the client
	opts := options.Client().ApplyURI(mongoUri).SetAuth(mongoCreds)
	client, err := mongo.NewClient(opts)
	if err != nil {
		return nil, err
	}

	// create a context with timeout
	ctx, cancel := context.WithTimeout(ctx, mongoDefaultTimeout)
	defer cancel()

	// connect to the client
	err = client.Connect(ctx)
	if err != nil {
		return nil, err
	}

	// get a database handler
	database := client.Database(mongoDbName)

	// ensure the locks collection, this collection is managed by the
	// distributed locking library which also manages the creation of the proper
	// indices, which is why it's done separately from ensuring our own schema
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
			staticName:     DBAbuseScanner,
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
				Keys:    bson.M{"email_uid": 1},
				Options: options.Index().SetUnique(true),
			},
			{
				Keys:    bson.M{"parsed": 1},
				Options: options.Index(),
			},
			{
				Keys:    bson.M{"blocked": 1},
				Options: options.Index(),
			},
			{
				Keys:    bson.M{"finalized": 1},
				Options: options.Index(),
			},
			{
				Keys:    bson.M{"reported": 1},
				Options: options.Index(),
			},
		},
		collNCMECReports: {
			{
				Keys:    bson.M{"email_id": 1},
				Options: options.Index(),
			},
			{
				Keys:    bson.M{"filed": 1},
				Options: options.Index(),
			},
		},
	})
	if err != nil {
		return nil, err
	}

	return db, nil
}

// NewTestAbuseScannerDB returns a new test database.
//
// NOTE: the database is purged before it gets returned.
func NewTestAbuseScannerDB(ctx context.Context, dbName string) (*AbuseScannerDB, error) {
	// create a nil logger
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// create the database
	dbName = strings.Replace(dbName, "/", "_", -1)
	db, err := NewAbuseScannerDB(ctx, "", dbName, test.MongoDBConnString, options.Credential{
		Username: test.MongoDBUsername,
		Password: test.MongoDBPassword,
	}, logger)
	if err != nil {
		return nil, err
	}

	// purge the database
	err = db.Purge(ctx)
	if err != nil {
		return nil, err
	}

	return db, nil
}

// Close will disconnect from the database
func (db *AbuseScannerDB) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()
	return db.staticClient.Disconnect(ctx)
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
	emails, err := db.find(bson.M{
		"parsed":    true,
		"blocked":   false,
		"finalized": false,
	})
	if err != nil {
		return nil, errors.AddContext(err, "failed to find unblocked emails")
	}
	return emails, nil
}

// FindUnfinalized returns the messages that have not been finalized.
func (db *AbuseScannerDB) FindUnfinalized(mailbox string) ([]AbuseEmail, error) {
	emails, err := db.find(bson.M{
		"email_uid": bson.M{"$regex": primitive.Regex{
			Pattern: fmt.Sprintf("^%v-", mailbox),
		}},

		"parsed":    true,
		"blocked":   true,
		"finalized": false,
	})
	if err != nil {
		return nil, errors.AddContext(err, "failed to find unfinalized emails")
	}
	return emails, nil
}

// FindUnparsed returns the messages that have not been parsed.
func (db *AbuseScannerDB) FindUnparsed() ([]AbuseEmail, error) {
	emails, err := db.find(bson.M{
		"parsed":    false,
		"blocked":   false,
		"finalized": false,
	})
	if err != nil {
		return nil, errors.AddContext(err, "failed to find unparsed emails")
	}
	return emails, nil
}

// FindUnreported returns the messages that have the 'csam' tag but have not
// been reported to NCMEC.
func (db *AbuseScannerDB) FindUnreported() ([]AbuseEmail, error) {
	emails, err := db.find(bson.M{
		"parsed":   true,
		"reported": false,

		"parse_result.tags": "csam",
	})
	if err != nil {
		return nil, errors.AddContext(err, "failed to find unblocked emails")
	}
	return emails, nil
}

// Purge removes all documents from the emails and locks collection
func (db *AbuseScannerDB) Purge(ctx context.Context) error {
	collEmails := db.staticDatabase.Collection(collEmails)
	collLocks := db.staticDatabase.Collection(collLocks)
	collReports := db.staticDatabase.Collection(collNCMECReports)

	_, purgeEmailsErr := collEmails.DeleteMany(ctx, bson.M{})
	_, purgeLocksErr := collLocks.DeleteMany(ctx, bson.M{})
	_, purgeReportsErr := collReports.DeleteMany(ctx, bson.M{})

	return errors.Compose(purgeEmailsErr, purgeLocksErr, purgeReportsErr)
}

// find is a function that retrieves emails based on the given filter. It's a
// generic function that's re-used by the more verbose find methods which are
// exposed on the database.
func (db *AbuseScannerDB) find(filter interface{}) ([]AbuseEmail, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	collEmails := db.staticDatabase.Collection(collEmails)
	cursor, err := collEmails.Find(ctx, filter)
	if err != nil {
		return nil, errors.AddContext(err, "could not retrieve emails")
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

// Exists returns whether an email with the given uid already exists in the db.
func (db *AbuseScannerDB) Exists(uid string) (exists bool, err error) {
	lock := db.NewLock(uid)

	// acquire a lock on the email UID and defer an unlock
	err = lock.Lock()
	if err != nil {
		return false, err
	}
	defer func() {
		unLockErr := lock.Unlock()
		err = errors.Compose(err, unLockErr)
	}()

	email, err := db.FindOne(uid)
	if err != nil {
		return false, err
	}
	exists = email != nil
	return exists, nil
}

// NewLock returns a new abuse lock for an email with given id.
func (db *AbuseScannerDB) NewLock(lockID string) *abuseLock {
	return db.newLockCustom(resourceEmails, lockID)
}

// newLockCustom returns a new abuse lock for a resource with given id
func (db *AbuseScannerDB) newLockCustom(resourceName, lockID string) *abuseLock {
	return &abuseLock{
		staticClient:         &db.Client,
		staticLockID:         lockID,
		staticPortalHostname: db.staticPortalHostName,
		staticResourceName:   resourceName,
	}
}

// UpdateNoLock will update the given email, this method does not lock the given
// email as it is expected for the caller to have acquired the lock.
func (db *AbuseScannerDB) UpdateNoLock(email AbuseEmail, update interface{}) (err error) {
	// create a context with default timeout
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	collEmails := db.staticDatabase.Collection(collEmails)
	_, err = collEmails.UpdateOne(ctx, bson.M{"email_uid": email.UID}, update)
	if err != nil {
		return err
	}

	return nil
}

// Lock exclusively locks the lock. It returns handler.ErrFileLocked if the
// email is already locked and it will put an expiration time on the lock in
// case the server dies while the file is locked. That way emails won't remain
// locked forever.
func (l *abuseLock) Lock() error {
	client := l.staticClient
	ld := lock.LockDetails{
		Owner: lockOwnerName,
		Host:  l.staticPortalHostname,
		TTL:   lockTTL,
	}

	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	return client.XLock(ctx, "emails", l.staticLockID, ld)
}

// Unlock attempts to unlock an email. It will retry doing so for a certain
// time before giving up.
func (l *abuseLock) Unlock() error {
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	var err error
	for {
		_, err = l.staticClient.Unlock(ctx, l.staticLockID)
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
