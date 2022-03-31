package database

import (
	"abuse-scanner/test"
	"context"
	"io/ioutil"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gitlab.com/NebulousLabs/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	// DBSkynet defines the name of the mongo database
	DBSkynet = "skynet"

	// collSkylinks is the name of the collection that contains all skylinks
	collSkylinks = "skylinks"

	// collUploads is the name of the collection that contains all uploads
	collUploads = "uploads"

	// collUsers is the name of the collection that contains all users
	collUsers = "users"
)

var (
	// AnonUserID represents the user ID used for anonymous uploads
	AnonUserID primitive.ObjectID
)

type (
	// SkynetDB wraps a generic mongo database
	SkynetDB struct {
		MongoDB
	}

	// SkynetUpload is a helper struct that represents a projection of an upload
	// document in the skynet database.
	SkynetUpload struct {
		SkylinkID  primitive.ObjectID `bson:"skylink_id,omitempty" json:"skylinkId"`
		Timestamp  time.Time          `bson:"timestamp" json:"timestamp"`
		UploaderIP string             `bson:"uploader_ip" json:"uploaderIP"`
		UserID     primitive.ObjectID `bson:"user_id,omitempty" json:"userId"`
	}

	// SkynetUploadHydrated is a helper struct that represents an upload where
	// the skylink and user are decorated.
	SkynetUploadHydrated struct {
		SkynetUpload

		Skylink string
		User    *SkynetUser
	}

	// SkynetSkylink is a helper struct that represents a skylink
	SkynetSkylink struct {
		ID      primitive.ObjectID `bson:"_id,omitempty" json:"id"`
		Skylink string             `bson:"skylink" json:"skylink"`
	}

	// SkynetUser is a helper struct that represents a projection of a user
	// document in the skynet database.
	SkynetUser struct {
		ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
		Email     string             `bson:"email" json:"email"`
		CreatedAt time.Time          `bson:"created_at" json:"createdAt"`
		StripeID  string             `bson:"stripe_id" json:"stripeCustomerId"`
	}

	// document is a helper struct to decode the mongo object id
	document struct {
		ID primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	}
)

// NewSkynetDB returns an instance of the Mongo DB.
func NewSkynetDB(ctx context.Context, mongoDbName, mongoUri string, mongoCreds options.Credential, logger *logrus.Logger) (*SkynetDB, error) {
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

	// create the mongo database
	return &SkynetDB{
		MongoDB{
			staticClient:   client,
			staticDatabase: database,
			staticLogger:   logger,
			staticName:     mongoDbName,
		},
	}, nil
}

// NewTestSkynetDB returns a new test database.
//
// NOTE: the database is purged before it gets returned.
func NewTestSkynetDB(ctx context.Context, dbName string, logger *logrus.Logger) (*SkynetDB, error) {
	// create a nil logger if none is passed
	if logger == nil {
		logger = logrus.New()
		logger.Out = ioutil.Discard
	}

	// create the database
	dbName = strings.Replace(dbName, "/", "_", -1)
	db, err := NewSkynetDB(ctx, dbName, test.MongoDBConnString, options.Credential{
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
func (db *SkynetDB) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()
	return db.staticClient.Disconnect(ctx)
}

// FindUpload returns the upload corresponding to the given skylink. Note that
// we return a hydrated version of the upload where the skylink and user object
// are decorated onto the object.
func (db *SkynetDB) FindUpload(skylink string) (*SkynetUploadHydrated, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	skylinks := db.staticDatabase.Collection(collSkylinks)
	res := skylinks.FindOne(ctx, bson.M{"skylink": skylink})
	if isDocumentNotFound(res.Err()) {
		return nil, nil
	}

	var doc document
	err := res.Decode(&doc)
	if err != nil {
		return nil, err
	}

	uploads := db.staticDatabase.Collection(collUploads)
	res = uploads.FindOne(ctx, bson.M{"skylink_id": doc.ID})
	if isDocumentNotFound(res.Err()) {
		return nil, nil
	}
	if res.Err() != nil {
		return nil, res.Err()
	}

	var upload SkynetUpload
	err = res.Decode(&upload)
	if err != nil {
		return nil, err
	}

	user, _ := db.FindUser(upload.UserID)
	hydrated := SkynetUploadHydrated{
		SkynetUpload: upload,
		Skylink:      skylink,
		User:         user,
	}
	return &hydrated, nil
}

// FindUploadsPerUser returns the uploads, grouped per user, for the given
// skylinks. The return value is a map where the key is the user id and the
// value is the list of uploads.
func (db *SkynetDB) FindUploadsPerUser(skylinks []string) (map[string][]*SkynetUploadHydrated, error) {
	grouped := make(map[string][]*SkynetUploadHydrated, 0)

	for _, skylink := range skylinks {
		upload, err := db.FindUpload(skylink)
		if err != nil {
			return nil, err
		}

		// if there's no upload init an empty upload
		if upload == nil {
			upload = &SkynetUploadHydrated{
				Skylink: skylink,
				SkynetUpload: SkynetUpload{
					UserID: AnonUserID,
				},
			}
		}

		user := upload.UserID.Hex()
		grouped[user] = append(grouped[user], upload)
	}

	return grouped, nil
}

// FindUser returns the user corresponding to the given mongo object id.
func (db *SkynetDB) FindUser(id primitive.ObjectID) (*SkynetUser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	users := db.staticDatabase.Collection(collUsers)
	res := users.FindOne(ctx, bson.M{"_id": id})
	if isDocumentNotFound(res.Err()) {
		return nil, nil
	}

	var user SkynetUser
	err := res.Decode(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// FindUserByEmail returns the user corresponding to the given email address.
func (db *SkynetDB) FindUserByEmail(email string) (*SkynetUser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	users := db.staticDatabase.Collection(collUsers)
	res := users.FindOne(ctx, bson.M{"email": email})
	if isDocumentNotFound(res.Err()) {
		return nil, nil
	}

	var user SkynetUser
	err := res.Decode(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// InsertTestUpload inserts the given upload document in the respective
// collections.
//
// NOTE: this method is only used in testing to insert dummy records.
func (db *SkynetDB) InsertTestUpload(upload *SkynetUploadHydrated) error {
	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	insert := upload.SkynetUpload

	// insert the skylink
	skylinks := db.staticDatabase.Collection(collSkylinks)
	res, err := skylinks.InsertOne(ctx, SkynetSkylink{Skylink: upload.Skylink})
	if err != nil {
		return err
	}
	insert.SkylinkID = res.InsertedID.(primitive.ObjectID)

	// insert the user
	if upload.User != nil {
		user, err := db.FindUserByEmail(upload.User.Email)
		if err != nil {
			return err
		}
		if user == nil {
			users := db.staticDatabase.Collection(collUsers)
			res, err = users.InsertOne(ctx, *upload.User)
			if err != nil {
				return err
			}
			insert.UserID = res.InsertedID.(primitive.ObjectID)
		} else {
			insert.UserID = user.ID
		}
	}

	// insert the upload
	uploads := db.staticDatabase.Collection(collUploads)
	_, err = uploads.InsertOne(ctx, insert)
	if err != nil {
		return err
	}

	return nil
}

// Purge removes all documents from the uploads, users and skylinks collection
func (db *SkynetDB) Purge(ctx context.Context) error {
	collSkylinks := db.staticDatabase.Collection(collSkylinks)
	collUploads := db.staticDatabase.Collection(collUploads)
	collUsers := db.staticDatabase.Collection(collUsers)

	_, purgeSkyinksErr := collSkylinks.DeleteMany(ctx, bson.M{})
	_, purgeUploadsErr := collUploads.DeleteMany(ctx, bson.M{})
	_, purgeUsersErr := collUsers.DeleteMany(ctx, bson.M{})

	return errors.Compose(purgeSkyinksErr, purgeUploadsErr, purgeUsersErr)
}

// IsAnon returns true if the upload represents an upload done by an anonymous
// user.
func (u *SkynetUpload) IsAnon() bool {
	return u.UserID.Hex() == AnonUserID.Hex()
}
