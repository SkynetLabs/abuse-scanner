package database

import (
	"context"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// TODO: needs to be extended to cover all methods

const (
	// portalHostName is a dummy hostname
	portalHostName = "dev.siasky.net"
)

// TestAbuseScannerDB is the test suite that covers the AbuseScannerDB
func TestAbuseScannerDB(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	t.Parallel()

	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "FindUnfinalized",
			test: testFindUnfinalized,
		},
	}
	for _, test := range tests {
		t.Run(test.name, test.test)
	}
}

// testFindUnfinalized is a unit test for the FindUnfinalized method on the
// abuse scanner database
func testFindUnfinalized(t *testing.T) {
	db, err := newTestAbuseScannerDB(t.Name())
	if err != nil {
		t.Fatal(err)
	}

	// create an abuse email that's parsed and blocked (so not finalized)
	email := AbuseEmail{
		ID:        primitive.NewObjectID(),
		UID:       "INBOX-1",
		UIDRaw:    1,
		Body:      nil,
		From:      "someone@gmail.com",
		Subject:   "Abuse Subject",
		MessageID: "<msg_uid>@gmail.com",

		Parsed:    true,
		Blocked:   true,
		Finalized: false,

		InsertedBy: portalHostName,
		InsertedAt: time.Now().UTC(),
	}

	// insert it into our database
	err = db.InsertOne(email)
	if err != nil {
		t.Fatal(err)
	}

	// check whether we find our unfinalized email
	unfinalized, err := db.FindUnfinalized("INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if len(unfinalized) != 1 {
		t.Fatalf("unexpected unfinalized emails found, %v != 1", len(unfinalized))
	}

	// check whether the regex on mailbox is enforced
	unfinalized, err = db.FindUnfinalized("Spam")
	if err != nil {
		t.Fatal(err)
	}
	if len(unfinalized) != 0 {
		t.Fatalf("unexpected unfinalized emails found, %v != 0", len(unfinalized))
	}

	// mark it as finalized
	err = db.UpdateNoLock(email, bson.D{
		{"$set", bson.D{
			{"finalized", true},
			{"finalized_by", portalHostName},
			{"finalized_at", time.Now().UTC()},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// assert we can't find it any longer
	unfinalized, err = db.FindUnfinalized("INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if len(unfinalized) != 0 {
		t.Fatalf("unexpected unfinalized emails found, %v != 0", len(unfinalized))
	}
}

// newTestAbuseScannerDB returns a new test database
func newTestAbuseScannerDB(dbName string) (*AbuseScannerDB, error) {
	// create a nil logger
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// create database
	dbName = strings.Replace(dbName, "/", "_", -1)
	db, err := NewAbuseScannerDB(context.Background(), portalHostName, MongoTestConnString, dbName, options.Credential{
		Username: MongoTestUsername,
		Password: MongoTestPassword,
	}, logger)
	if err != nil {
		return nil, err
	}

	// purge it
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	err = db.Purge(ctx)
	if err != nil {
		return nil, err
	}

	return db, nil
}
