package database

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var (
	// emailUID ensures the email UID is unique
	emailUID = 0
	// emailUIDMu guards the emailUID so we can run tests in parallel
	emailUIDMu sync.Mutex
)

// TestAbuseScannerDB contains a set of unit tests that cover the functionality
// of the AbuseScannerDB.
func TestAbuseScannerDB(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), mongoDefaultTimeout)
	defer cancel()

	db, err := NewTestDatabase(ctx, t.Name(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "FindUnblocked",
			test: func(t *testing.T) { testFindUnblocked(ctx, t, db) },
		},
		{
			name: "FindUnfinalized",
			test: func(t *testing.T) { testFindUnfinalized(ctx, t, db) },
		},
		{
			name: "FindUnparsed",
			test: func(t *testing.T) { testFindUnparsed(ctx, t, db) },
		},
		{
			name: "FindUnreported",
			test: func(t *testing.T) { testFindUnreported(ctx, t, db) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, test.test)
	}
}

// testFindUnblocked is a unit test for the method FindUnblocked.
func testFindUnblocked(ctx context.Context, t *testing.T, db *AbuseScannerDB) {
	err := db.Purge(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// assert the database contains 0 unblocked emails
	if err := assertCount(db.FindUnblocked, 0); err != nil {
		t.Fatal(err)
	}

	// insert one and assert it now contains one unblocked email
	email := newTestEmail()
	email.Parsed = true
	err = db.InsertOne(email)
	if err != nil {
		t.Fatal(err)
	}

	// assert the database contains 1 unblocked email
	if err := assertCount(db.FindUnblocked, 1); err != nil {
		t.Fatal(err)
	}
}

// testFindUnfinalized is a unit test for the method FindUnfinalized.
func testFindUnfinalized(ctx context.Context, t *testing.T, db *AbuseScannerDB) {
	err := db.Purge(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// assert the database contains 0 unfinalized emails
	if err := assertCount(db.FindUnfinalized, 0); err != nil {
		t.Fatal(err)
	}

	// insert one email - simple case
	email := newTestEmail()
	email.Parsed = true
	email.Blocked = true
	email.Finalized = false
	email.ParseResult = AbuseReport{Tags: []string{"terrorism"}}
	err = db.InsertOne(email)
	if err != nil {
		t.Fatal(err)
	}

	// assert we can find it
	firstUID := email.UID
	if err := assertCount(db.FindUnfinalized, 1); err != nil {
		t.Fatal(err)
	}

	// insert a second email - complex case
	email = newTestEmail()
	email.Parsed = true
	email.Blocked = true
	email.Finalized = false
	email.Reported = false // this makes it not-ready-for-finalization
	email.ParseResult = AbuseReport{Tags: []string{"csam"}}
	err = db.InsertOne(email)
	if err != nil {
		t.Fatal(err)
	}

	// assert there's still only one
	if err := assertCount(db.FindUnfinalized, 1); err != nil {
		t.Fatal(err)
	}

	// update the 2nd one to mark it as reported
	second, err := db.FindOne(email.UID)
	db.UpdateNoLock(*second, bson.D{
		{"$set", bson.D{
			{"reported", true},
		}},
	})

	// assert we can now find two
	if err := assertCount(db.FindUnfinalized, 2); err != nil {
		t.Fatal(err)
	}

	// update the 1st one to mark it as finalized
	first, err := db.FindOne(firstUID)
	db.UpdateNoLock(*first, bson.D{
		{"$set", bson.D{
			{"finalized", true},
		}},
	})

	// assert there's a single unfinalized email now
	if err := assertCount(db.FindUnfinalized, 1); err != nil {
		t.Fatal(err)
	}
}

// testFindUnparsed is a unit test for the method FindUnparsed.
func testFindUnparsed(ctx context.Context, t *testing.T, db *AbuseScannerDB) {
	err := db.Purge(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// assert there's no unparsed emails
	if err := assertCount(db.FindUnparsed, 0); err != nil {
		t.Fatal(err)
	}

	// insert an email
	email := newTestEmail()
	err = db.InsertOne(email)
	if err != nil {
		t.Fatal(err)
	}

	// assert there's now one unparsed email
	if err := assertCount(db.FindUnparsed, 1); err != nil {
		t.Fatal(err)
	}

	// insert an email
	unparsed, err := db.FindOne(email.UID)
	if err != nil {
		t.Fatal(err)
	}
	unparsed.Parsed = true
	err = db.UpdateNoLock(*unparsed, bson.D{
		{"$set", bson.D{
			{"parsed", true},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// assert there's no unparsed emails
	if err := assertCount(db.FindUnparsed, 0); err != nil {
		t.Fatal(err)
	}
}

// testFindUnreported is a unit test for the method FindUnreported.
func testFindUnreported(ctx context.Context, t *testing.T, db *AbuseScannerDB) {
	err := db.Purge(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// assert there's no unreported emails
	if err := assertCount(db.FindUnreported, 0); err != nil {
		t.Fatal(err)
	}

	// insert an email
	email := newTestEmail()
	email.Parsed = true
	email.Blocked = true
	email.Reported = false
	email.Finalized = false
	email.ParseResult = AbuseReport{Tags: []string{"terrorism"}}
	err = db.InsertOne(email)
	if err != nil {
		t.Fatal(err)
	}

	// assert there's no unreported emails
	if err := assertCount(db.FindUnreported, 0); err != nil {
		t.Fatal(err)
	}

	// update the email to have csam
	first, err := db.FindOne(email.UID)
	if err != nil {
		t.Fatal(err)
	}
	err = db.UpdateNoLock(*first, bson.D{
		{"$set", bson.D{
			{"parse_result", AbuseReport{Tags: []string{"csam"}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// assert there's one unreported email
	if err := assertCount(db.FindUnreported, 1); err != nil {
		t.Fatal(err)
	}

	// update the email to be reported
	err = db.UpdateNoLock(*first, bson.D{
		{"$set", bson.D{
			{"reported", true},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// assert there's no unreported emails
	if err := assertCount(db.FindUnreported, 0); err != nil {
		t.Fatal(err)
	}
}

// newTestEmail returns a test email object
func newTestEmail() AbuseEmail {
	emailUIDMu.Lock()
	uid := emailUID
	emailUID += 1
	emailUIDMu.Unlock()

	return AbuseEmail{
		ID:        primitive.NewObjectID(),
		UID:       fmt.Sprintf("INBOX-%d", uid),
		UIDRaw:    1,
		Body:      nil,
		From:      "someone@gmail.com",
		Subject:   "Abuse Subject",
		MessageID: "<msg_uid>@gmail.com",

		Parsed:    false,
		Blocked:   false,
		Finalized: false,

		InsertedBy: "dev.siasky.net",
		InsertedAt: time.Now().UTC(),
	}
}

// assertCount is a helper that takes a function and asserts the amount of abuse
// emails it returns is equal to the given count.
func assertCount(findFn func() ([]AbuseEmail, error), count int) error {
	entities, err := findFn()
	if err != nil {
		return err
	}
	if len(entities) != count {
		return fmt.Errorf("unexpected number of emails, %v != %v", len(entities), count)
	}
	return nil
}
