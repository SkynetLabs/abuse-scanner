package email

import (
	"abuse-scanner/database"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	skyapi "gitlab.com/SkynetLabs/skyd/node/api"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.sia.tech/siad/build"
)

// TestBlocker contains a set of unit tests that cover the blocker struct.
func TestBlocker(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	t.Parallel()

	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "Blocker",
			test: testBlocker,
		},
	}
	for _, test := range tests {
		t.Run(test.name, test.test)
	}
}

// testBlocker covers the functionality of the blocker
func testBlocker(t *testing.T) {
	// create a context w/timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// create a null logger
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// create the abuse databases
	abuseDBName := t.Name() + "_AbuseDB"
	abuseDB, err := database.NewTestAbuseScannerDB(ctx, abuseDBName)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := abuseDB.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	// create a test server that returns a mocked response indicating all is ok
	mux := http.NewServeMux()
	mux.HandleFunc("/block", func(w http.ResponseWriter, r *http.Request) {
		skyapi.WriteSuccess(w)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	// create a blocker
	domain := "dev.siasky.net"
	bl := NewBlocker(ctx, server.URL, domain, abuseDB, logger)

	// insert an email to report
	insertedAt := time.Now().UTC()
	email := database.AbuseEmail{
		ID:  primitive.NewObjectID(),
		UID: "INBOX-0",

		Parsed:    true,
		Blocked:   false,
		Finalized: false,
		Reported:  false,

		ParseResult: database.AbuseReport{
			Tags:     []string{"csam"},
			Skylinks: []string{sl1}},

		InsertedAt: insertedAt,
	}
	err = abuseDB.InsertOne(email)
	if err != nil {
		t.Fatal(err)
	}

	// assert there's one unblocked email
	unblocked, err := abuseDB.FindUnblocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(unblocked) != 1 {
		t.Fatalf("unexpected number of unblocked emails, %v != 1", len(unblocked))
	}

	// start the blocker
	err = bl.Start()
	if err != nil {
		t.Fatal(err)
	}

	// defer stop
	defer func() {
		if err := bl.Stop(); err != nil {
			t.Fatal(err)
		}
	}()

	// assert there's no unreported emails left in a retry
	err = build.Retry(100, 100*time.Millisecond, func() error {
		unblocked, err := abuseDB.FindUnblocked()
		if err != nil {
			t.Fatal(err)
		}
		if len(unblocked) != 0 {
			return fmt.Errorf("unexpected number of unblocked emails, %v != 0", len(unblocked))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// assert the blocked_by parameter was set
	blocked, err := abuseDB.FindOne("INBOX-0")
	if err != nil {
		t.Fatal(err)
	}
	if blocked.BlockedBy != domain {
		t.Fatal("unexpected blocked_by value", email.BlockedBy)
	}

	// call cancel so we can cleanly stop the blocker
	cancel()
}
