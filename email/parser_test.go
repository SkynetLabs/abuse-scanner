package email

import (
	"abuse-scanner/database"
	"context"
	"io/ioutil"
	"sort"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gitlab.com/SkynetLabs/skyd/skymodules"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	// exampleBody is an example body of an abuse email as it gets reported by a
	// provider, the Skylinks in the examples are scrambled and not real
	exampleBody = []byte(`
	Hello,

	Please be informed that we have located another phishing content located at the following URLs:

	hxxps:// siasky [.] net/GAEE7l0IkIVcVEHDgRCcNkRYS8keZKr9v_ffxf9_614m6g
	hxxps:// siasky [.] net/nAA_hbtNaOYyR2WrM9UNIc5jRu4WfGy5QK_iTGosDgLmSA#info@jwmarine [.] com [.] au
	hxxps:// siasky [.] net/CADEnmNNR6arnyDSH60MlGjQK5O3Sv-ecK1PGt3MNmQUhA#apg@franklinbank [.] com
	hxxps:// siasky [.] net/GABJJhT8AlfNh-XS-6YVH8en7O-t377ej9XS2eclnv2yFg

	As a reminder, phishing is expressly prohibited by our Universal Terms of Service Agreement, paragraph 7. "Acceptable Use Policy (AUP)"
	`)
)

// TestParser is a collection of unit tests that probe the functionality of
// various methods related to parsing abuse emails.
func TestParser(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	t.Parallel()

	t.Run("BuildAbuseReport", testBuildAbuseReport)
	t.Run("ExtractSkylinks", testExtractSkylinks)
	t.Run("ExtractTags", testExtractTags)
}

// testExtractSkylinks is a unit test that verifies the behaviour of the
// 'extractSkylinks' helper function
func testExtractSkylinks(t *testing.T) {
	t.Parallel()

	// base case
	skylinks := extractSkylinks(nil)
	if len(skylinks) != 0 {
		t.Fatalf("unexpected amount of skylinks found, %v != 0", len(skylinks))
	}

	// extract skylinks
	skylinks = extractSkylinks(exampleBody)
	if len(skylinks) != 4 {
		t.Fatalf("unexpected amount of skylinks found, %v != 4", len(skylinks))
	}

	// assert we have extracted the correct skylinks
	sort.Strings(skylinks)
	if skylinks[0] != "CADEnmNNR6arnyDSH60MlGjQK5O3Sv-ecK1PGt3MNmQUhA" ||
		skylinks[1] != "GABJJhT8AlfNh-XS-6YVH8en7O-t377ej9XS2eclnv2yFg" || skylinks[2] != "GAEE7l0IkIVcVEHDgRCcNkRYS8keZKr9v_ffxf9_614m6g" || skylinks[3] != "nAA_hbtNaOYyR2WrM9UNIc5jRu4WfGy5QK_iTGosDgLmSA" {
		t.Fatal("unexpected skylinks", skylinks)
	}

	// use a made up email body that contains base32 skylinks
	skylinks = extractSkylinks([]byte(`
	Hello,

	Please be informed that we have located another phishing content located at the following URLs:

	hxxps:// 7g01n1fmusamd3k4c5l7ahb39356rfhfs92e9mjshj1vq93vk891m2o [.] siasky [.] net
	`))
	if len(skylinks) != 1 {
		t.Fatalf("unexpected amount of skylinks found, %v != 1", len(skylinks))
	}

	// NOTE: it will have loaded the base32 encoded version Skylink and output
	// its base64 encoded version
	var sl skymodules.Skylink
	if err := sl.LoadString("7g01n1fmusamd3k4c5l7ahb39356rfhfs92e9mjshj1vq93vk891m2o"); err != nil {
		t.Fatal(err)
	}
	if skylinks[0] != sl.String() {
		t.Fatal("unexpected skylinks", skylinks)
	}
}

// testExtractTags is a unit test that verifies the behaviour of the
// 'extractTags' helper function
func testExtractTags(t *testing.T) {
	t.Parallel()

	// base case, assert the abusive tags is returned of no others were found
	tags := extractTags(nil)
	if len(tags) != 1 {
		t.Fatalf("unexpected amount of tags found, %v != 1", len(tags))
	}
	if tags[0] != database.AbuseDefaultTag {
		t.Fatal("unexpected tag", tags[0])
	}

	// use a made up email body that contains all tags
	exampleBody := []byte(`
	This is an example of an email body that might contain phishing links, but could also contain malware or even skylinks that are infringing on copyright. In the worst cases it might contain skylinks that link to terrorist content or even child pornographic material, also known as csam.
	`)

	// extract the tags and assert we found all of them
	tags = extractTags(exampleBody)
	if len(tags) != 5 {
		t.Fatalf("unexpected amount of tags found, %v != 5", len(tags))
	}

	// assert we have extracted the correct tags
	sort.Strings(tags)
	if tags[0] != "copyright" || tags[1] != "csam" || tags[2] != "malware" || tags[3] != "phishing" || tags[4] != "terrorism" {
		t.Fatal("unexpected tags", tags)
	}
}

// testBuildAbuseReport is a unit test that verifies the functionality of the
// 'buildAbuseReport' method on the Parser.
func testBuildAbuseReport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// create discard logger
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// create test database
	db, err := newTestDatabase(ctx, "testBuildAbuseReport", logger)
	if err != nil {
		t.Fatal(err)
	}

	// purge the database
	err = db.Purge(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// create a parser
	parser := NewParser(ctx, db, "somesponsor", logger)

	// create an abuse email
	email := database.AbuseEmail{
		ID:        primitive.NewObjectID(),
		UID:       "INBOX-1",
		UIDRaw:    1,
		Body:      exampleBody,
		From:      "someone@gmail.com",
		Subject:   "Abuse Subject",
		MessageID: "<msg_uid>@gmail.com",

		Parsed:    false,
		Blocked:   false,
		Finalized: false,

		InsertedBy: "dev.siasky.net",
		InsertedAt: time.Now().UTC(),
	}

	// insert the email
	err = db.InsertOne(email)
	if err != nil {
		t.Fatal(err)
	}

	// parse the email
	err = parser.parseEmail(email)
	if err != nil {
		t.Fatal(err)
	}

	// fetch the email
	updated, err := db.FindOne(email.UID)
	if err != nil {
		t.Fatal(err)
	}

	// assert various fields on the email
	if !updated.Parsed {
		t.Fatal("expected the email to be parsed")
	}
	if updated.ParsedAt == (time.Time{}) {
		t.Fatal("expected 'parsedAt' to be set")
	}
	if updated.Finalized {
		t.Fatal("expected the email to not be finalized")
	}

	// assert the parse result, note that we don't deep equal the parse result,
	// since we use the example email body we can rest assured it's correct
	// since the unit tests cover that as well
	pr := updated.ParseResult
	if len(pr.Skylinks) != 4 {
		t.Fatal("unexpected amount of skylinks", pr.Skylinks)
	}
	if len(pr.Tags) != 1 {
		t.Fatal("unexpected amount of tags", pr.Tags)
	}
	if pr.Sponsor != "somesponsor" {
		t.Fatal("unexpected sponsor", pr.Sponsor)
	}
	if pr.Reporter.Email != "someone@gmail.com" {
		t.Fatal("unexpected reporter", pr.Reporter.Email)
	}
}

// newTestDatabase returns a test database with given name.
func newTestDatabase(ctx context.Context, dbName string, logger *logrus.Logger) (*database.AbuseScannerDB, error) {
	return database.NewAbuseScannerDB(ctx, "", "mongodb://localhost:37017", dbName, options.Credential{
		Username: "admin",
		Password: "aO4tV5tC1oU3oQ7u",
	}, logger)
}
