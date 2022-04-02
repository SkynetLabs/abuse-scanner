package email

import (
	"abuse-scanner/database"
	"context"
	"io/ioutil"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gitlab.com/SkynetLabs/skyd/skymodules"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var (
	// exampleBody is an example body of an abuse email as it gets reported by a
	// provider, the Skylinks in the examples are scrambled and not real.
	exampleBody = []byte(`
	Hello,

	Please be informed that we have located another phishing content located at the following URLs:

	hxxps:// siasky [.] net/GAEE7l0IkIVcVEHDgRCcNkRYS8keZKr9v_ffxf9_614m6g
	hxxps:// siasky [.] net/nAA_hbtNaOYyR2WrM9UNIc5jRu4WfGy5QK_iTGosDgLmSA#info@jwmarine [.] com [.] au
	hxxps:// siasky [.] net/CADEnmNNR6arnyDSH60MlGjQK5O3Sv-ecK1PGt3MNmQUhA#apg@franklinbank [.] com
	hxxps:// siasky [.] net/GABJJhT8AlfNh-XS-6YVH8en7O-t377ej9XS2eclnv2yFg

	As a reminder, phishing is expressly prohibited by our Universal Terms of Service Agreement, paragraph 7. "Acceptable Use Policy (AUP)"
	`)

	// htmlBody is an example body of an (actual) abuse email that contains
	// HTML, the Skylinks in the examples are scrambled and not real.
	htmlBody = `<html><head></head><body><p><span style="color: #808080;">&mdash;-&mdash;-&mdash;-&mdash;</span></p>
	<p><span style="color: #808080;">Please reply above this line</span></p>
	<p>&nbsp;</p>
	<p>Hostkey Abuse Team commented:</p>
	<p>      </p><p></p><p>Dear Client,</p><p>We have received a phishing complaint regarding your server with IP-address XXXXXX. <br />
	Please remove the fraudulent content within the next 24 hours or we will have to consider blocking this address.</p><p>Thank you for understanding in that matter.</p><p>The original message of the complaint is presented below.</p><p> </p><p>Dear network operator,</p><p>SWITCH-CERT has been made aware of a phishing attack against ZHDK under the following URL(s):</p><p>hXXps://siasky<span class="error">[.]</span>net/CAA0F6NzigGep-VM6sJGewvHC6pZ2sJYTIVRsDYA4_QUVA#hs.admin@zhdk<span class="error">[.]</span>ch</p><p>The pages are intended for criminal purposes and may cause considerable damage to third parties including,<br />
	but not limited to, fraudulent financial transactions and identity theft. To demonstrate the fraudulent<br />
	intent of the websites, we have attached screenshots of the offending sites to this mail whenever possible.</p><p>The URL(s) and/or IP(s) mentioned above belong to your constituency which is why we have contacted you<br />
	to help us with the appropriate actions to solve this issue. We would greatly appreciate your assistance<br />
	in removing this content as soon as possible.</p><p>If you are not the correct person to be dealing with this incident, or there is a better way for us to<br />
	report this incident, please let us know. You are free to pass this information on to other trusted<br />
	parties (e.g. law enforcement), as you see fit.</p><p>Many thanks for your prompt attention to this matter. Please do not hesitate to get in touch with us<br />
	under the email address cert@switch.ch when the site has been cleaned, and we will remove your site<br />
	from our blacklist.</p><p>Kind Regards,</p><p>SWITCH-CERT</p><p>–<br />
	SWITCH-CERT<br />
	SWITCH, Werdstrasse 2, P.O. Box, 8021 Zurich, Switzerland<br />
	incident phone +41 44 268 15 40<br />
	<a href="https://r.relay.hostkey.com/tr/cl/dH8SAQr2PfuM9z2U69X3RU4lOXxLfUvBy-PoYz0i9xaU-qfb2ba8nHjnhjGmQJWvlh1RGqVuG5GRLOEjdLptEXfwTtQZwuZ-Ktri0FbnaNv4Qsq1IwvuKJBMJPPKrCqws00fZWfF5a6L27KGJyhOZ6z2sz5u3gTAI6c1Ngfuxits8DbOEwdXd35Mw2zhzPWS0bGe_PpfRvgPbv31wAxUs0MZP0eCDcrq">http://www.switch.ch/security</a></p>
	  <img width="1" height="1" src="https://r.relay.hostkey.com/tr/op/aAMIbWQvCFUFW51yPO-mQwWdaGyPuvXUgRReI7L4Jg-v7wCrnpIWymrHdlMYdd5M6LNIEo-fcd6kxcD5KftPakp-3NrW3Z-dvYZ_KX54q8f5897S0HES-iPqJF3-uPx30Gu15Nax8rj16DaAgWW8eKHmKEZAGhMltg" alt="" /></body></html>
	`
)

// TestParser is a collection of unit tests that probe the functionality of
// various methods related to parsing abuse emails.
func TestParser(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	t.Parallel()

	t.Run("BuildAbuseReport", testBuildAbuseReport)
	t.Run("Dedupe", testDedupe)
	t.Run("ExtractSkylinks", testExtractSkylinks)
	t.Run("ExtractTags", testExtractTags)
	t.Run("ExtractTextFromHTML", testExtractTextFromHTML)
}

// testDedupe is a unit test that verifies the behaviour of the 'dedupe' helper
// function
func testDedupe(t *testing.T) {
	t.Parallel()

	input := []string{}
	output := dedupe(input)
	if len(output) != len(input) {
		t.Fatal("unexpected output", output)
	}

	input = []string{"a", "b", "a"}
	output = dedupe(input)
	sort.Strings(output)

	if len(output) != 2 {
		t.Fatal("unexpected output", output)
	}
	if output[0] != "a" || output[1] != "b" {
		t.Fatal("unexpected output", output)
	}
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
		t.Fatal("unexpected skylinks", skylinks, sl.String())
	}
}

// testExtractTextFromHTML is a unit test that verifies the behaviour of the
// 'extractTextFromHTML' helper function
func testExtractTextFromHTML(t *testing.T) {
	t.Parallel()

	// extract text from HTML
	text, err := extractTextFromHTML(strings.NewReader(htmlBody))
	if err != nil {
		t.Fatal("unexpected error while extracting text from HTML", err)
	}

	// extract the skylinks from the text
	skylinks := extractSkylinks([]byte(text))
	if len(skylinks) != 1 {
		t.Fatalf("unexpected amount of skylinks found, %v != 1", len(skylinks))
	}
	if skylinks[0] != "CAA0F6NzigGep-VM6sJGewvHC6pZ2sJYTIVRsDYA4_QUVA" {
		t.Fatalf("unexpected skylink %v", skylinks[0])
	}

	// extract the tags from the text
	tags := extractTags([]byte(text))
	if len(tags) != 1 {
		t.Fatalf("unexpected amount of tags found, %v != 1", len(tags))
	}
	if tags[0] != "phishing" {
		t.Fatalf("unexpected tag %v", tags[0])
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

	// check whether islamic state is tagged as terrost content
	exampleBody = []byte(`
	This is an example of an email body that might contain links to islamic state propaganda.
	`)

	// extract the tags and assert we found all of them
	tags = extractTags(exampleBody)
	if len(tags) != 1 {
		t.Fatalf("unexpected amount of tags found, %v != 1", len(tags))
	}
	if tags[0] != "terrorism" {
		t.Fatal("unexpected tag", tags[0])
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
	db, err := database.NewTestAbuseScannerDB(ctx, "testBuildAbuseReport")
	if err != nil {
		t.Fatal(err)
	}

	// purge the database
	err = db.Purge(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// create a parser
	domain := "dev.siasky.net"
	parser := NewParser(ctx, db, domain, "somesponsor", logger)

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

		InsertedBy: domain,
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
