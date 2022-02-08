package email

import (
	"abuse-scanner/database"
	"bufio"
	"bytes"
	"context"
	"io"
	"io/ioutil"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-message"
	"github.com/sirupsen/logrus"
	"gitlab.com/NebulousLabs/errors"
	"gitlab.com/SkynetLabs/skyd/skymodules"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/net/html"
)

const (
	// parseFrequency defines the frequency with which the parser looks for
	// emails to be parsed
	parseFrequency = 30 * time.Second
)

var (
	skylinkRE           = regexp.MustCompile("^.*([a-z0-9]{55})|([a-zA-Z0-9-_]{46}).*$")
	validateSkylink64RE = regexp.MustCompile("^([a-zA-Z0-9-_]{46})$")
	validateSkylink32RE = regexp.MustCompile("^([a-zA-Z0-9-_]{55})$")
)

type (
	// Parser is an object that will periodically scan for unparsed emails and
	// parse them for skylinks.
	Parser struct {
		staticContext   context.Context
		staticDatabase  *database.AbuseScannerDB
		staticLogger    *logrus.Entry
		staticSponsor   string
		staticWaitGroup sync.WaitGroup
	}
)

// NewParser creates a new parser.
func NewParser(ctx context.Context, database *database.AbuseScannerDB, sponsor string, logger *logrus.Logger) *Parser {
	return &Parser{
		staticContext:  ctx,
		staticDatabase: database,
		staticLogger:   logger.WithField("module", "Parser"),
		staticSponsor:  sponsor,
	}
}

// Start initializes the fetch process.
func (p *Parser) Start() error {
	p.staticWaitGroup.Add(1)
	go func() {
		p.threadedParseMessages()
		p.staticWaitGroup.Done()
	}()
	return nil
}

// Stop waits for the parser's waitgroup and times out after one minute.
func (p *Parser) Stop() error {
	c := make(chan struct{})
	go func() {
		defer close(c)
		p.staticWaitGroup.Wait()
	}()
	select {
	case <-c:
		return nil
	case <-time.After(time.Minute):
		return errors.New("unclean parser shutdown")
	}
}

// buildAbuseReport will parse the email body into an abuse report. This report
// contains information about the reporter, the tags and the skylinks.
func (p *Parser) buildAbuseReport(email database.AbuseEmail) (database.AbuseReport, error) {
	// convenience variables
	logger := p.staticLogger

	// check for nil body
	body := email.Body
	if body == nil {
		return database.AbuseReport{}, errors.New("empty body")
	}

	// extract the reporter.
	reporter := database.AbuseReporter{
		Email: email.From,
	}

	// extract all tags and skylinks
	var tags []string
	var skylinks []string

	// use the message library to parse the email
	msg, err := message.Read(bytes.NewBuffer(body))
	if err != nil {
		return database.AbuseReport{}, err
	}

	// create a multi-part reader from the message
	mpr := msg.MultipartReader()
	if mpr != nil {
		for {
			p, err := mpr.NextPart()
			if err == io.EOF {
				break
			} else if err != nil {
				logger.Errorf("error occurred while trying to read next part from multi-part reader, err: %v", err)
				break
			}

			t, _, _ := p.Header.ContentType()
			switch t {
			case "text/plain":
				body, err = ioutil.ReadAll(p.Body)
				if err != nil {
					logger.Errorf("error occurred while trying to read multipart body, err: %v", err)
					break
				}

				// extract all skylinks from the email body
				skylinks = append(skylinks, extractSkylinks(body)...)

				// extract all tags from the email body
				tags = append(tags, extractTags(body)...)
			case "text/html":
				// extract all text from the HTML
				text, err := extractTextFromHTML(p.Body)
				if err != nil {
					logger.Errorf("error occurred while trying to read the HTML from the multipart body, err: %v", err)
					break
				}

				// extract all skylinks from the HTML
				skylinks = append(skylinks, extractSkylinks([]byte(text))...)

				// extract all tags from the HTML
				tags = append(tags, extractTags([]byte(text))...)
			default:
			}
		}
	} else {
		skylinks = extractSkylinks(body)
		tags = extractTags(body)
	}

	// return a report
	return database.AbuseReport{
		Skylinks: skylinks,
		Reporter: reporter,
		Sponsor:  p.staticSponsor,
		Tags:     tags,
	}, nil
}

// parseEmail will parse the body of the given email into a list of abuse
// reports. Every report contains a unique skylink with extra metadata and can
// be used to block abusive skylinks.
func (p *Parser) parseEmail(email database.AbuseEmail) (err error) {
	// convenience variables
	abuseDB := p.staticDatabase

	// acquire a lock on the email
	lock := abuseDB.NewLock(email.UID)
	err = lock.Lock()
	if err != nil {
		return errors.AddContext(err, "could not acquire lock")
	}

	// defer the unlock
	defer func() {
		unlockErr := lock.Unlock()
		if unlockErr != nil {
			err = errors.Compose(err, errors.AddContext(unlockErr, "could not release lock"))
			return
		}
	}()

	// parse the email body into a report
	var report database.AbuseReport
	report, err = p.buildAbuseReport(email)
	if err != nil {
		return errors.AddContext(err, "could not parse email body")
	}

	// update the email
	err = abuseDB.UpdateNoLock(email,
		bson.D{
			{"$set", bson.D{
				{"parsed", true},
				{"parsed_at", time.Now().UTC()},
				{"parse_result", report},
			}},
		},
	)
	if err != nil {
		return errors.AddContext(err, "could not update email")
	}
	return nil
}

// parseMessages fetches all unparsed message from the database and parses them.
// Parsing entails extracting all skylinks and tags from the email to build an
// abuse report, which is set on the abuse email in the database.
func (p *Parser) parseMessages() {
	// convenience variables
	abuseDB := p.staticDatabase
	logger := p.staticLogger

	// fetch all unparsed emails
	toParse, err := abuseDB.FindUnparsed()
	if err != nil {
		logger.Errorf("Failed fetching unparsed emails, error %v", err)
		return
	}

	// log unparsed messages count
	numUnparsed := len(toParse)
	if numUnparsed == 0 {
		logger.Debugf("Found %v unparsed messages", numUnparsed)
		return
	}

	logger.Infof("Found %v unparsed messages", numUnparsed)

	// loop all emails and parse them
	for _, email := range toParse {
		err = p.parseEmail(email)
		if err != nil {
			logger.Errorf("Failed to parse email %v, error %v", email.UID, err)
		}
	}
}

// threadedParseMessages will periodically fetch email messages that have not
// been parsed yet and parse them.
func (p *Parser) threadedParseMessages() {
	// convenience variables
	logger := p.staticLogger

	// create a new ticker
	ticker := time.NewTicker(parseFrequency)

	// start the loop
	for {
		logger.Debugln("threadedParseMessages loop iteration triggered")
		p.parseMessages()

		select {
		case <-p.staticContext.Done():
			logger.Info("Parser context done")
			return
		case <-ticker.C:
		}
	}
}

// extractSkylinks is a helper function that extracts all skylinks (as strings)
// from the given byte slice.
func extractSkylinks(input []byte) []string {
	var maybeSkylinks []string

	// range over the string line by line and extract potential skylinks
	sc := bufio.NewScanner(bytes.NewBuffer(input))
	for sc.Scan() {
		line := sc.Text()
		for _, match := range skylinkRE.FindStringSubmatch(line) {
			if validateSkylink32RE.Match([]byte(match)) {
				maybeSkylinks = append(maybeSkylinks, match)
				continue
			}
			if validateSkylink64RE.Match([]byte(match)) {
				maybeSkylinks = append(maybeSkylinks, match)
				continue
			}
		}
	}

	// dedupe skylinks and validate them using `LoadString`
	skylinksMap := make(map[string]struct{}, 0)
	for _, maybeSkylink := range maybeSkylinks {
		var sl skymodules.Skylink
		err := sl.LoadString(maybeSkylink)
		if err == nil {
			skylinksMap[sl.String()] = struct{}{}
		}
	}

	// turn the skylinks map in an array
	var skylinks []string
	for skylink := range skylinksMap {
		skylinks = append(skylinks, skylink)
	}

	return skylinks
}

// extract tags is a helper function that extracts a set of tags from the given
// input
func extractTags(input []byte) []string {
	phishing := regexp.MustCompile(`[Pp]hishing`).Find(input) != nil
	malware := regexp.MustCompile(`[Mm]alware`).Find(input) != nil
	copyright := regexp.MustCompile(`[Ii]nfringing`).Find(input) != nil
	copyright = copyright || regexp.MustCompile(`[Cc]opyright`).Find(input) != nil
	terrorism := regexp.MustCompile(`[Tt]error`).Find(input) != nil
	csam := regexp.MustCompile(`[Cc]hild`).Find(input) != nil
	csam = csam || regexp.MustCompile(`CSAM`).Find(input) != nil
	csam = csam || regexp.MustCompile(`csam`).Find(input) != nil

	var tags []string
	if phishing {
		tags = append(tags, "phishing")
	}
	if malware {
		tags = append(tags, "malware")
	}
	if copyright {
		tags = append(tags, "copyright")
	}
	if terrorism {
		tags = append(tags, "terrorism")
	}
	if csam {
		tags = append(tags, "csam")
	}

	// if we have not found any tags yet
	if len(tags) == 0 {
		tags = append(tags, database.AbuseDefaultTag)
	}

	return tags
}

// extractTextFromHTML is a helper function that parses the given email body,
// which is expected to contain valid HTML, and returns the contents of all text
// nodes as a string.
func extractTextFromHTML(r io.Reader) (string, error) {
	var text []string
	tokenizer := html.NewTokenizer(r)
	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			if tokenizer.Err() == io.EOF {
				break
			}
			return "", tokenizer.Err()
		}

		if tt == html.TextToken {
			text = append(text, strings.TrimSpace(tokenizer.Token().Data))
		}
	}

	return strings.Join(text, "\n"), nil
}
