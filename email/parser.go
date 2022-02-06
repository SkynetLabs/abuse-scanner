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

// parseEmailBody will parse the email body into an abuse report. This report
// contains information about the reporter, the tags and the skylinks.
func (p *Parser) parseEmailBody(body []byte) (database.AbuseReport, error) {
	// convenience variables
	logger := p.staticLogger

	// check for nil body
	if body == nil {
		return database.AbuseReport{}, errors.New("empty body")
	}

	// extract the reporter.
	reporterEmail := regexp.MustCompile(`From: .*`).Find(body)
	reporterEmail = reporterEmail[6 : len(reporterEmail)-1]
	reporter := database.AbuseReporter{
		Name:  string(reporterEmail),
		Email: string(reporterEmail),
	}

	// extract all tags and skylinks
	var tags []string
	var skylinks []string

	// use the message library to parse the email
	msg, err := message.Read(bytes.NewBuffer(body))
	if err != nil {
		return database.AbuseReport{}, err
	}

	// if the message is multi-part, read every part and only parse the ones
	// with Content-Type 'text/plain'
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
			if t == "text/plain" {
				body, err = ioutil.ReadAll(p.Body)
				if err != nil {
					logger.Errorf("error occurred while trying to read multipart body, err: %v", err)
					break
				}

				// extract all skylinks from the email body
				skylinks = append(skylinks, extractSkylinks(body)...)

				// extract all tags from the email body
				tags = append(tags, extractTags(body)...)
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
func (p *Parser) parseEmail(email database.AbuseEmail) error {
	// convenience variables
	abuseDB := p.staticDatabase

	// acquire a lock on the email
	lock := abuseDB.NewLock(email.UID)
	err := lock.Lock()
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
	report, err := p.parseEmailBody(email.Body)
	if err != nil {
		return errors.AddContext(err, "could not parse email body")
	}

	// update the email
	err = abuseDB.UpdateNoLock(email,
		bson.D{
			{"$set", bson.D{
				{"parsed", true},
				{"parse_result", report},
			}},
		},
	)
	if err != nil {
		return errors.AddContext(err, "could not update email")
	}
	return nil
}

// threadedParseMessages will periodically fetch email messages that have not
// been parsed yet and parse them.
func (p *Parser) threadedParseMessages() {
	// convenience variables
	abuseDB := p.staticDatabase
	logger := p.staticLogger

	// create a new ticker
	ticker := time.NewTicker(parseFrequency)

	// start the loop
	for {
		logger.Debugln("Triggered")

		func() {
			// fetch all unparsed emails
			toParse, err := abuseDB.FindUnparsed()
			if err != nil {
				logger.Errorf("Failed fetching unparsed emails, error %v", err)
				return
			}

			// log unparsed messages count
			numUnparsed := len(toParse)
			if numUnparsed == 0 {
				logger.Debugf("Found %v unparsed messages\n", numUnparsed)
				return
			}

			logger.Infof("Found %v unparsed messages\n", numUnparsed)

			// loop all emails and parse them
			for _, email := range toParse {
				err = p.parseEmail(email)
				if err != nil {
					logger.Errorf("Failed to parse email %v, error %v", email.UID, err)
				}
			}
		}()

		select {
		case <-p.staticContext.Done():
			logger.Info("Parser context done")
			return
		case <-ticker.C:
		}
	}
}

// extractSkylinks is a helper function that extracts all skylinks (as strings)
// from the given email body.
func extractSkylinks(emailBody []byte) []string {
	var afterHeader bool
	var maybeSkylinks []string

	// range over the string line by line and extract potential skylinks
	sc := bufio.NewScanner(bytes.NewBuffer(emailBody))
	for sc.Scan() {
		line := sc.Text()

		// NOTE: this hack ensures we do not parse the email header which
		// contains things like `X-Google-DKIM-Signature`. These headers contain
		// strings that match valid skylinks and thus result into false
		// positives.
		//
		// TODO: we should fetch the BODY without the header although all my
		// attempts at doing so have failed, which is why I have added this hack
		// for the time being
		if strings.HasPrefix(strings.ToLower(line), "from:") {
			afterHeader = true
		}
		if !afterHeader {
			continue
		}

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
// email body
func extractTags(emailBody []byte) []string {
	phishing := regexp.MustCompile(`[Pp]hishing`).Find(emailBody) != nil
	malware := regexp.MustCompile(`[Mm]alware`).Find(emailBody) != nil
	copyright := regexp.MustCompile(`[Ii]nfringing`).Find(emailBody) != nil
	copyright = copyright || regexp.MustCompile(`[Cc]opyright`).Find(emailBody) != nil
	terrorism := regexp.MustCompile(`[Tt]error`).Find(emailBody) != nil
	csam := regexp.MustCompile(`[Cc]hild`).Find(emailBody) != nil
	csam = csam || regexp.MustCompile(`CSAM`).Find(emailBody) != nil
	csam = csam || regexp.MustCompile(`csam`).Find(emailBody) != nil

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
