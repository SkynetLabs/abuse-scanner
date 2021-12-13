package email

import (
	"abuse-scanner/database"
	"bufio"
	"context"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gitlab.com/NebulousLabs/errors"
	"gitlab.com/SkynetLabs/skyd/skymodules"
)

const (
	// parseFrequency defines the frequency with which the parser looks for
	// emails to be parsed
	parseFrequency = 15 * time.Second
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
		staticContext  context.Context
		staticDatabase *database.AbuseScannerDB
		staticLogger   *logrus.Logger
		staticSponsor  string
	}
)

// NewParser creates a new parser.
func NewParser(ctx context.Context, database *database.AbuseScannerDB, sponsor string, logger *logrus.Logger) *Parser {
	return &Parser{
		staticContext:  ctx,
		staticDatabase: database,
		staticLogger:   logger,
		staticSponsor:  sponsor,
	}
}

// Start initializes the fetch process.
func (p *Parser) Start() error {
	go p.threadedParseMessages()
	return nil
}

// threadedParseMessages will periodically fetch email messages that have not
// been parsed yet and parse them.
func (p *Parser) threadedParseMessages() {
	// convenience variables
	logger := p.staticLogger
	abuseDB := p.staticDatabase
	first := true

	// start the loop
	for {
		// sleep until next iteration, sleeping at the start of the for loop
		// allows to 'continue' on error.
		if !first {
			select {
			case <-p.staticContext.Done():
				return
			case <-time.After(parseFrequency):
			}
		}
		first = false

		logger.Debugln("Parsing messages...")

		// fetch all unparsed emails
		toParse, err := abuseDB.FindUnparsed()
		if err != nil {
			logger.Errorf("Failed fetching unparsed emails, error %v", err)
			continue
		}

		logger.Debugf("Found %v unparsed messages\n", len(toParse))

		// loop all emails and parse them
		for _, email := range toParse {
			err = func() (err error) {
				lock := abuseDB.NewLock(email.UID)
				err = lock.Lock()
				if err != nil {
					return errors.AddContext(err, "could not acquire lock")
				}
				defer func() {
					unlockErr := lock.Unlock()
					if unlockErr != nil {
						err = errors.Compose(err, errors.AddContext(unlockErr, "could not release lock"))
						return
					}
				}()

				// parse the email
				report, err := p.parseEmail(email)
				if err != nil {
					return errors.AddContext(err, "could not parse email")
				}

				// update the email
				email.Parsed = true
				email.ParseResult = report
				err = abuseDB.UpdateNoLock(email)
				if err != nil {
					return errors.AddContext(err, "could not update email")
				}
				return nil
			}()
			if err != nil {
				logger.Errorf("Failed to parse email %v, error %v", email.UID, err)
			}
		}
	}
}

// parseEmail will parse the body of the given email into a list of abuse
// reports. Every report contains a unique skylink with extra metadata and can
// be used to block abusive skylinks.
func (p *Parser) parseEmail(email database.AbuseEmail) (database.AbuseReport, error) {
	body := email.Body

	// extract all skylinks from the email body
	skylinks := extractSkylinks(string(body))

	// extract all tags from the email body
	tags := extractTags(body)

	// extract the reporter.
	reporterEmail := regexp.MustCompile(`From: .*`).Find(body)
	reporterEmail = reporterEmail[6 : len(reporterEmail)-1]
	reporter := database.AbuseReporter{
		Name:  string(reporterEmail),
		Email: string(reporterEmail),
	}

	// Find the sponsor.
	sponsor := os.Getenv("SKYNET_ABUSE_SPONSOR")

	// Create a blockpost for each skylink.
	return database.AbuseReport{
		Skylinks: skylinks,
		Reporter: reporter,
		Sponsor:  sponsor,
		Tags:     tags,
	}, nil
}

func extractSkylinks(emailBody string) []string {
	// range over the string line by line and extract potential skylinks
	var maybeSkylinks []string
	sc := bufio.NewScanner(strings.NewReader(emailBody))
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

func extractTags(emailBodyBytes []byte) []string {
	phishing := regexp.MustCompile(`[Pp]hishing`).Find(emailBodyBytes) != nil
	malware := regexp.MustCompile(`[Mm]alware`).Find(emailBodyBytes) != nil
	copyright := regexp.MustCompile(`[Ii]nfringing`).Find(emailBodyBytes) != nil
	copyright = copyright || regexp.MustCompile(`[Cc]opyright`).Find(emailBodyBytes) != nil
	terrorism := regexp.MustCompile(`[Tt]error`).Find(emailBodyBytes) != nil
	csam := regexp.MustCompile(`[Cc]hild`).Find(emailBodyBytes) != nil
	csam = csam || regexp.MustCompile(`CSAM`).Find(emailBodyBytes) != nil
	csam = csam || regexp.MustCompile(`csam`).Find(emailBodyBytes) != nil

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
	return tags
}
