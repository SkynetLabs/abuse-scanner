package email

import (
	"abuse-scanner/database"
	"abuse-scanner/utils"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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

	//nolint:golint,blank-imports
	_ "github.com/emersion/go-message/charset"
)

const (
	cypressConfig = `
const { defineConfig } = require('cypress')
module.exports = defineConfig({
	e2e: {
		defaultCommandTimeout: 5000,
		setupNodeEvents(on, config) {
			on('task', {
				log(message) {
					console.log(message)
					return null
				},
			})
		},
		screenshotOnRunFailure: false,
		specPattern: 'cypress/integration/**/*.cy.js',
		supportFile: false,
		video: false
	}
})`

	// defaultDirPerm defines the default permissions used for a new dir
	defaultDirPerm = 0755

	// defaultFilePerm defines the default permissions used for a new file
	defaultFilePerm = 0644

	// parseFrequency defines the frequency with which the parser looks for
	// emails to be parsed
	parseFrequency = 30 * time.Second
)

var (
	// extractSkylink64RE and extractSkylink64RE_2 are regexes capable of
	// extracting base-64 encoded skylinks from text
	extractSkylink64RE   = regexp.MustCompile(`.+?://.+?\..+?/([a-zA-Z0-9-_]{46})`)
	extractSkylink64RE_2 = regexp.MustCompile(`(http.+|hxxp.+|\..+|://.+|^)([a-zA-Z0-9-_]{46})(\?.*)?$`)

	// extractSkylink32RE and extractSkylink32RE_2 are regexes capable of
	// extracting base-32 encoded skylinks from text
	extractSkylink32RE   = regexp.MustCompile(`(?i).+?://.*?([a-z0-9]{55})`)
	extractSkylink32RE_2 = regexp.MustCompile(`(?i)(http.+|hxxp.+|\..+|://.+|^)([a-z0-9]{55})(\?.*)?$`)

	// extractSkytransferURL is a regex that is capable of extracting skytransfer URLs
	extractSkytransferURL = regexp.MustCompile(`^.*((?:https://)?skytransfer.hns.*/.*?(\s|$))`)

	// extractPortalURL is a regex that is capable of extracting the portal from
	// an hns URL
	extractPortalURL = regexp.MustCompile(`^https://.*\.hns\.(.*?)/.*`)

	// space matches all whitespace
	space = regexp.MustCompile(`\s+`)

	validateSkylink64RE = regexp.MustCompile(`^([a-zA-Z0-9-_]{46})$`)
	validateSkylink32RE = regexp.MustCompile(`(?i)^([a-z0-9]{55})$`)
)

type (
	// Parser is an object that will periodically scan for unparsed emails and
	// parse them for skylinks.
	Parser struct {
		staticContext      context.Context
		staticDatabase     *database.AbuseScannerDB
		staticLogger       *logrus.Entry
		staticServerDomain string
		staticSponsor      string
		staticWaitGroup    sync.WaitGroup
	}
)

// NewParser creates a new parser.
func NewParser(ctx context.Context, database *database.AbuseScannerDB, serverDomain, sponsor string, logger *logrus.Logger) *Parser {
	return &Parser{
		staticContext:      ctx,
		staticDatabase:     database,
		staticLogger:       logger.WithField("module", "Parser"),
		staticServerDomain: serverDomain,
		staticSponsor:      sponsor,
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
		Email: email.ReplyToEmail(),
	}

	// extract all tags and skylinks
	skylinks, tags, err := parseBody(body, logger)
	if err != nil {
		return database.AbuseReport{}, err
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
	err = abuseDB.UpdateNoLock(email, bson.M{
		"$set": bson.M{
			"parsed":       true,
			"parsed_at":    time.Now().UTC(),
			"parsed_by":    p.staticServerDomain,
			"parse_result": report,
		},
	})
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

// parseBody is a helper function that parses the given body bytes, extracted
// as a standalone function for unit testing purposes
func parseBody(body []byte, logger *logrus.Entry) ([]string, []string, error) {
	// use the message library to parse the email
	msg, err := message.Read(bytes.NewBuffer(body))
	if err != nil {
		return nil, nil, err
	}

	// extract all tags and skylinks
	var tags []string
	var skylinks []string
	var skytransferURLs []string

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
			if !shouldParseMediaType(t) {
				continue
			}
			switch t {
			case "text/html":
				// extract all text from the HTML
				text, err := extractTextFromHTML(p.Body)
				if err != nil {
					logger.Errorf("error occurred while trying to read the HTML from the multipart body, err: %v", err)
					continue
				}

				// extract all skylinks from the HTML
				skylinks = append(skylinks, extractSkylinks([]byte(text))...)

				// extract all skytransfer URLs from the HTML
				skytransferURLs = dedupe(append(skytransferURLs, extractSkyTransferURLs([]byte(text), logger.Logger)...))

				// extract all tags from the HTML
				tags = append(tags, extractTags([]byte(text))...)
			default:
				body, err = ioutil.ReadAll(p.Body)
				if err != nil {
					logger.Errorf("error occurred while trying to read multipart body with content type %v, err: %v", t, err)
					continue
				}

				// extract all skylinks from the email body
				skylinks = append(skylinks, extractSkylinks(body)...)

				// extract all skytransfer URLs from the HTML
				skytransferURLs = dedupe(append(skytransferURLs, extractSkyTransferURLs(body, logger.Logger)...))

				// extract all tags from the email body
				tags = append(tags, extractTags(body)...)
			}
		}
	} else {
		skylinks = extractSkylinks(body)
		skytransferURLs = dedupe(append(skytransferURLs, extractSkyTransferURLs(body, logger.Logger)...))
		tags = extractTags(body)
	}

	// if we have not found any tags yet
	if len(tags) == 0 {
		tags = append(tags, database.AbuseDefaultTag)
	}

	// if we have found skytransfer URLs, resolve them to skylinks
	if len(skytransferURLs) > 0 {
		resolvedSkylinks, err := resolveSkyTransferURLs(skytransferURLs, logger.Logger)
		if err != nil {
			fmt.Println(err)
			logger.Errorf("failed to resolve skytransfer URLs, err %v", err)
		} else {
			skylinks = append(skylinks, resolvedSkylinks...)
		}
	} else {
		logger.Info("NO SKYTRANSFER URLS FOUND")
	}

	return dedupe(skylinks), dedupe(tags), nil
}

// dedupe is a helper function that deduplicates the given input slice
func dedupe(input []string) []string {
	if len(input) == 0 {
		return input
	}

	var deduped []string
	seen := make(map[string]struct{})
	for _, value := range input {
		if _, exists := seen[value]; !exists {
			deduped = append(deduped, value)
			seen[value] = struct{}{}
		}
	}
	return deduped
}

// extractSkylinks is a helper function that extracts all skylinks (as strings)
// from the given byte slice.
func extractSkylinks(input []byte) []string {
	var maybeSkylinks []string

	// range over the string line by line and extract potential skylinks
	sc := bufio.NewScanner(bytes.NewBuffer(input))
	for sc.Scan() {
		for _, line := range []string{
			sc.Text(),
			space.ReplaceAllString(sc.Text(), ""),
		} {
			base64matches := append(
				extractSkylink64RE.FindAllStringSubmatch(line, -1),
				extractSkylink64RE_2.FindAllStringSubmatch(line, -1)...,
			)
			base32matches := append(
				extractSkylink32RE.FindAllStringSubmatch(line, -1),
				extractSkylink32RE_2.FindAllStringSubmatch(line, -1)...,
			)
			for _, matches := range append(
				base64matches,
				base32matches...,
			) {
				for _, match := range matches {
					if validateSkylink64RE.Match([]byte(match)) {
						maybeSkylinks = append(maybeSkylinks, match)
						continue
					}
					if validateSkylink32RE.Match([]byte(match)) {
						maybeSkylinks = append(maybeSkylinks, match)
						continue
					}
				}
			}
		}
	}

	// add the potential skylinks to a list of skylinks if LoadString succeeds
	var skylinks []string
	for _, skylink := range maybeSkylinks {
		var sl skymodules.Skylink
		err := sl.LoadString(skylink)
		if err == nil {
			skylinks = append(skylinks, sl.String())
		}
	}

	return dedupe(skylinks)
}

// extractSkyTransferURLs is a helper function that extracts all skytransfer
// URLs from the given byte slice.
func extractSkyTransferURLs(input []byte, logger *logrus.Logger) []string {
	var skyTransferURLs []string

	// range over the string line by line and extract potential skylinks
	sc := bufio.NewScanner(bytes.NewBuffer(input))
	for sc.Scan() {
		for _, matches := range extractSkytransferURL.FindAllStringSubmatch(sc.Text(), -1) {
			for _, match := range matches {
				match = utils.SanitizeURL(match)
				_, err := url.ParseRequestURI(match)
				if err != nil {
					logger.Debugf("matched skytransfer URL '%v' but was invalid, err '%v'", match, err)
					continue
				}
				skyTransferURLs = append(skyTransferURLs, match)
			}
		}
	}

	return dedupe(skyTransferURLs)
}

// extract tags is a helper function that extracts a set of tags from the given
// input
func extractTags(input []byte) []string {
	phishing := regexp.MustCompile(`[Pp]hishing`).Find(input) != nil
	malware := regexp.MustCompile(`[Mm]alware`).Find(input) != nil
	copyright := regexp.MustCompile(`[Ii]nfringing`).Find(input) != nil
	copyright = copyright || regexp.MustCompile(`[Cc]opyright`).Find(input) != nil
	terrorism := regexp.MustCompile(`[Tt]error`).Find(input) != nil
	terrorism = terrorism || regexp.MustCompile(`[Ii]slamic [Ss]tate`).Find(input) != nil
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

	return strings.Join(text, ""), nil
}

// extractPortalFromHnsDomain is a helper function that extracts the portal from
// a hns subdomain
func extractPortalFromHnsDomain(url string) string {
	matches := extractPortalURL.FindStringSubmatch(url)
	if len(matches) != 2 {
		return ""
	}
	return matches[1]
}

// resolveSkyTransferURLs takes a set of skytransfer URLs and attempts to
// resolve them to the underlying skylink
func resolveSkyTransferURLs(urls []string, logger *logrus.Logger) ([]string, error) {
	logger.Debugf("resolving %v skytransfer.hns URLs\n", len(urls))

	// prepare a tmp dir
	dir, err := ioutil.TempDir(os.TempDir(), "abuse-scanner-skytransfer-resolve-")
	if err != nil {
		return nil, errors.AddContext(err, "could not create temporary directory")
	}

	logger.Debugf("generating tmp directory %v", dir)
	defer os.RemoveAll(dir)

	// write cypress config to disk
	err = writeCypressConfig(dir)
	if err != nil {
		return nil, err
	}

	// write cypress tests to disk
	err = writeCypressTests(dir, urls, logger)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command("docker", "run", "-v", fmt.Sprintf("%v:/e2e", dir), "-w", "/e2e", "cypress/included:10.3.0") //nolint:gosec
	logger.Debugf("executing cmd %v", cmd.String())
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	// run cypress
	err = cmd.Run()
	if err != nil {
		msg := fmt.Sprintf("failed running cypress tests, err %v, stderr %v, stdout %v", err, stderr.String(), out.String())
		logger.Debugf(msg)
		return nil, errors.New(msg)
	}

	// extract the skylinks from the output
	return extractSkylinks(out.Bytes()), nil
}

// writeCypressConfig writes the required cypress configuration to the given directory
func writeCypressConfig(dir string) error {
	err := os.WriteFile(filepath.Join(dir, "cypress.config.js"), []byte(cypressConfig), defaultFilePerm)
	return errors.AddContext(err, "could not write cypress config file")
}

// writeCypressTests generates the cypress tests for given URLs and writes them
// to the appropriate test file location in the given dir
func writeCypressTests(dir string, urls []string, logger *logrus.Logger) error {
	// build the tests
	var sb strings.Builder
	sb.WriteString("describe('SkyTransfer URL Resolver', () => {\n")

	before := sb.Len()
	for _, url := range urls {
		portal := extractPortalFromHnsDomain(url)
		if portal == "" {
			logger.Errorf("could not extract portal from url '%v'", url)
			continue
		}

		sb.WriteString(fmt.Sprintf("  it('Resolves skylink for %v', () => {\n", url))
		sb.WriteString("    cy.on('uncaught:exception', (err, runnable) => {return false});\n")
		sb.WriteString("    cy.on('fail', (e) => {return});\n")
		sb.WriteString(fmt.Sprintf("    cy.visit('%v');\n", url))
		sb.WriteString(fmt.Sprintf("    cy.intercept('https://%v/*').as('myReq');\n", portal))
		sb.WriteString("    cy.get('.ant-btn').contains('Download all files').click();\n")
		sb.WriteString("    cy.wait('@myReq').should(($obj) => {cy.task('log', $obj.request.url)});\n")
		sb.WriteString("    cy.wait(30000);\n")
		sb.WriteString("  })\n")
	}

	// check whether tests have been added
	if sb.Len() == before {
		return fmt.Errorf("no cypress tests generated for URLs %v", urls)
	}
	sb.WriteString("})\n")

	// prepare the directory
	integrationDir := filepath.Join(dir, "cypress", "integration")
	err := os.MkdirAll(integrationDir, defaultDirPerm)
	if err != nil {
		return err
	}

	// write the tests
	err = os.WriteFile(filepath.Join(integrationDir, "test.cy.js"), []byte(sb.String()), defaultFilePerm)
	return errors.AddContext(err, "could not write cypress tests file")
}

// shouldParseMediaType is a helper function that returns true if the given
// media type is one that we should parse
func shouldParseMediaType(mediaType string) bool {
	return strings.HasPrefix(mediaType, "application") ||
		strings.HasPrefix(mediaType, "message") ||
		strings.HasPrefix(mediaType, "multipart") ||
		strings.HasPrefix(mediaType, "text")
}
