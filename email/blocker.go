package email

import (
	"abuse-scanner/database"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"gitlab.com/NebulousLabs/errors"
	"go.mongodb.org/mongo-driver/bson"
)

const (
	// blockFrequency defines the frequency with which we scan for emails for
	// which the parsed emails have not been blocked yet.
	blockFrequency = 30 * time.Second
)

type (
	// Blocker is an object that will periodically scan the database for abuse
	// reports that have not been blocked yet.
	Blocker struct {
		staticBlockerApiUrl string
		staticContext       context.Context
		staticDatabase      *database.AbuseScannerDB
		staticLogger        *logrus.Entry
		staticServerDomain  string
		staticWaitGroup     sync.WaitGroup
	}

	// BlockPOST is the datastructure expected by the blocker API
	BlockPOST struct {
		Skylink  string                 `json:"skylink"`
		Reporter database.AbuseReporter `json:"reporter"`
		Tags     []string               `json:"tags"`
	}
)

// NewBlocker creates a new blocker.
func NewBlocker(ctx context.Context, blockerApiUrl, serverDomain string, database *database.AbuseScannerDB, logger *logrus.Logger) *Blocker {
	return &Blocker{
		staticBlockerApiUrl: blockerApiUrl,
		staticContext:       ctx,
		staticDatabase:      database,
		staticLogger:        logger.WithField("module", "Blocker"),
		staticServerDomain:  serverDomain,
	}
}

// Start initializes the blocker process.
func (b *Blocker) Start() error {
	b.staticWaitGroup.Add(1)
	go func() {
		b.threadedBlockMessages()
		b.staticWaitGroup.Done()
	}()
	return nil
}

// Stop waits for the blocker's waitgroup and times out after one minute.
func (b *Blocker) Stop() error {
	c := make(chan struct{})
	go func() {
		defer close(c)
		b.staticWaitGroup.Wait()
	}()
	select {
	case <-c:
		return nil
	case <-time.After(time.Minute):
		return errors.New("unclean blocker shutdown")
	}
}

// threadedBlockMessages will periodically fetch email messages that have not
// been blocked yet and feed them to the blocker API.
func (b *Blocker) threadedBlockMessages() {
	// convenience variables
	logger := b.staticLogger

	// create a new ticker
	ticker := time.NewTicker(blockFrequency)

	// start the loop
	for {
		logger.Debugln("threadedBlockMessages loop iteration triggered")
		b.blockMessages()

		select {
		case <-b.staticContext.Done():
			logger.Debugln("Blocker context done")
			return
		case <-ticker.C:
		}
	}
}

// blockMessages is executed on every iteration of the loop in
// threadedBlockMessages, it will scan for emails for which the skylinks have
// not been blocked yet and attempt to block them.
func (b *Blocker) blockMessages() {
	// convenience variables
	abuseDB := b.staticDatabase
	logger := b.staticLogger

	// fetch all unblocked emails
	toBlock, err := abuseDB.FindUnblocked()
	if err != nil {
		logger.Errorf("Failed fetching unblocked emails, error %v", err)
		return
	}

	// log unblocked messages count
	numUnblocked := len(toBlock)
	if numUnblocked == 0 {
		logger.Debugf("Found %v unblocked messages", numUnblocked)
		return
	}

	logger.Infof("Found %v unblocked messages", numUnblocked)

	// loop all emails and block the skylinks they contain
	for _, email := range toBlock {
		err := b.blockEmail(email)
		if err != nil {
			logger.Errorf("Failed to parse email %v, error %v", email.UID, err)
		}
	}
}

// blockEmail will block the skylinks that are contained in the parse result of
// the given email.
func (b *Blocker) blockEmail(email database.AbuseEmail) (err error) {
	// convenience variables
	abuseDB := b.staticDatabase

	// acquire the lock
	lock := abuseDB.NewLock(email.UID)
	err = lock.Lock()
	if err != nil {
		return errors.AddContext(err, "could not acquire lock")
	}

	// defer the release
	defer func() {
		unlockErr := lock.Unlock()
		if unlockErr != nil {
			err = errors.Compose(err, errors.AddContext(unlockErr, "could not release lock"))
			return
		}
	}()

	// block the skylinks from the parse result
	result, err := b.blockReport(email.ParseResult)
	if err != nil {
		return errors.AddContext(err, "failed blocking skylinks in the parse result")
	}

	// update the email
	err = abuseDB.UpdateNoLock(email, bson.M{
		"$set": bson.M{
			"blocked":      true,
			"blocked_by":   b.staticServerDomain,
			"blocked_at":   time.Now().UTC(),
			"block_result": result,
		},
	})
	if err != nil {
		return errors.AddContext(err, "could not update email")
	}
	return nil
}

// blockReport will block all skylinks from the given abuse report.
func (b *Blocker) blockReport(report database.AbuseReport) ([]string, error) {
	var results []string
	for _, skylink := range report.Skylinks {
		result := func() string {
			// build the request
			req, err := b.buildBlockRequest(skylink, report)
			if err != nil {
				return fmt.Sprintf("failed to build request, err: %v", err.Error())
			}

			// execute the request
			b.staticLogger.Debugf("blocking %v...%v", skylink[:4], skylink[len(skylink)-4:])
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Sprintf("failed to execute request, err: %v", err.Error())
			}
			defer func() {
				err = resp.Body.Close()
				if err != nil {
					b.staticLogger.Errorf("failed to close response body, err: %v", err)
				}
			}()

			// handle the response
			switch resp.StatusCode {
			case http.StatusOK, http.StatusNoContent:
				return database.AbuseStatusBlocked
			default:
				respBody, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					return fmt.Sprintf("failed to read response body, err: %v", err.Error())
				}
				return fmt.Sprintf("failed to block skylink, status %v response: %v", resp.Status, string(respBody))
			}
		}()
		results = append(results, result)
	}

	// sanity check we have a result for every skylink
	if len(results) != len(report.Skylinks) {
		return nil, errors.New("block result not defined for every skylink")
	}

	return results, nil
}

// buildBlockRequest builds a request to be sent to the blocker API using the
// provided input.
func (b *Blocker) buildBlockRequest(skylink string, report database.AbuseReport) (*http.Request, error) {
	// build the request body
	reqBody := BlockPOST{
		Skylink:  skylink,
		Reporter: report.Reporter,
		Tags:     report.Tags,
	}

	// build the request
	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	reqBodyBuffer := bytes.NewBuffer(reqBodyBytes)

	url := fmt.Sprintf("%s/block", b.staticBlockerApiUrl)
	req, err := http.NewRequest(http.MethodPost, url, reqBodyBuffer)
	if err != nil {
		return nil, err
	}

	// add the headers
	req.Header.Set("User-Agent", "Sia-Agent")
	return req, nil
}
