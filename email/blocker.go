package email

import (
	"abuse-scanner/database"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
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
		staticBlockerApiUrl     string
		staticBlockerAuthHeader string
		staticContext           context.Context
		staticDatabase          *database.AbuseScannerDB
		staticLogger            *logrus.Entry
	}

	// BlockPOST is the datastructure expected by the blocker API
	BlockPOST struct {
		Skylink  string                 `json:"skylink"`
		Reporter database.AbuseReporter `json:"reporter"`
		Tags     []string               `json:"tags"`
	}
)

// NewBlocker creates a new blocker.
func NewBlocker(ctx context.Context, blockerAuthHeader, blockerApiUrl string, database *database.AbuseScannerDB, logger *logrus.Logger) *Blocker {
	return &Blocker{
		staticBlockerAuthHeader: blockerAuthHeader,
		staticBlockerApiUrl:     blockerApiUrl,
		staticContext:           ctx,
		staticDatabase:          database,
		staticLogger:            logger.WithField("module", "Blocker"),
	}
}

// Start initializes the blocker process.
func (b *Blocker) Start() error {
	go b.threadedBlockMessages()
	return nil
}

// threadedBlockMessages will periodically fetch email messages that have not
// been blocked yet and feed them to the blocker API.
func (b *Blocker) threadedBlockMessages() {
	// convenience variables
	logger := b.staticLogger
	abuseDB := b.staticDatabase
	first := true

	// start the loop
	for {
		// sleep until next iteration, sleeping at the start of the for loop
		// allows to 'continue' on error.
		if !first {
			select {
			case <-b.staticContext.Done():
				logger.Debugln("Blocker context done")
				return
			case <-time.After(blockFrequency):
			}
		}
		first = false

		logger.Debugln("Triggered")

		// fetch all unblocked emails
		toBlock, err := abuseDB.FindUnblocked()
		if err != nil {
			logger.Errorf("Failed fetching unparsed emails, error %v", err)
			continue
		}

		// log unblocked messages count
		numUnblocked := len(toBlock)
		if numUnblocked == 0 {
			logger.Debugf("Found %v unblocked messages\n", numUnblocked)
		} else {
			logger.Infof("Found %v unblocked messages\n", numUnblocked)
		}

		// loop all emails and parse them
		for _, email := range toBlock {
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
				result, err := b.blockReport(email.ParseResult)
				if err != nil {
					return errors.AddContext(err, "could not block report")
				}

				// sanity check we have a result for every skylink
				if len(result) != len(email.ParseResult.Skylinks) {
					return errors.New("block result not defined for every skylink")
				}

				// update the email
				err = abuseDB.UpdateNoLock(email,
					bson.D{
						{"$set", bson.D{
							{"blocked", true},
							{"blockResult", result},
						}},
					},
				)
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
			b.staticLogger.Debugf("blocking %v", skylink)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Sprintf("failed to execute request, err: %v", err.Error())
			}

			// handle the response
			switch resp.StatusCode {
			case http.StatusOK, http.StatusNoContent:
				return database.AbuseStatusBlocked
			default:
				respBody, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					return fmt.Sprintf("failed to read response body, err: %v", err.Error())
				}
				resp.Body.Close()
				return fmt.Sprintf("failed to block skylink, status %v response: %v", resp.Status, string(respBody))
			}
		}()
		results = append(results, result)
	}

	return results, nil
}

// buildBlockRequest buils a request to be sent to the blocker API using the
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

	url := fmt.Sprintf("http://%s/block", b.staticBlockerApiUrl)
	req, err := http.NewRequest(http.MethodPost, url, reqBodyBuffer)
	if err != nil {
		return nil, err
	}

	// add the headers
	//
	// TODO: we don't even need the auth header here seeing as we removed
	// authentication from that route in the blocker API, I left it here anyway
	// as we might bring that back in the future
	// req.Header.Set("Authorization", b.staticBlockerAuthHeader)
	req.Header.Set("User-Agent", "Sia-Agent")
	return req, nil
}
