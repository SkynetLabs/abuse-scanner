package accounts

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"gitlab.com/NebulousLabs/errors"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.sia.tech/siad/node/api"
)

type (
	// AccountsClient is a helper struct that is used to communicate with the
	// accounts API.
	AccountsClient struct {
		staticAccountsURL string
	}

	// UploadInfo TODO: replace with accounts struct
	UploadInfo struct {
		Skylink   string
		IP        string
		CreatedAt time.Time
		UploaderInfo
	}

	// UploaderInfo TODO: replace with accounts struct
	UploaderInfo struct {
		UserID   primitive.ObjectID
		Email    string
		Sub      string
		StripeID string
	}
)

// NewAccountsClient returns a new accounts client
func NewAccountsClient(host, port string) *AccountsClient {
	return &AccountsClient{
		staticAccountsURL: fmt.Sprintf("%s:%s", host, port),
	}
}

// UploadInfoGET calls the `/uploadinfo/:skylink` endpoint with given parameters
func (c *AccountsClient) UploadInfoGET(skylink string) (*UploadInfo, error) {
	// execute the get request
	var info UploadInfo
	err := c.get(fmt.Sprintf("/uploadinfo/%s", skylink), url.Values{}, &info)
	if err != nil {
		return nil, errors.AddContext(err, fmt.Sprintf("failed to fetch upload info for skylink %s, err %v", skylink, err))
	}

	return &info, nil
}

// get is a helper function that executes a GET request on the given endpoint
// with the provided query values. The response will get unmarshaled into the
// given response object.
func (c *AccountsClient) get(endpoint string, query url.Values, obj interface{}) error {
	// create the request
	queryString := query.Encode()
	url := fmt.Sprintf("%s%s", c.staticAccountsURL, endpoint)
	if queryString != "" {
		url = fmt.Sprintf("%s%s?%s", c.staticAccountsURL, endpoint, queryString)
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return errors.AddContext(err, "failed to create request")
	}

	// set headers and execute the request
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer drainAndClose(res.Body)

	// return an error if the status code is not in the 200s
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("GET request to '%s' with status %d error %v", url, res.StatusCode, readAPIError(res.Body))
	}

	// handle the response body
	err = json.NewDecoder(res.Body).Decode(obj)
	if err != nil {
		return err
	}
	return nil
}

// drainAndClose reads rc until EOF and then closes it. drainAndClose should
// always be called on HTTP response bodies, because if the body is not fully
// read, the underlying connection can't be reused.
func drainAndClose(rc io.ReadCloser) {
	io.Copy(ioutil.Discard, rc)
	rc.Close()
}

// readAPIError decodes and returns an api.Error.
func readAPIError(r io.Reader) error {
	var apiErr api.Error

	err := json.NewDecoder(r).Decode(&apiErr)
	if err != nil {
		return errors.AddContext(err, "could not read error response")
	}

	return apiErr
}
