package email

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"gitlab.com/NebulousLabs/errors"
)

const (
	// ncmecBaseURI is the base URI for NCMEC's production API.
	ncmecBaseURI = "https://report.cybertip.org/ispws"

	// ncmecTestBaseURI is the base URI for NCMEC's test API.
	ncmecTestBaseURI = "https://exttest.cybertip.org/ispws"

	// ncmecStatusOK is the custom status code ncmec uses on their endpoints
	// when everything is ok.
	ncmecStatusOK = 0

	// ncmecStatusValidationFailed is the custom status code ncmec uses on
	// their endpoints when validation fails.
	ncmecStatusValidationFailed = 4100
)

type (

	// NCMECCredentials holds the credentials that are required to authenticate
	// with NCMEC's API.
	NCMECCredentials struct {
		Username string
		Password string

		// Debug indicates whether the reports are sent to NCMEC's test - or
		// production API.
		Debug bool
	}

	// NCMECReporter holds information about the reporter. This information is
	// loaded from the environment as it has to be configurable.
	NCMECReporter struct {
		ReportingPerson ncmecPerson `xml:"reportingPerson"`
	}

	// report is the xml that is expected from NCMEC to report an incident
	report struct {
		Xsi                       string `xml:"xmlns:xsi,attr"`
		NoNamespaceSchemaLocation string `xml:"xsi:noNamespaceSchemaLocation,attr"`

		IncidentSummary ncmecIncidentSummary `xml:"incidentSummary"`
		InternetDetails ncmecInternetDetails `xml:"internetDetails"`
		Reporter        NCMECReporter        `xml:"reporter"`

		Uploader ncmecReportedPerson `xml:"personOrUserReported"`
	}

	// reportResponse is the xml response that gets returned when a report
	// is opened with NCMEC
	reportResponse struct {
		ResponseCode        uint64 `xml:"responseCode"`
		ResponseDescription string `xml:"responseDescription"`
		ReportId            uint64 `xml:"reportId"`
	}

	// reportDoneResponse is the xml response that gets returned when a report
	// is finished with NCMEC
	reportDoneResponse struct {
		ResponseCode uint64 `xml:"responseCode"`
		ReportId     uint64 `xml:"reportId"`

		Files []ncmecFileId `xml:"files>ncmecFileId"`
	}

	// ncmecIncidentSummary contains the incident type and date.
	ncmecIncidentSummary struct {
		IncidentType     string `xml:"incidentType"`
		IncidentDateTime string `xml:"incidentDateTime"`
	}

	// ncmecInternetDetails contains the webpage.
	ncmecInternetDetails struct {
		WebPageIncident ncmecWebPageIncident `xml:"webPageIncident"`
	}

	// ncmecWebPageIncident defines the url at which abusive content was found.
	ncmecWebPageIncident struct {
		ThirdPartyHostedContent bool     `xml:"thirdPartyHostedContent,attr"`
		Url                     []string `xml:"url"`
	}

	// ncmecPerson defines a persion.
	ncmecPerson struct {
		FirstName string `xml:"firstName"`
		LastName  string `xml:"lastName"`
		Email     string `xml:"email"`
	}

	// ncmecReportedPerson defines the reported user.
	ncmecReportedPerson struct {
		UserReported   ncmecPerson           `xml:"personOrUserReportedPerson"`
		IPCaptureEvent []ncmecIPCaptureEvent `xml:"ipCaptureEvent"`
		AdditionalInfo string                `xml:"additionalInfo"`
	}

	// ncmecIPCaptureEvent represent an event capture for which we have an IP
	ncmecIPCaptureEvent struct {
		IPAddress string `xml:"ipAddress"`
		EventName string `xml:"eventName"`
		Date      string `xml:"dateTime"`
	}

	// ncmecFileId represents a file identifier
	ncmecFileId string

	// NCMECClient is a helper struct that abstracts all http requests that are
	// needed to report a CSAM incident to NCMEC.
	NCMECClient struct {
		staticAuthorization string
		staticBaseUri       string
	}
)

// LoadNCMECCredentials is a helper function that loads the NCMEC credentials so
// we can communicate with their API.
func LoadNCMECCredentials() (NCMECCredentials, error) {
	var creds NCMECCredentials
	var ok bool
	var err error
	if creds.Username, ok = os.LookupEnv("NCMEC_USERNAME"); !ok {
		return NCMECCredentials{}, errors.New("missing env var NCMEC_USERNAME")
	}
	if creds.Password, ok = os.LookupEnv("NCMEC_PASSWORD"); !ok {
		return NCMECCredentials{}, errors.New("missing env var NCMEC_PASSWORD")
	}
	var debugStr string
	if debugStr, ok = os.LookupEnv("NCMEC_DEBUG"); !ok {
		return NCMECCredentials{}, errors.New("missing env var NCMEC_DEBUG")
	}
	if creds.Debug, err = strconv.ParseBool(debugStr); err != nil {
		return NCMECCredentials{}, errors.New("invalid bool value for var NCMEC_DEBUG")
	}

	return creds, nil
}

// LoadNCMECReporter is a helper function that loads the NCMEC reporter from the
// environment.
func LoadNCMECReporter() (NCMECReporter, error) {
	var reporter ncmecPerson
	var ok bool
	if reporter.FirstName, ok = os.LookupEnv("NCMEC_REPORTER_FIRSTNAME"); !ok {
		return NCMECReporter{}, errors.New("missing env var NCMEC_REPORTER_FIRSTNAME")
	}
	if reporter.LastName, ok = os.LookupEnv("NCMEC_REPORTER_LASTNAME"); !ok {
		return NCMECReporter{}, errors.New("missing env var NCMEC_REPORTER_LASTNAME")
	}
	if reporter.Email, ok = os.LookupEnv("NCMEC_REPORTER_EMAIL"); !ok {
		return NCMECReporter{}, errors.New("missing env var NCMEC_REPORTER_EMAIL")
	}

	return NCMECReporter{ReportingPerson: reporter}, nil
}

// NewNCMECClient returns a new instance of the NCMEC client.
func NewNCMECClient(creds NCMECCredentials) *NCMECClient {
	baseUri := ncmecBaseURI
	if creds.Debug {
		baseUri = ncmecTestBaseURI
	}
	return &NCMECClient{
		staticAuthorization: base64.StdEncoding.EncodeToString([]byte(creds.Username + ":" + creds.Password)),
		staticBaseUri:       baseUri,
	}
}

// finishReport completes the submission for the given report id
func (c *NCMECClient) finishReport(reportId uint64) (reportDoneResponse, error) {
	// create a form with the given report id
	form := url.Values{}
	form.Add("id", fmt.Sprint(reportId))
	body := strings.NewReader(form.Encode())

	// construct the request headers
	headers := http.Header{}
	headers.Set("Authorization", fmt.Sprintf("Basic %s", c.staticAuthorization))
	headers.Add("Content-Type", "application/x-www-form-urlencoded")

	var resp reportDoneResponse
	err := c.post("/finish", url.Values{}, headers, body, &resp)
	if err != nil {
		return reportDoneResponse{}, err
	}

	return resp, nil
}

// openReport opens the given report with NCMEC
func (c *NCMECClient) openReport(r report) (reportResponse, error) {
	// marshal the report and create the request body
	reportBytes, err := xml.Marshal(&r)
	if err != nil {
		return reportResponse{}, err
	}

	xmlBytes := append([]byte{}, []byte(xml.Header)...)
	xmlBytes = append(xmlBytes, reportBytes...)
	body := bytes.NewBuffer(xmlBytes)

	// construct the request headers
	headers := http.Header{}
	headers.Set("Authorization", fmt.Sprintf("Basic %s", c.staticAuthorization))
	headers.Add("Content-Type", "text/xml; charset=utf-8")

	var resp reportResponse
	err = c.post("/submit", url.Values{}, headers, body, &resp)
	if err != nil {
		return reportResponse{}, err
	}

	return resp, nil
}

// status  verifies we can access the NCMEC server
func (c *NCMECClient) status() (reportResponse, error) {
	// construct the request headers
	headers := http.Header{}
	headers.Set("Authorization", fmt.Sprintf("Basic %s", c.staticAuthorization))

	var resp reportResponse
	err := c.get("/status", url.Values{}, headers, &resp)
	if err != nil {
		return reportResponse{}, err
	}

	return resp, nil
}

// get is a helper function that executes a GET request on the given endpoint
// with the provided query values. The response will get unmarshaled into the
// given response object.
func (c *NCMECClient) get(endpoint string, query url.Values, headers http.Header, obj interface{}) (err error) {
	url := fmt.Sprintf("%s%s", c.staticBaseUri, endpoint)

	queryString := query.Encode()
	if queryString != "" {
		url += "?" + queryString
	}

	var req *http.Request
	req, err = http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return errors.AddContext(err, "failed to create request")
	}

	// set headers and execute the request
	for k, v := range headers {
		req.Header.Set(k, v[0])
	}
	var res *http.Response
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		io.Copy(ioutil.Discard, res.Body)
		err = errors.Compose(err, res.Body.Close())
	}()

	// decode the response body
	return xml.NewDecoder(res.Body).Decode(obj)
}

// post is a helper function that executes a POST request on the given endpoint
// with the provided query values.
func (c *NCMECClient) post(endpoint string, query url.Values, headers http.Header, body io.Reader, obj interface{}) (err error) {
	url := fmt.Sprintf("%s%s", c.staticBaseUri, endpoint)

	queryString := query.Encode()
	if queryString != "" {
		url += "?" + queryString
	}

	// create the request
	var req *http.Request
	req, err = http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return errors.AddContext(err, "failed to create request")
	}

	// set headers and execute the request
	for k, v := range headers {
		req.Header.Set(k, v[0])
	}
	var res *http.Response
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		io.Copy(ioutil.Discard, res.Body)
		err = errors.Compose(err, res.Body.Close())
	}()

	// decode the response body
	return xml.NewDecoder(res.Body).Decode(obj)
}
