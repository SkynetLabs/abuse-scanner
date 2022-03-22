package database

import (
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.sia.tech/siad/build"
)

const (
	// AbuseStatusBlocked denotes the blocked status.
	AbuseStatusBlocked = "BLOCKED"

	// AbuseStatusNotBlocked denotes the not blocked status.
	AbuseStatusNotBlocked = "NOT BLOCKED"

	// AbuseDefaultTag is the tag used when there are no tags found in the email
	AbuseDefaultTag = "abusive"

	// responseLegalNotice is a small notice we append to the automated response
	// that mentions we do not store any content on our servers
	responseLegalNotice = `
Please note that no content is stored on our servers, but rather on a decentralised network of hosts. 
Therefore we are not to be held accountable for any potential abusive content it might contain.
We will, however, do everything in our power to block access from said content when it gets reported.

Thank you for your report.
`
)

type (
	// AbuseEmail represent an object in the emails collection.
	AbuseEmail struct {
		// fields set by fetcher
		ID        primitive.ObjectID `bson:"_id"`
		UID       string             `bson:"email_uid"`
		UIDRaw    uint32             `bson:"email_uid_raw"`
		Body      []byte             `bson:"email_body"`
		From      string             `bson:"email_from"`
		Subject   string             `bson:"email_subject"`
		MessageID string             `bson:"email_message_id"`

		InsertedBy string    `bson:"inserted_by"`
		InsertedAt time.Time `bson:"inserted_at"`

		Skip bool `bson:"skip"`

		// fields set by parser
		Parsed      bool        `bson:"parsed"`
		ParsedAt    time.Time   `bson:"parsed_at"`
		ParsedBy    string      `bson:"parsed_by"`
		ParseResult AbuseReport `bson:"parse_result"`

		// fields set by blocker
		Blocked     bool      `bson:"blocked"`
		BlockedAt   time.Time `bson:"blocked_at"`
		BlockedBy   string    `bson:"blocked_by"`
		BlockResult []string  `bson:"block_result"`

		// fields set by finalizer
		Finalized   bool      `bson:"finalized"`
		FinalizedAt time.Time `bson:"finalized_at"`
		FinalizedBy string    `bson:"finalized_by"`

		// fields set by reporter
		Reported   bool      `bson:"reported"`
		ReportedAt time.Time `bson:"reported_at"`

		// NCMEC report specific fields
		NCMECReportId  uint64 `bson:"ncmec_report_id"`
		NCMECReportErr string `bson:"ncmec_report_err"`
	}

	// AbuseReport contains all information about an abuse report.
	AbuseReport struct {
		Skylinks []string      `bson:"skylinks"`
		Reporter AbuseReporter `bson:"reporter"`
		Sponsor  string        `bson:"sponsor"`
		Tags     []string      `bson:"tags"`
	}

	// AbuseReporter encapsulates some information about the reporter.
	AbuseReporter struct {
		Name         string `bson:"name"`
		Email        string `bson:"email"`
		OtherContact string `bson:"other_contact"`
	}
)

// response is a small helper method that returns an automated response for this
// abuse email
func (a AbuseEmail) response() string {
	// sanity check
	if !a.Parsed || !a.Blocked {
		build.Critical("result should only be called when the email has been parsed and blocked")
		return ""
	}

	// fetch which skylinks were blocked and which ones weren't
	blocked, unblocked := a.result()

	// if no skylinks were found, return another version of the template
	if len(blocked) == 0 && len(unblocked) == 0 {
		return fmt.Sprintf(`
Hello,

we have processed your report but were unable to find any valid links.
Please verify the link is not corrupted as we need it in order to prevent access to it from our portals.
%s
`, responseLegalNotice)
	}

	// build the response template
	var sb strings.Builder
	sb.WriteString("Hello,\n\n")

	if len(blocked) > 0 {
		sb.WriteString(fmt.Sprintf("the following links were identified and blocked on all of our servers as of %v\n\n", a.BlockedAt.Format("Mon Jan _2 15:04:05 2006")))
		for _, skylink := range blocked {
			sb.WriteString(fmt.Sprintf("- %s\n", skylink))
		}
	}

	if len(unblocked) > 0 {
		sb.WriteString("\nthe following links could not be blocked:\n\n")
		for _, skylink := range unblocked {
			sb.WriteString(fmt.Sprintf("- %s\n", skylink))
		}
	}

	sb.WriteString(responseLegalNotice)
	return sb.String()
}

// result returns which skylinks were blocked and which we failed to block
func (a AbuseEmail) result() ([]string, []string) {
	// sanity check
	if !a.Parsed || !a.Blocked {
		build.Critical("result should only be called when the email has been parsed and blocked")
		return nil, nil
	}

	// split the parse result in blocked and unblocked skylinks
	var blocked []string
	var unblocked []string
	for i, skylink := range a.ParseResult.Skylinks {
		if a.BlockResult[i] == AbuseStatusBlocked {
			blocked = append(blocked, skylink)
		} else {
			unblocked = append(unblocked, skylink)
		}
	}
	return blocked, unblocked
}

// String returns a string representation of the abuse email
func (a AbuseEmail) String() string {
	var sb strings.Builder
	pr := a.ParseResult
	sb.WriteString("\nAbuse Scanner Report:\n")

	sb.WriteString("\nServer:\n")
	sb.WriteString(fmt.Sprintf("Domain: %v\n", a.InsertedBy))

	sb.WriteString("\nReporter:\n")
	sb.WriteString(fmt.Sprintf("Name: %v\n", pr.Reporter.Name))
	sb.WriteString(fmt.Sprintf("Email: %v\n", pr.Reporter.Email))

	// if the abuse email has CSAM we report on the NCMEC reporting
	if a.ParseResult.HasTag("csam") {
		sb.WriteString("\nNCMEC Report:\n")
		sb.WriteString(fmt.Sprintf("Report ID: %v\n", a.NCMECReportId))
		sb.WriteString(fmt.Sprintf("Report Error: %v\n", a.NCMECReportErr))
	}

	sb.WriteString("\nTags:\n")
	for _, tag := range pr.Tags {
		sb.WriteString(tag + "\n")
	}

	allBlocked := true
	sb.WriteString("\nSkylinks:\n")
	for i, skylink := range pr.Skylinks {
		var parts []string
		if a.BlockResult[i] == AbuseStatusBlocked {
			parts = []string{AbuseStatusBlocked, skylink}
		} else {
			parts = []string{AbuseStatusNotBlocked, skylink, a.BlockResult[i]}
			allBlocked = false
		}
		sb.WriteString(fmt.Sprintf("%s\n", strings.Join(parts, " | ")))
	}

	sb.WriteString("\nSummary:\n")
	if len(pr.Skylinks) == 0 {
		sb.WriteString("FAILURE - no skylinks found.\n")
	} else {
		if allBlocked {
			sb.WriteString("SUCCESS\n")
		} else {
			sb.WriteString("FAILURE - not all skylinks blocked.\n")
		}
	}

	return sb.String()
}

// HasTag returns true if the abuse report contains the given tag.
func (ar AbuseReport) HasTag(tag string) bool {
	for _, arTag := range ar.Tags {
		if tag == arTag {
			return true
		}
	}
	return false
}
