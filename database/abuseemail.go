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
		ParsedAt    time.Time   `bson:"parsed_at"`
		ParseResult AbuseReport `bson:"parse_result"`
		Parsed      bool        `bson:"parsed"`

		// fields set by blocker
		BlockedAt   time.Time `bson:"blocked_at"`
		BlockResult []string  `bson:"block_result"`
		Blocked     bool      `bson:"blocked"`

		// fields set by finalizer
		Finalized   bool      `bson:"finalized"`
		FinalizedAt time.Time `bson:"finalized_at"`
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

// String returns a string representation of the abuse email
func (a AbuseEmail) String() string {
	// convenience variables
	pr := a.ParseResult
	blocked, unblocked := a.result()

	var sb strings.Builder
	sb.WriteString("\nAbuse Scanner Report:\n")

	// write summary
	sb.WriteString("\nSummary:\n")
	if len(blocked) == 0 && len(unblocked) == 0 {
		sb.WriteString("FAILURE - no skylinks found.\n")
	} else if len(unblocked) != 0 {
		sb.WriteString("FAILURE - not all skylinks blocked.\n")
	} else {
		sb.WriteString("SUCCESS - all skylinks blocked.\n")
	}

	// write server info
	sb.WriteString("\nServer Info:\n")
	sb.WriteString(fmt.Sprintf("Domain: %v\n", a.InsertedBy))

	// write reporter info
	sb.WriteString("\nReporter:\n")
	sb.WriteString(fmt.Sprintf("Name: %v\n", pr.Reporter.Name))
	sb.WriteString(fmt.Sprintf("Email: %v\n", pr.Reporter.Email))

	// write response template
	sb.WriteString("\nResponse Template:\n\n")
	sb.WriteString(a.response())
	return sb.String()
}

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
