package database

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/andreyvit/diff"
)

// TestAbuseEmail is a collection of unit tests around the abuse email object.
func TestAbuseEmail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "Sender",
			test: testSender,
		},
		{
			name: "String",
			test: testString,
		},
		{
			name: "Success",
			test: testSuccess,
		},
		{
			name: "Template",
			test: testTemplate,
		},
	}
	for _, test := range tests {
		t.Run(test.name, test.test)
	}
}

// testSender is a small unit test that covers the Sender method
func testSender(t *testing.T) {
	email := AbuseEmail{}

	// base case
	if email.Sender() != "" {
		t.Fatal("unexpected sender", email.Sender())
	}

	// from filled
	email.From = "abuse@siasky.net"
	if email.Sender() != "abuse@siasky.net" {
		t.Fatal("unexpected sender", email.Sender())
	}

	// reply-to filled
	email.ReplyTo = "john.doe@examle.com"
	if email.Sender() != "john.doe@examle.com" {
		t.Fatal("unexpected sender", email.Sender())
	}

	// only reply to filled
	email.From = ""
	if email.Sender() != "john.doe@examle.com" {
		t.Fatal("unexpected sender", email.Sender())
	}
}

// testString is a small unit test that verifies the implementation of the
// String method on the abuse email.
func testString(t *testing.T) {
	// draft a dummy abuse email
	blockedAt := time.Now().UTC()
	email := AbuseEmail{
		InsertedBy: "some-server.skynetlabs.com",
		InsertedAt: time.Now().UTC(),

		Blocked:   true,
		BlockedAt: blockedAt,

		Parsed:   true,
		ParsedAt: time.Now().UTC(),

		ParseResult: AbuseReport{
			Reporter: AbuseReporter{
				Name:  "Skynetlabs Dev Team",
				Email: "devs@skynetlabs.com",
			},
			Skylinks: nil,
			Sponsor:  "skynetlabs.com",
			Tags:     []string{"csam"},
		},
		BlockResult: nil,
	}

	// small helper function that checks whether the given string is part of the
	// abuse email's string representation
	hasString := func(s string) bool {
		return strings.Contains(email.String(), s)
	}

	// check output of the summary
	if !hasString("FAILURE - no skylinks found") {
		t.Fatal("unexpected", email.String())
	}
	email.ParseResult.Skylinks = []string{
		"BBB6rPvqSR8Mcp0ulwFvFHSYvCZsnsizCvDPxac8HiThjQ",
		"EAC6rPvqSR8Mcp0ulwFvFHSYvCZsnsizCvDPxac8HiThjQ",
	}
	email.BlockResult = []string{
		AbuseStatusBlocked,
		AbuseStatusNotBlocked,
	}
	if !hasString("FAILURE - not all skylinks blocked") {
		t.Fatal("unexpected", email.String())
	}
	email.BlockResult[1] = AbuseStatusBlocked
	if !hasString("SUCCESS") {
		t.Fatal("unexpected", email.String())
	}

	// assert the whole abuse report for good measure
	expected := fmt.Sprintf(`
Abuse Scanner Report:

Summary:
SUCCESS - all skylinks blocked.

Server Info:
Domain: some-server.skynetlabs.com

Reporter:
Name: Skynetlabs Dev Team
Email: devs@skynetlabs.com

Response Template:

Hello,

the following links were identified and blocked on all of our servers as of %v

- BBB6rPvqSR8Mcp0ulwFvFHSYvCZsnsizCvDPxac8HiThjQ
- EAC6rPvqSR8Mcp0ulwFvFHSYvCZsnsizCvDPxac8HiThjQ

Please note that no content is stored on our servers, but rather on a decentralised network of hosts. 
Therefore we are not to be held accountable for any potential abusive content it might contain.
We will, however, do everything in our power to block access from said content when it gets reported.

Thank you for your report.
`, blockedAt.Format(time.RFC1123))

	// assert it's identical
	actual := email.String()
	if actual != expected {
		t.Fatal(diff.LineDiff(expected, actual))
	}
}

// testSuccess is a small unit test that verifies the Success method
func testSuccess(t *testing.T) {
	// base case
	email := AbuseEmail{Parsed: true, Blocked: true}
	if email.Success() {
		t.Fatal("unexpected result")
	}

	// empty case
	email.ParseResult = AbuseReport{Skylinks: nil}
	email.BlockResult = nil
	if email.Success() {
		t.Fatal("unexpected result")
	}

	// single not blocked case
	email.ParseResult.Skylinks = []string{"BAEE7l0IkIVcVEHDgRCcNkRYS8keZKr9v_ffxf9_614m6g"}
	email.BlockResult = []string{AbuseStatusNotBlocked}
	if email.Success() {
		t.Fatal("unexpected result")
	}

	// double, only one blocked case
	email.ParseResult.Skylinks = []string{
		"BAEE7l0IkIVcVEHDgRCcNkRYS8keZKr9v_ffxf9_614m6g",
		"CAEE7l0IkIVcVEHDgRCcNkRYS8keZKr9v_ffxf9_614m7h",
	}
	email.BlockResult = []string{
		AbuseStatusNotBlocked,
		AbuseStatusBlocked,
	}
	if email.Success() {
		t.Fatal("unexpected result")
	}

	// success case
	email.BlockResult[0] = AbuseStatusBlocked
	if !email.Success() {
		t.Fatal("unexpected result")
	}
}

// testTemplate verifies the implementation of the response template method on
// the abuse email
func testTemplate(t *testing.T) {
	// draft a dummy abuse email
	blockedAt := time.Now().UTC()
	email := AbuseEmail{
		InsertedBy: "some-server.skynetlabs.com",
		InsertedAt: time.Now().UTC(),

		Blocked:   true,
		BlockedAt: blockedAt,

		Parsed:   true,
		ParsedAt: time.Now().UTC(),
		ParseResult: AbuseReport{
			Reporter: AbuseReporter{
				Name:  "Skynetlabs Dev Team",
				Email: "devs@skynetlabs.com",
			},
			Skylinks: nil,
			Sponsor:  "skynetlabs.com",
			Tags:     []string{"csam"},
		},
		BlockResult: nil,
	}

	// assert the abuse report looks as we expected it to, we use full string
	// comparison to ensure it's absolutely the way we want it
	expected := `
Hello,

we have processed your report but were unable to find any valid links.
Please verify the link is not corrupted as we need it in order to prevent access to it from our portals.

Please note that no content is stored on our servers, but rather on a decentralised network of hosts. 
Therefore we are not to be held accountable for any potential abusive content it might contain.
We will, however, do everything in our power to block access from said content when it gets reported.

Thank you for your report.

`
	// assert it's identical
	actual := email.Response()
	if actual != expected {
		t.Fatal(diff.LineDiff(expected, actual))
	}

	// add one blocked skylink and assert we get another template
	skylink := "EAC6rPvqSR8Mcp0ulwFvFHSYvCZsnsizCvDPxac8HiThjQ"
	email.ParseResult.Skylinks = []string{skylink}
	email.BlockResult = []string{AbuseStatusBlocked}

	expected = fmt.Sprintf(`Hello,

the following links were identified and blocked on all of our servers as of %s

- EAC6rPvqSR8Mcp0ulwFvFHSYvCZsnsizCvDPxac8HiThjQ

Please note that no content is stored on our servers, but rather on a decentralised network of hosts. 
Therefore we are not to be held accountable for any potential abusive content it might contain.
We will, however, do everything in our power to block access from said content when it gets reported.

Thank you for your report.
`, blockedAt.Format(time.RFC1123))

	// assert it's identical
	actual = email.Response()
	if actual != expected {
		t.Fatal("\n" + diff.LineDiff(expected, actual))
	}

	// add one skylink that we could not block for some reason
	skylink2 := "4BHyW37RDVl_I475WfO-5FD8zNOBbSCYJ9U_C9n3yondMw"
	email.ParseResult.Skylinks = []string{skylink, skylink2}
	email.BlockResult = []string{AbuseStatusBlocked, AbuseStatusNotBlocked}

	expected = fmt.Sprintf(`Hello,

the following links were identified and blocked on all of our servers as of %v

- EAC6rPvqSR8Mcp0ulwFvFHSYvCZsnsizCvDPxac8HiThjQ

the following links could not be blocked:

- 4BHyW37RDVl_I475WfO-5FD8zNOBbSCYJ9U_C9n3yondMw

Please note that no content is stored on our servers, but rather on a decentralised network of hosts. 
Therefore we are not to be held accountable for any potential abusive content it might contain.
We will, however, do everything in our power to block access from said content when it gets reported.

Thank you for your report.
`, blockedAt.Format(time.RFC1123))

	// assert it's identical
	actual = email.Response()
	if actual != expected {
		t.Fatal(diff.LineDiff(expected, actual))
	}
}
