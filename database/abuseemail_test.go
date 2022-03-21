package database

import (
	"strings"
	"testing"
	"time"
)

// TestAbuseEmail is a collection of unit tests around the abuse email object.
func TestAbuseEmail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "String",
			test: testString,
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

// testString is a small unit test that verifies the implementation of the
// String method on the abuse email.
func testString(t *testing.T) {
	// draft a dummy abuse email
	email := AbuseEmail{
		InsertedBy: "some-server.skynetlabs.com",
		InsertedAt: time.Now(),

		Blocked:   true,
		BlockedAt: time.Now(),

		Parsed:   true,
		ParsedAt: time.Now(),

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
	if !hasString("SUCCESS - all skylinks blocked") {
		t.Fatal("unexpected", email.String())
	}
}

// testTemplate verifies the implementation of the response template method on
// the abuse email
func testTemplate(t *testing.T) {
	// draft a dummy abuse email
	email := AbuseEmail{
		InsertedBy: "some-server.skynetlabs.com",
		InsertedAt: time.Now(),

		Blocked:   true,
		BlockedAt: time.Now(),

		Parsed:   true,
		ParsedAt: time.Now(),
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
	// abuse email's response template
	hasString := func(s string) bool {
		return strings.Contains(email.response(), s)
	}

	// check whether it returns the appropriate template
	if !hasString("were unable to find any valid links") {
		t.Fatal("unexpected response", email.String())
	}

	// assert the legal notice is set
	if !hasString("no content is stored on our servers") {
		t.Fatal("unexpected response", email.String())
	}

	// add one blocked skylink and assert we get another template
	skylink := "EAC6rPvqSR8Mcp0ulwFvFHSYvCZsnsizCvDPxac8HiThjQ"
	email.ParseResult.Skylinks = []string{skylink}
	email.BlockResult = []string{AbuseStatusBlocked}

	// check whether it returns the appropriate template
	if !hasString("following links were identified and blocked") {
		t.Fatal("unexpected response", email.String())
	}

	// assert the legal notice is set
	if !hasString("no content is stored on our servers") {
		t.Fatal("unexpected response", email.String())
	}

	// add one skylink that we could not block for some reason
	skylink2 := "4BHyW37RDVl_I475WfO-5FD8zNOBbSCYJ9U_C9n3yondMw"
	email.ParseResult.Skylinks = []string{skylink, skylink2}
	email.BlockResult = []string{AbuseStatusBlocked, AbuseStatusNotBlocked}

	// check whether it returns the appropriate template
	if !hasString("following links were identified and blocked") {
		t.Fatal("unexpected response", email.String())
	}
	if !hasString("following links could not be blocked") {
		t.Fatal("unexpected response", email.String())
	}

	// assert the legal notice is set
	if !hasString("no content is stored on our servers") {
		t.Fatal("unexpected response", email.String())
	}
}
