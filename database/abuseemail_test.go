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
			name: "ResponseTemplate",
			test: testResponseTemplate,
		},
	}
	for _, test := range tests {
		t.Run(test.name, test.test)
	}
}

// testResponseTemplate verifies the implementation of the response template
// method on the abuse email
func testResponseTemplate(t *testing.T) {
	// draft a dummy abuse email with all required fields set
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
		return strings.Contains(email.responseTemplate(), s)
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
