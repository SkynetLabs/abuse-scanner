package email

import (
	"abuse-scanner/database"
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/andreyvit/diff"
	"github.com/sirupsen/logrus"
	"gitlab.com/SkynetLabs/skyd/skymodules"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var (
	// exampleBody is an example body of an abuse email as it gets reported by a
	// provider, the Skylinks in the examples are scrambled and not real.
	exampleBody = []byte(`
	X-UI-Out-Filterresults: notjunk:1;V03:K0:sQbC5Bf/7VA=:BVBvnd1QjaGT0MiZL1Ho9A
	 IfQpxAOa2PG7BhMwdjkSKRkIi/0Xi320ptoRVrfdAAfeBr+OlbE7g1lSC70AY1aq/+Fpbv4wK
	 3w2N9ynN89sZ8DCaJdB7ly3XgvTsG63gsWdX8Qx0neby0Ej1pajsGSgib3Zm8tezcKH7kM+uH
	 8vULEwVR983S1CyJCBaD2LqZ2TmObmdS+5OJ/edFn2tq2WoPNrpgdm2AFO0gTOwQJ7h7ZG7Cw
	 C51GLljzSwED8mirSv3crcZeIBAS1Id6HFLPoaPWp4PveU/v0K8KtULYo7z19AK6hQgwViBiU
	 Xq2l7J/I405Ww4d83HRzSQk5RYrUot3RK7Z1kuWHlS2xZrnuwbD/O/2jZ1wqm8ODWogMHSGkU
	 I98W13ylJ0OsjeGFO+nsutUv3MjInhjUV3BBvOsnOMPOEOB6O6XEm1wr4UtjHcc9NUBPBvNh9
	 H+gscpw0FrvBbZa+9XSyucw0nXv8ux6AcRDIkceD/k7QPuQ9qF7tieTcu08DuYDQn9NyBefCl
	 RgFTNK0mc/IGzqsAmjjLJjN3Or8ZFb9AGX4Km12EJu5AVmgaX8HWNy7TkwU/G/8fRhwNm1MZA
	 tvKIzaih0+MQ3vhyhX68w4FaCyw03DtqUuXiWc/B+ieWBognxojBZW8fnl6gh1JAtvlo0LKQp
	 GMyXa9CB0//7vKj4QzhelXKBJJgYM8711kf0IFnD84KydbfFnV0LupfaJ57SHxX6EQpsO8YE5
	 Q3y3pDDyLVRM6fCl4EjRAoVRJTN+cWfVrqR2XbR8PzsEhgLpvc0oqDoNuLLFLc9tNZyVRm+3M
	 NDkpXctNC4+MD8zqzyiDiRUOZ27w9qeZqUIEqMlbnpmYnILxrfZL8A5WXYajQ5BDUYi1oMT4W
	 UT47J3cxaP66B+03lzJqMDPAxGGzBoH4buNH0ku66gi0xcmhQtBcWhfDsGM9V9RSXeG/2FmHI
	 i4y3714s6I4zN5G7Fr7EPgg61IkFB+swtoo1O5WrNJ+jFWe5nIsCXWCinXRZgaD4Q2/+57VP5
	 idJHzNoSCPhRv6mwO/9+ia/4pVxgU8wVX6huAHRsFD2WkmpU42jsBGiWOwFj43HTwPuBxfBH9
	 VhQDFA5VMxSpI+4TBiXX9ZYWqnKGpBoBtfKDHqGxF5C1JqWv2xMsiUD9c43po1Z9SsfBEC2A5
	 cfV/KfZ5odL68cjZ0s7OQXt36o

	Hello,

	Please be informed that we have located another phishing content located at the following URLs:

	hxxps:// siasky [.] net/GAEE7l0IkIVcVEHDgRCcNkRYS8keZKr9v_ffxf9_614m6g
	hxxps:// siasky [.] net/nAA_hbtNaOYyR2WrM9UNIc5jRu4WfGy5QK_iTGosDgLmSA#info@jwmarine [.] com [.] au
	hxxps:// siasky [.] net/CADEnmNNR6arnyDSH60MlGjQK5O3Sv-ecK1PGt3MNmQUhA#apg@franklinbank [.] com
	hxxps:// siasky [.] net/GABJJhT8AlfNh-XS-6YVH8en7O-t377ej9XS2eclnv2yFg

	https:// siasky [.]netAAAg4mZrsNcedNPazZ4kSFAYBzf7f8ZgHO1Tu1L-NN8Gjg
	BBBg4mZrsNcedNPazZ4kSFAYBzf7f8ZgHO1Tu1L-NN8Gjg

	As a reminder, phishing is expressly prohibited by our Universal Terms of Service Agreement, paragraph 7. "Acceptable Use Policy (AUP)"
	`)

	// exampleSkyTransferBody is an example body of an abuse email, as it gets
	// reported by a provider, that contains a skytransfer URL.
	exampleSkyTransferBody = []byte(`
I again affirm that the link below contains material distributed illegally, WITHOUT MY authorization. Thus, I request the immediate removal of the 02 links:

https://skytransfer.hns.siasky.net/#/v2/d871327aa70cd7525a3a323bf15896ea192da03254856602c0f030baeea8da8a/12a75f63a2cc182905731d68e9211d7d828f38e1203ff210c060d2eee81e6ff92b1fc48dfbf8649ab9b20b332780544626d83822621d63a44a187a90321bdf6a

My original product links:
	`)

	// htmlBody is an example body of an (actual) abuse email that contains
	// HTML, the Skylinks in the examples are scrambled and not real.
	htmlBody = `<html><head></head><body><p><span style="color: #808080;">&mdash;-&mdash;-&mdash;-&mdash;</span></p>
	<p><span style="color: #808080;">Please reply above this line</span></p>
	<p>&nbsp;</p>
	<p>Hostkey Abuse Team commented:</p>
	<p>      </p><p></p><p>Dear Client,</p><p>We have received a phishing complaint regarding your server with IP-address XXXXXX. <br />
	Please remove the fraudulent content within the next 24 hours or we will have to consider blocking this address.</p><p>Thank you for understanding in that matter.</p><p>The original message of the complaint is presented below.</p><p> </p><p>Dear network operator,</p><p>SWITCH-CERT has been made aware of a phishing attack against ZHDK under the following URL(s):</p><p>hXXps://siasky<span class="error">[.]</span>net/CAA0F6NzigGep-VM6sJGewvHC6pZ2sJYTIVRsDYA4_QUVA#hs.admin@zhdk<span class="error">[.]</span>ch</p><p>The pages are intended for criminal purposes and may cause considerable damage to third parties including,<br />
	but not limited to, fraudulent financial transactions and identity theft. To demonstrate the fraudulent<br />
	intent of the websites, we have attached screenshots of the offending sites to this mail whenever possible.</p><p>The URL(s) and/or IP(s) mentioned above belong to your constituency which is why we have contacted you<br />
	to help us with the appropriate actions to solve this issue. We would greatly appreciate your assistance<br />
	in removing this content as soon as possible.</p><p>If you are not the correct person to be dealing with this incident, or there is a better way for us to<br />
	report this incident, please let us know. You are free to pass this information on to other trusted<br />
	parties (e.g. law enforcement), as you see fit.</p><p>Many thanks for your prompt attention to this matter. Please do not hesitate to get in touch with us<br />
	under the email address cert@switch.ch when the site has been cleaned, and we will remove your site<br />
	from our blacklist.</p><p>Kind Regards,</p><p>SWITCH-CERT</p><p>–<br />
	SWITCH-CERT<br />
	SWITCH, Werdstrasse 2, P.O. Box, 8021 Zurich, Switzerland<br />
	incident phone +41 44 268 15 40<br />
	<a href="https://r.relay.hostkey.com/tr/cl/dH8SAQr2PfuM9z2U69X3RU4lOXxLfUvBy-PoYz0i9xaU-qfb2ba8nHjnhjGmQJWvlh1RGqVuG5GRLOEjdLptEXfwTtQZwuZ-Ktri0FbnaNv4Qsq1IwvuKJBMJPPKrCqws00fZWfF5a6L27KGJyhOZ6z2sz5u3gTAI6c1Ngfuxits8DbOEwdXd35Mw2zhzPWS0bGe_PpfRvgPbv31wAxUs0MZP0eCDcrq">http://www.switch.ch/security</a></p>
	  <img width="1" height="1" src="https://r.relay.hostkey.com/tr/op/aAMIbWQvCFUFW51yPO-mQwWdaGyPuvXUgRReI7L4Jg-v7wCrnpIWymrHdlMYdd5M6LNIEo-fcd6kxcD5KftPakp-3NrW3Z-dvYZ_KX54q8f5897S0HES-iPqJF3-uPx30Gu15Nax8rj16DaAgWW8eKHmKEZAGhMltg" alt="" /></body></html>
	`

	// contentTypeBody is an example email body that uses a bunch of different
	// content types to ensure in testing we parse those parts of the email body
	// properly
	contentTypeBody = `Delivered-To: report@siasky.net
Received: by 2002:a05:7000:a1a:0:0:0:0 with SMTP id ke26csp576371mab;
        Sun, 26 Jun 2022 23:29:59 -0700 (PDT)
Date: Mon, 27 Jun 2022 09:29:55 +0300
From: =obfuscated<phishing@obfuscated.com>
To: response@cert-gib.ru, abuse@namecheap.com, abuse@siasky.net
Subject: [Ticket#22062706295325258] Phishing site
MIME-Version: 1.0
Content-Type: multipart/mixed; 
        boundary="----=_Part_71086_603584994.1656311395405"

------=_Part_71086_603584994.1656311395405
Content-Type: multipart/alternative; 
        boundary="----=_Part_71087_1111859740.1656311395408"

------=_Part_71087_1111859740.1656311395408
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

Hi,
=EF=BB=BF
The bad news is you are hosting a phishing site:
https://siasky.net/BACCHn5eHow5edoimjiwBtD2ErM3OL57mf-_MghKeebanA#abuse%40y=
andex.ru

The good news is that now that you know about this scam you can stop it. Pl=
ease shut this site down.

It would also help us greatly to prevent any phishing activity in the futur=
e, if you could provide us with the source code of this site and any data t=
hat has already been stolen so that we could use them for analysis.

------=_Part_71087_1111859740.1656311395408
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: 7bit

<p>Hi,<br />&#xfeff;<br />The bad news is you are hosting a phishing site:<br /><a href="https://siasky.net/BACCHn5eHow5edoimjiwBtD2ErM3OL57mf-_MghKeebanA#abuse%obfuscated.ru" rel="nofollow">https://siasky.net/BACCHn5eHow5edoimjiwBtD2ErM3OL57mf-_MghKeebanA#abuse%40yandex.ru</a></p><br /><p>The good news is that now that you know about this scam you can stop it. Please shut this site down.</p><br /><p>It would also help us greatly to prevent any phishing activity in the future, if you could provide us with the source code of this site and any data that has already been stolen so that we could use them for analysis.</p><br /><p>--<br /><a href="https://forms.yandex.ru/surveys/10012037/?theme&#61;support-vote&amp;iframe&#61;1&amp;lang&#61;en&amp;session&#61;a20d99e6-2969-3f30-a04f-1a1b6935c3b8" rel="nofollow">Please rate our reply</a></p><br /><p>Some One<br />Support team<br /><a href="https://obfuscated.com/support/" rel="nofollow">https://obfuscated.com/support/</a></p>
------=_Part_71087_1111859740.1656311395408--

------=_Part_71086_603584994.1656311395405
Content-Type: application/octet-stream; name=image.png
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename=image.png

iVBORw0KGgoAAAANSUhEUgAAB4AAAAPtCAIAAADg5eUGAAAgAElEQVR4nOzd+7ddZX0/+vwFhJ/6
BADCHn5eHow5edoimjiwBtD2ErM3OL57mf-_MghKeebanAqq1oQSOZXa4le09KsIiFzUEUPFfgvV
QIJRAW1FTUyC7HCNkgDJPs/ec+25522t9ay911xz7vB6jc/Ateea81nPXLexfe8nn7ng6KNO7l3H
------=_Part_71086_603584994.1656311395405

------=_Part_71086_603584994.1656311395405
Content-Type: image/png
Content-Transfer-Encoding: base64
Content-ID: <6B7613EB-E52E-44C0-9A21-DC3B25738265>
Content-Disposition: inline; filename="Screenshot 2022-06-21 at 10.59.37.png"

------=_Part_71086_603584994.1656311395405--`

	// unknownCharsetBody is an example body that uses a character set that is
	// not supported by default
	unknownCharsetBody = `Received: by 2002:a05:7000:ae16:0:0:0:0 with SMTP id ij22csp429885mab;
	Thu, 31 Mar 2022 01:17:25 -0700 (PDT)
Content-Type: text/plain; charset="iso-8859-1"
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
Content-Description: Mail message body
Subject: Obfuscated
To: "Some User" <obfuscated@unknown.com>
From: "Some User" <obfuscated@unknown.com>
Date: Thu, 31 Mar 2022 09:16:57 +0100

Hi,
phishing link found
https://siasky.net/BACCHn5eHow5edoimjiwBtD2ErM3OL57mf-_MghKeebanA`
)

// TestParser is a collection of unit tests that probe the functionality of
// various methods related to parsing abuse emails.
func TestParser(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	t.Parallel()

	t.Run("BuildAbuseReport", testBuildAbuseReport)
	t.Run("Dedupe", testDedupe)
	t.Run("ExtractPortalFromHnsDomain", testExtractPortalFromHnsDomain)
	t.Run("ExtractSkyTransferURLs", testExtractSkyTransferURLs)
	t.Run("ExtractSkylinks", testExtractSkylinks)
	t.Run("ExtractTags", testExtractTags)
	t.Run("ExtractTextFromHTML", testExtractTextFromHTML)
	t.Run("ParseBody", testParseBody)
	t.Run("ParseBodySkyTransfer", testParseBodySkyTransfer)
	t.Run("ShouldParseMediaType", testShouldParseMediaType)
	t.Run("WriteCypressConfig", testWriteCypressConfig)
	t.Run("WriteCypressTests", testWriteCypressTests)
}

// testParseBody is a unit test that covers the functionality of the parseBody helper
func testParseBody(t *testing.T) {
	t.Parallel()

	// create discard logger
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// parse our example body with multipart content
	skylinks, tags, err := parseBody([]byte(contentTypeBody), logger.WithField("module", "Parser"))
	if err != nil {
		t.Fatal(err)
	}

	// assert we find the correct skylink and tag
	if len(skylinks) != 1 {
		t.Fatalf("unexpected amount of skylinks found, %v != 1", len(skylinks))
	}
	if skylinks[0] != "BACCHn5eHow5edoimjiwBtD2ErM3OL57mf-_MghKeebanA" {
		t.Fatal("unexpected skylink found", skylinks[0])
	}

	if len(tags) != 1 {
		t.Fatalf("unexpected amount of tags found, %v != 1", len(tags))
	}
	if tags[0] != "phishing" {
		t.Fatal("unexpected tag found", tags[0])
	}

	// parse our example body for unknown charsets
	skylinks, tags, err = parseBody([]byte(unknownCharsetBody), logger.WithField("module", "Parser"))
	if err != nil {
		t.Fatal(err)
	}

	// assert we find the correct skylink and tag
	if len(skylinks) != 1 {
		t.Fatalf("unexpected amount of skylinks found, %v != 1", len(skylinks))
	}
	if skylinks[0] != "BACCHn5eHow5edoimjiwBtD2ErM3OL57mf-_MghKeebanA" {
		t.Fatal("unexpected skylink found", skylinks[0])
	}

	if len(tags) != 1 {
		t.Fatalf("unexpected amount of tags found, %v != 1", len(tags))
	}
	if tags[0] != "phishing" {
		t.Fatal("unexpected tag found", tags[0])
	}
}

// testParseBodySkyTransfer is a unit test that covers the functionality of the parseBody helper
func testParseBodySkyTransfer(t *testing.T) {
	t.Skip("skytransfer URL out of date")

	t.Parallel()

	// create discard logger
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// parse our example body containing skytransfer links
	skylinks, tags, err := parseBody([]byte(exampleSkyTransferBody), logger.WithField("module", "Parser"))
	if err != nil {
		t.Fatal(err)
	}
	// assert we find the correct skylink and tag
	if len(skylinks) != 1 {
		t.Fatalf("unexpected amount of skylinks found, %v != 1", len(skylinks))
	}
	if skylinks[0] != "AAAFb6q43vcBvF8KByAygTvWEDHW9pq95WyTDrQhPrhqRg" {
		t.Fatal("unexpected skylink found", skylinks[0])
	}

	if len(tags) != 1 {
		t.Fatalf("unexpected amount of tags found, %v != 1", len(tags))
	}
	if tags[0] != "abusive" {
		t.Fatal("unexpected tag found", tags[0])
	}
}

// testDedupe is a unit test that verifies the behaviour of the 'dedupe' helper
// function
func testDedupe(t *testing.T) {
	t.Parallel()

	input := []string{}
	output := dedupe(input)
	if len(output) != len(input) {
		t.Fatal("unexpected output", output)
	}

	input = []string{"a", "b", "a"}
	output = dedupe(input)
	sort.Strings(output)

	if len(output) != 2 {
		t.Fatal("unexpected output", output)
	}
	if output[0] != "a" || output[1] != "b" {
		t.Fatal("unexpected output", output)
	}
}

// testExtractPortalFromHnsDomain is a unit test that verifies the behaviour of the
// 'extractPortalFromHnsDomain' helper function
func testExtractPortalFromHnsDomain(t *testing.T) {
	t.Parallel()

	cases := []struct {
		url    string
		portal string
	}{
		{
			url:    "https://skytransfer.hns.siasky.net/#/v2/d871327aa70cd7525",
			portal: "siasky.net",
		},
		{
			url:    "https://skytransfer.hns.skyportal.xyz/#/v2/d871327aa70cd7525",
			portal: "skyportal.xyz",
		},
		{
			url:    "https://d871327aa70cd7525.skyportal.xyz/#/v2/d871327aa70cd7525",
			portal: "",
		},
	}

	for _, tt := range cases {
		portal := extractPortalFromHnsDomain(tt.url)
		if portal != tt.portal {
			t.Errorf("unexpected portal, '%v' != '%v'", portal, tt.portal)
		}
	}
}

// testExtractSkyTransferURLs is a unit test that verifies the behaviour of the
// 'extractSkyTransferURLs' helper function
func testExtractSkyTransferURLs(t *testing.T) {
	t.Parallel()

	// create discard logger
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// prepare some simple cases
	cases := []struct {
		input  []byte
		output []string
	}{
		{
			input:  exampleBody,
			output: []string{},
		},
		{
			input:  exampleSkyTransferBody,
			output: []string{"https://skytransfer.hns.siasky.net/#/v2/d871327aa70cd7525a3a323bf15896ea192da03254856602c0f030baeea8da8a/12a75f63a2cc182905731d68e9211d7d828f38e1203ff210c060d2eee81e6ff92b1fc48dfbf8649ab9b20b332780544626d83822621d63a44a187a90321bdf6a"},
		},
	}

	for _, tt := range cases {
		urls := extractSkyTransferURLs(tt.input, logger)
		if len(urls) != len(tt.output) {
			t.Errorf("unexpected urls, '%v' != '%v'", urls, tt.output)
		}
		sort.Strings(urls)
		for i, url := range urls {
			if url != tt.output[i] {
				t.Errorf("unexpected url, '%v' != '%v'", url, tt.output[i])
			}
		}
	}
}

// testExtractSkylinks is a unit test that verifies the behaviour of the
// 'extractSkylinks' helper function
func testExtractSkylinks(t *testing.T) {
	t.Parallel()

	// base case
	skylinks := extractSkylinks(nil)
	if len(skylinks) != 0 {
		t.Fatalf("unexpected amount of skylinks found, %v != 0", len(skylinks))
	}

	// extract skylinks
	skylinks = extractSkylinks(exampleBody)
	sort.Strings(skylinks)
	if len(skylinks) != 6 {
		t.Fatalf("unexpected amount of skylinks found, %v != 6, skylinks %+v", len(skylinks), skylinks)
	}

	// assert we have extracted the correct skylinks
	//
	// NOTE: we didn't discover IGzqsAmjjLJjN3Or8ZFb9AGX4Km12EJu5AVmgaX8HWNy7Q
	// which could have been a false positive as it's a valid skylink
	if skylinks[0] != "AAAg4mZrsNcedNPazZ4kSFAYBzf7f8ZgHO1Tu1L-NN8Gjg" ||
		skylinks[1] != "BBBg4mZrsNcedNPazZ4kSFAYBzf7f8ZgHO1Tu1L-NN8Gjg" ||
		skylinks[2] != "CADEnmNNR6arnyDSH60MlGjQK5O3Sv-ecK1PGt3MNmQUhA" ||
		skylinks[3] != "GABJJhT8AlfNh-XS-6YVH8en7O-t377ej9XS2eclnv2yFg" ||
		skylinks[4] != "GAEE7l0IkIVcVEHDgRCcNkRYS8keZKr9v_ffxf9_614m6g" ||
		skylinks[5] != "nAA_hbtNaOYyR2WrM9UNIc5jRu4WfGy5QK_iTGosDgLmSA" {
		t.Fatal("unexpected skylinks", skylinks)
	}

	// use a made up email body that contains base32 skylinks
	skylinks = extractSkylinks([]byte(`
	Hello,

	Please be informed that we have located another phishing content located at the following URLs:

	hxxps:// 7g01n1fmusamd3k4c5l7ahb39356rfhfs92e9mjshj1vq93vk891m2o [.] siasky [.] net

	hxxps:// [.] eu-ger-1 [.] siasky [.] net / 1005m6ki628f5t2o74h1qirph34lcavbn52oj7e2oan533sj3cgbr1o

	hxxps:// [.] eu-ger-1 [.] siasky [.] net2005m6KI628f5t2o74h1qirph34lcavbn52oj7e2oan533sj3cgbr2b

	3005m6ki628f5t2o74h1qirph34lcavbn52oj7e2oan533sj3cgbr2b
	`))
	if len(skylinks) != 4 {
		t.Fatalf("unexpected amount of skylinks found, %v != 4, skylinks: %v", len(skylinks), skylinks)
	}

	// NOTE: it will have loaded the base32 encoded version Skylink and output
	// its base64 encoded version
	var sl skymodules.Skylink
	if err := sl.LoadString("7g01n1fmusamd3k4c5l7ahb39356rfhfs92e9mjshj1vq93vk891m2o"); err != nil {
		t.Fatal(err)
	}
	if skylinks[0] != sl.String() {
		t.Fatal("unexpected skylinks", skylinks, sl.String())
	}

	// extract multiple base32 skylinks on single line
	skylinks = extractSkylinks([]byte(`
	before https://300g9rit1288an2k871o244s6p25giu93pialvdvuvfsbvrvtdf2dqg.siasky.net/foo/bar https://1005m6ki628f5t2o74h1qirph34lcavbn52oj7e2oan533sj3cgbr1o.siasky.net/index.html after
	`))
	if len(skylinks) != 2 {
		t.Log(skylinks)
		t.Fatalf("unexpected amount of skylinks found, %v != 2", len(skylinks))
	}
	sort.Strings(skylinks)
	if skylinks[0] != "CABbGpIwkPL0WDkiHUt5iMlWK-u5RYmdwsKuUY-TGyC9hw" ||
		skylinks[1] != "GAEE7l0IkIVcVEHDgRCcNkRYS8keZKr9v_ffxf9_614m6g" {
		t.Fatal("unexpected skylinks", skylinks)
	}

	// extract multiple base64 skylinks on single line
	skylinks = extractSkylinks([]byte(`
	before https://siasky.net/GAEE7l0IkIVcVEHDgRCcNkRYS8keZKr9v_ffxf9_614m6g?foo=bar https://siasky.net/CABbGpIwkPL0WDkiHUt5iMlWK-u5RYmdwsKuUY-TGyC9hw/index.html after
	`))
	if len(skylinks) != 2 {
		t.Log(skylinks)
		t.Fatalf("unexpected amount of skylinks found, %v != 2", len(skylinks))
	}
	sort.Strings(skylinks)
	if skylinks[0] != "CABbGpIwkPL0WDkiHUt5iMlWK-u5RYmdwsKuUY-TGyC9hw" ||
		skylinks[1] != "GAEE7l0IkIVcVEHDgRCcNkRYS8keZKr9v_ffxf9_614m6g" {
		t.Fatal("unexpected skylinks", skylinks)
	}
}

// testExtractTextFromHTML is a unit test that verifies the behaviour of the
// 'extractTextFromHTML' helper function
func testExtractTextFromHTML(t *testing.T) {
	t.Parallel()

	// extract text from HTML
	text, err := extractTextFromHTML(strings.NewReader(htmlBody))
	if err != nil {
		t.Fatal("unexpected error while extracting text from HTML", err)
	}

	// extract the skylinks from the text
	skylinks := extractSkylinks([]byte(text))
	if len(skylinks) != 1 {
		t.Fatalf("unexpected amount of skylinks found, %v != 1", len(skylinks))
	}
	if skylinks[0] != "CAA0F6NzigGep-VM6sJGewvHC6pZ2sJYTIVRsDYA4_QUVA" {
		t.Fatalf("unexpected skylink %v", skylinks[0])
	}

	// extract the tags from the text
	tags := extractTags([]byte(text))
	if len(tags) != 1 {
		t.Fatalf("unexpected amount of tags found, %v != 1", len(tags))
	}
	if tags[0] != "phishing" {
		t.Fatalf("unexpected tag %v", tags[0])
	}
}

// testExtractTags is a unit test that verifies the behaviour of the
// 'extractTags' helper function
func testExtractTags(t *testing.T) {
	t.Parallel()

	// base case, assert no tags are returned
	tags := extractTags(nil)
	if len(tags) != 0 {
		t.Fatalf("unexpected amount of tags found, %v != 0", len(tags))
	}

	// use a made up email body that contains all tags
	exampleBody := []byte(`
	This is an example of an email body that might contain phishing links, but could also contain malware or even skylinks that are infringing on copyright. In the worst cases it might contain skylinks that link to terrorist content or even child pornographic material, also known as csam.
	`)

	// extract the tags and assert we found all of them
	tags = extractTags(exampleBody)
	if len(tags) != 5 {
		t.Fatalf("unexpected amount of tags found, %v != 5", len(tags))
	}

	// assert we have extracted the correct tags
	sort.Strings(tags)
	if tags[0] != "copyright" || tags[1] != "csam" || tags[2] != "malware" || tags[3] != "phishing" || tags[4] != "terrorism" {
		t.Fatal("unexpected tags", tags)
	}

	// check whether islamic state is tagged as terrost content
	exampleBody = []byte(`
	This is an example of an email body that might contain links to islamic state propaganda.
	`)

	// extract the tags and assert we found all of them
	tags = extractTags(exampleBody)
	if len(tags) != 1 {
		t.Fatalf("unexpected amount of tags found, %v != 1", len(tags))
	}
	if tags[0] != "terrorism" {
		t.Fatal("unexpected tag", tags[0])
	}
}

// testBuildAbuseReport is a unit test that verifies the functionality of the
// 'buildAbuseReport' method on the Parser.
func testBuildAbuseReport(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// create discard logger
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// create test database
	db, err := database.NewTestAbuseScannerDB(ctx, "testBuildAbuseReport")
	if err != nil {
		t.Fatal(err)
	}

	// purge the database
	err = db.Purge(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// create a parser
	domain := "dev.siasky.net"
	parser := NewParser(ctx, db, domain, "somesponsor", logger)

	// create an abuse email
	email := database.AbuseEmail{
		ID:        primitive.NewObjectID(),
		UID:       "INBOX-1",
		UIDRaw:    1,
		Body:      exampleBody,
		From:      "someone@gmail.com",
		Subject:   "Abuse Subject",
		MessageID: "<msg_uid>@gmail.com",

		Parsed:    false,
		Blocked:   false,
		Finalized: false,

		InsertedBy: domain,
		InsertedAt: time.Now().UTC(),
	}

	// insert the email
	err = db.InsertOne(email)
	if err != nil {
		t.Fatal(err)
	}

	// parse the email
	err = parser.parseEmail(email)
	if err != nil {
		t.Fatal(err)
	}

	// fetch the email
	updated, err := db.FindOne(email.UID)
	if err != nil {
		t.Fatal(err)
	}

	// assert various fields on the email
	if !updated.Parsed {
		t.Fatal("expected the email to be parsed")
	}
	if updated.ParsedAt == (time.Time{}) {
		t.Fatal("expected 'parsedAt' to be set")
	}
	if updated.Finalized {
		t.Fatal("expected the email to not be finalized")
	}
	if updated.ParsedBy != domain {
		t.Fatal("expected the parsed_by field to be set")
	}

	// assert the parse result, note that we don't deep equal the parse result,
	// since we use the example email body we can rest assured it's correct
	// since the unit tests cover that as well
	pr := updated.ParseResult
	if len(pr.Skylinks) != 6 {
		t.Fatal("unexpected amount of skylinks", pr.Skylinks)
	}
	if len(pr.Tags) != 1 {
		t.Fatal("unexpected amount of tags", pr.Tags)
	}
	if pr.Sponsor != "somesponsor" {
		t.Fatal("unexpected sponsor", pr.Sponsor)
	}
	if pr.Reporter.Email != "someone@gmail.com" {
		t.Fatal("unexpected reporter", pr.Reporter.Email)
	}
}

// testShouldParseMediaType is a unit test that covers the ShouldParseMediaType helper function
func testShouldParseMediaType(t *testing.T) {
	t.Parallel()

	cases := []struct {
		mediaType   string
		shouldParse bool
	}{
		{
			mediaType:   "application/json",
			shouldParse: true,
		},
		{
			mediaType:   "audio/mp4",
			shouldParse: false,
		},
		{
			mediaType:   "font/otf",
			shouldParse: false,
		},
		{
			mediaType:   "example/foo",
			shouldParse: false,
		},
		{
			mediaType:   "image/png",
			shouldParse: false,
		},
		{
			mediaType:   "message/example",
			shouldParse: true,
		},
		{
			mediaType:   "model/example",
			shouldParse: false,
		},
		{
			mediaType:   "multipart/mixed",
			shouldParse: true,
		},
		{
			mediaType:   "text/html",
			shouldParse: true,
		},
		{
			mediaType:   "video/mp4",
			shouldParse: false,
		},
	}

	for _, tt := range cases {
		if output := shouldParseMediaType(tt.mediaType); output != tt.shouldParse {
			t.Errorf("unexpected outcome for media type '%v', %v != %v", tt.mediaType, output, tt.shouldParse)
		}
	}
}

// testWriteCypressConfig is a unit test that verifies the cypress config is
// properly written to disk
func testWriteCypressConfig(t *testing.T) {
	t.Parallel()

	// create a test dir
	dir := t.TempDir()

	// write cypress config
	err := writeCypressConfig(dir)
	if err != nil {
		t.Fatal(err)
	}

	// read the directory
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	// assert directory contents
	if len(files) != 1 {
		t.Fatal("expected one file", len(files))
	}
	configFile := files[0]
	if configFile.Name() != "cypress.config.js" {
		t.Fatal("unexpected filename")
	}

	// assert file contents
	contents, err := os.ReadFile(filepath.Join(dir, configFile.Name()))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != cypressConfig {
		t.Fatal("unexpected file contents", string(contents))
	}
}

// testWriteCypressTests is a unit test that verifies the cypress test is
// properly written to disk
func testWriteCypressTests(t *testing.T) {
	t.Parallel()

	// create discard logger
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// create a test dir
	dir := t.TempDir()

	// assert empty case
	err := writeCypressTests(dir, nil, logger)
	if err == nil || !strings.Contains(err.Error(), "no cypress tests generated") {
		t.Fatal(err)
	}

	// assert directory is still empty
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("unexpected dir contents", len(entries))
	}

	// assert base case
	err = writeCypressTests(dir, []string{
		"https://skytransfer.hns.siasky.net/#/v2/d871327/12a75f63",
		"https://skytransfer.hns.siasky.net/#/v2/12a75f63/d871327",
		"https://skytransfer.hns/#/v2/invalid/portal",
	}, logger)
	if err != nil {
		t.Fatal(err)
	}

	// assert directory contains subdir /cypress/integrations
	entries, err = os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !entries[0].IsDir() || entries[0].Name() != "cypress" {
		t.Fatal("unexpected dir contents", entries)
	}
	subpath := filepath.Join(dir, entries[0].Name())
	entries, err = os.ReadDir(subpath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !entries[0].IsDir() || entries[0].Name() != "integration" {
		t.Fatal("unexpected dir contents", entries)
	}
	subpath = filepath.Join(subpath, entries[0].Name())
	entries, err = os.ReadDir(subpath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].IsDir() || entries[0].Name() != "test.cy.js" {
		t.Fatal("unexpected dir contents", entries)
	}

	// assert file contents
	subpath = filepath.Join(subpath, entries[0].Name())
	contents, err := os.ReadFile(subpath)
	if err != nil {
		t.Fatal(err)
	}
	expected := `describe('SkyTransfer URL Resolver', () => {
  it('Resolves skylink for https://skytransfer.hns.siasky.net/#/v2/d871327/12a75f63', () => {
    cy.on('uncaught:exception', (err, runnable) => {return false});
    cy.on('fail', (e) => {return});
    cy.visit('https://skytransfer.hns.siasky.net/#/v2/d871327/12a75f63');
    cy.intercept('https://siasky.net/*').as('myReq');
    cy.get('.ant-btn').contains('Download all files').click();
    cy.wait('@myReq').should(($obj) => {cy.task('log', $obj.request.url)});
    cy.wait(30000);
  })
  it('Resolves skylink for https://skytransfer.hns.siasky.net/#/v2/12a75f63/d871327', () => {
    cy.on('uncaught:exception', (err, runnable) => {return false});
    cy.on('fail', (e) => {return});
    cy.visit('https://skytransfer.hns.siasky.net/#/v2/12a75f63/d871327');
    cy.intercept('https://siasky.net/*').as('myReq');
    cy.get('.ant-btn').contains('Download all files').click();
    cy.wait('@myReq').should(($obj) => {cy.task('log', $obj.request.url)});
    cy.wait(30000);
  })
})
`
	if string(contents) != expected {
		t.Fatal("unexpected file contents", diff.LineDiff(expected, string(contents)))
	}
}
