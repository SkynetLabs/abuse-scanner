package utils

import (
	"fmt"
	"strings"
)

// SanitizeURL is a helper function that sanitizes the given input portal
// URL, stripping away trailing slashes and ensuring it's prefixed with https.
func SanitizeURL(portalURL string) string {
	portalURL = strings.TrimSpace(portalURL)
	portalURL = strings.TrimSuffix(portalURL, "/")
	if strings.HasPrefix(portalURL, "https://") {
		return portalURL
	}
	portalURL = strings.TrimPrefix(portalURL, "http://")
	if portalURL == "" {
		return portalURL
	}
	return fmt.Sprintf("https://%s", portalURL)
}
