package scim

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// baseURLFromRequest reconstructs the externally visible base of this
// directory's endpoint, which SCIM resources echo back in `meta.location`
// and `$ref`.
//
// The scheme comes from the TLS state, or from X-Forwarded-Proto when
// the connection was terminated upstream. Only the two literal values
// the header may carry are honoured; anything else falls back to http
// rather than being reflected into a URL.
func baseURLFromRequest(r *http.Request, slug string) string {
	scheme := "https"
	if r.TLS == nil {
		if fwd := r.Header.Get("X-Forwarded-Proto"); fwd == "https" || fwd == "http" {
			scheme = fwd
		} else {
			scheme = "http"
		}
	}
	return fmt.Sprintf("%s://%s/scim/v2/%s", scheme, r.Host, slug)
}

// fingerprint reduces a value to its SHA-256 hex digest, which is what
// the audit log accepts as class-two evidence. The empty string maps to
// the empty string rather than to the digest of nothing, so "absent"
// and "present but empty" do not collide.
func fingerprint(v string) string {
	if v == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// normalizeEmail lowercases and trims an address so the unique index
// and every later lookup agree on what "the same address" means. The
// identity handlers normalise identically; a directory that asserted
// mixed case would otherwise create a second subject for one person.
func normalizeEmail(v string) string { return strings.ToLower(strings.TrimSpace(v)) }

// formatExternalName renders a SCIM name object as a display name,
// preferring the formatted form the directory supplied.
func formatExternalName(name *SCIMName) string {
	if name == nil {
		return ""
	}
	if name.Formatted != "" {
		return name.Formatted
	}
	parts := make([]string, 0, 2)
	if name.GivenName != "" {
		parts = append(parts, name.GivenName)
	}
	if name.FamilyName != "" {
		parts = append(parts, name.FamilyName)
	}
	return strings.Join(parts, " ")
}
