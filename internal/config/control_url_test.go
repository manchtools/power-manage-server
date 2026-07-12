package config

import (
	"strings"
	"testing"
)

// TestValidateControlURL pins the gateway control-URL startup contract
// (spec 29 AC8-9): accept only HTTPS URLs with a host and no user-info,
// query, or fragment; on success return the bare scheme://host[:port]
// origin; on failure never echo the raw (possibly credential-bearing)
// value in the error.
func TestValidateControlURL(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		cases := []struct {
			name       string
			in         string
			wantOrigin string
		}{
			{"host and port", "https://control:8082", "https://control:8082"},
			{"host only", "https://control", "https://control"},
			// A path is accepted for a Connect base URL, but the logged origin
			// never contains it.
			{"path allowed, stripped from origin", "https://control:8082/internal", "https://control:8082"},
			{"ipv6 host", "https://[2001:db8::1]:8082", "https://[2001:db8::1]:8082"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				origin, err := ValidateControlURL(tc.in)
				if err != nil {
					t.Fatalf("ValidateControlURL(%q) unexpected error: %v", tc.in, err)
				}
				if origin != tc.wantOrigin {
					t.Errorf("origin = %q, want %q", origin, tc.wantOrigin)
				}
				// The origin must never carry a path, query, fragment, or credential.
				for _, forbidden := range []string{"/internal", "?", "#", "@"} {
					if strings.Contains(origin, forbidden) {
						t.Errorf("origin %q leaks forbidden component %q", origin, forbidden)
					}
				}
			})
		}
	})

	t.Run("rejected without echoing the raw value", func(t *testing.T) {
		const secret = "s3cr3t-p4ss"
		cases := []struct {
			name string
			in   string
		}{
			{"empty", ""},
			{"malformed", "://nope"},
			{"whitespace in host", "https://cont rol:8082"},
			{"non-https http", "http://control:8082"},
			{"non-https scheme", "ftp://control:8082"},
			{"hostless", "https:///internal"},
			{"user-info credential", "https://admin:" + secret + "@control:8082"},
			{"query string", "https://control:8082?token=" + secret},
			{"fragment", "https://control:8082#" + secret},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				origin, err := ValidateControlURL(tc.in)
				if err == nil {
					t.Fatalf("ValidateControlURL(%q) = %q, want error", tc.in, origin)
				}
				if origin != "" {
					t.Errorf("origin = %q on error, want empty", origin)
				}
				// The error must name the offending component but never echo the
				// raw URL or any secret it carried.
				msg := err.Error()
				if tc.in != "" && strings.Contains(msg, tc.in) {
					t.Errorf("error %q echoes the raw URL %q", msg, tc.in)
				}
				if strings.Contains(msg, secret) {
					t.Errorf("error %q leaks the embedded secret", msg)
				}
			})
		}
	})
}
