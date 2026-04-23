package api_test

import (
	"strings"
	"testing"

	"github.com/manchtools/power-manage/server/internal/api"
)

// TestValidateGatewayURL covers the shapes the control server may be
// handed via CONTROL_GATEWAY_URL and the ones registration_handler
// rechecks defensively. Each case captures a real operator footgun
// rc10 reviewers flagged:
//
//   - empty string — rc10 closed the "enroll with empty URL" path.
//   - bare hostname like "gateway.example.com" — parses via url.Parse
//     without error but isn't an absolute URL; the agent would dial
//     a relative path and fail with a cryptic error.
//   - http:// — agents refuse h2c as of rc10 (see agent main.go).
//   - ws:// / wss:// — agent uses HTTPS transport for the streaming
//     client; accepting wss here would confuse the operator.
//   - userinfo — credentials in the URL leak on every enrollment
//     response and are never the right answer.
//   - fragment — meaningless on the wire.
func TestValidateGatewayURL(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantErr  bool
		wantWord string // substring that must appear in the error message
	}{
		{"empty", "", true, "empty"},
		{"bare hostname", "gateway.example.com", true, "scheme"},
		{"http downgrade", "http://gateway.example.com", true, "https"},
		{"wss scheme", "wss://gateway.example.com", true, "https"},
		{"ws scheme", "ws://gateway.example.com", true, "https"},
		{"userinfo", "https://user:pass@gateway.example.com", true, "userinfo"},
		{"userinfo username only", "https://user@gateway.example.com", true, "userinfo"},
		{"fragment", "https://gateway.example.com#frag", true, "fragment"},
		{"host only", "https://", true, "host"},
		// CR called out that u.Host would accept ":8443" silently
		// (it treats the empty part as a host with a port). Switching
		// to u.Hostname() plus this regression test closes the gap.
		{"port without hostname", "https://:8443", true, "host"},

		{"happy path host", "https://gateway.example.com", false, ""},
		{"happy path with port", "https://gateway.example.com:8443", false, ""},
		{"happy path with path", "https://gateway.example.com/gw/01ABC", false, ""},
		{"happy path with trailing slash", "https://gateway.example.com/", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := api.ValidateGatewayURL(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ValidateGatewayURL(%q) = nil, want error containing %q", tc.in, tc.wantWord)
				}
				if tc.wantWord != "" && !strings.Contains(err.Error(), tc.wantWord) {
					t.Errorf("ValidateGatewayURL(%q) err = %q, want substring %q", tc.in, err.Error(), tc.wantWord)
				}
				return
			}
			if err != nil {
				t.Errorf("ValidateGatewayURL(%q) = %v, want nil", tc.in, err)
			}
		})
	}
}
