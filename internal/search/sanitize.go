package search

import (
	"strings"
	"unicode/utf8"
)

// Length caps for agent-controlled values written to the search index.
const (
	maxHostnameField = 253  // DNS hostname ceiling
	maxLabelsField   = 4096 // flattened "k=v k=v …" label blob
	maxOSField       = 256  // os_name / os_version / os_arch / kernel / agent_version
)

// sanitizeSearchField bounds an AGENT-CONTROLLED string before it is written
// into the Valkey search index. Agents self-report hostname / labels / os_* /
// kernel / agent_version; a malicious or buggy agent could report a multi-KB
// value (index bloat / memory pressure) or one embedding ASCII control
// characters or <markup> (which a UI rendering raw search-result fields could
// then execute). The helper drops control characters (incl. NUL and newlines),
// angle brackets, and invalid UTF-8, then caps the result to maxRunes.
//
// Operator-set fields (linux_username, actor_id) are trusted-by-policy and are
// deliberately NOT routed through this — they never originate from an agent.
func sanitizeSearchField(s string, maxRunes int) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	runes := 0
	for _, r := range s {
		if runes >= maxRunes {
			break
		}
		if r == '<' || r == '>' {
			continue
		}
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			continue
		}
		b.WriteRune(r)
		runes++
	}
	return b.String()
}
