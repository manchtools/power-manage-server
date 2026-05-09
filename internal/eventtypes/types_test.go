package eventtypes

import (
	"regexp"
	"testing"
)

// TestAll_NoDuplicates ensures the All() slice has no duplicate values.
// A duplicate would mean two constants share a wire string and a typo
// or copy-paste mistake during a future addition would silently
// shadow an existing event.
func TestAll_NoDuplicates(t *testing.T) {
	seen := make(map[EventType]bool, len(All()))
	for _, et := range All() {
		if seen[et] {
			t.Errorf("duplicate event type in All(): %q", et)
		}
		seen[et] = true
	}
}

// TestAll_NonEmpty ensures every constant has a non-empty wire string.
// An empty event type would never match in any switch and would also
// fail the events table CHECK constraint.
func TestAll_NonEmpty(t *testing.T) {
	for i, et := range All() {
		if et == "" {
			t.Errorf("All()[%d] is empty", i)
		}
	}
}

// TestAll_MatchesPattern ensures every constant follows PascalCase
// (the project convention for event-type identifiers). This catches
// accidental snake_case or kebab-case slips at refactor time.
func TestAll_MatchesPattern(t *testing.T) {
	// Allow PascalCase with embedded uppercase runs (TOTPVerified,
	// SCIMGroupMapped, IdentityProviderSCIMEnabled). Identifiers must
	// start with an uppercase letter and contain only ASCII letters
	// and digits.
	pattern := regexp.MustCompile(`^[A-Z][A-Za-z0-9]+$`)
	for _, et := range All() {
		if !pattern.MatchString(string(et)) {
			t.Errorf("event type %q does not match PascalCase pattern", et)
		}
	}
}
