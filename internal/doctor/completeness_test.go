package doctor

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAllChecksAreTested is the self-discovering completeness guard (spec 15,
// criterion 15): every check registered in DefaultChecks() must be constructed by
// a test in this package. It derives the check set from DefaultChecks() (no
// hardcoded list) and scans the package's *_test.go for each check's concrete
// type — so adding a check without a test fails the build. Includes a
// matches-zero guard and a duplicate-id guard.
func TestAllChecksAreTested(t *testing.T) {
	checks := DefaultChecks()
	require.NotEmpty(t, checks, "matches-zero guard: DefaultChecks() is empty")

	src := packageTestSource(t)
	require.NotEmpty(t, src, "no *_test.go source read — the scan is broken")

	seen := map[string]bool{}
	for _, c := range checks {
		id := c.ID()
		assert.Falsef(t, seen[id], "duplicate check id %q", id)
		seen[id] = true

		typeName := reflect.TypeOf(c).Name()
		assert.Containsf(t, src, typeName+"{",
			"check %q (%s) is registered but never constructed in a test — add a unit test", id, typeName)
	}
}

func packageTestSource(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	var b strings.Builder
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(e.Name())
		require.NoError(t, err)
		b.Write(data)
	}
	return b.String()
}
