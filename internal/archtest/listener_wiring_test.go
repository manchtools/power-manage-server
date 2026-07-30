package archtest

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEveryEventListenerIsRegistered pins that a declared event listener is
// actually wired into the store.
//
// The failure this prevents is silent by nature. An unregistered listener
// compiles, has passing unit tests, and reads like working code — it simply
// never runs, so whatever property it enforces is not enforced at all. A test
// that constructs the listener directly and asserts its behaviour still passes,
// which is what makes this class of defect survive review.
//
// The same shape already shipped once on this branch: a revocation checker with
// correct logic and green tests that no production code ever constructed, so
// the fail-closed property it advertised was unreachable. Listeners are the
// common case of that mistake, and they are mechanically checkable.
//
// Self-discovering in both directions: constructors are found by scanning for
// the declaration shape, registrations by scanning for the call. Neither side is
// a hand-maintained list, so adding a listener adds an obligation automatically.
func TestEveryEventListenerIsRegistered(t *testing.T) {
	root := moduleRoot(t)

	declRe := regexp.MustCompile(`func ([A-Z][A-Za-z0-9]*Listener)\(`)
	// Registration may be qualified (api.SearchListener) or bare (TotpListener
	// inside its own package), and may wrap across lines, so match the name
	// following the call rather than the whole expression.
	regRe := regexp.MustCompile(`RegisterEventListener\(\s*(?:[a-z][A-Za-z0-9]*\.)?([A-Z][A-Za-z0-9]*Listener)\b`)

	declared := map[string]string{} // name -> file
	registered := map[string]bool{}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			base := info.Name()
			if base == ".git" || base == "node_modules" || base == "generated" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		text := string(src)
		isTest := strings.HasSuffix(path, "_test.go")

		if !isTest {
			for _, m := range declRe.FindAllStringSubmatch(text, -1) {
				rel, _ := filepath.Rel(root, path)
				declared[m[1]] = rel
			}
		}
		// Registrations in TEST files do not count: a listener wired only by a
		// test is precisely the unwired-in-production case this guard exists to
		// catch.
		if !isTest {
			for _, m := range regRe.FindAllStringSubmatch(text, -1) {
				registered[m[1]] = true
			}
		}
		return nil
	})
	require.NoError(t, err)

	// Matches-zero guards: an empty scan on either side would make the
	// comparison below vacuously true.
	require.NotEmpty(t, declared, "no event-listener constructors discovered — the scan is broken")
	require.NotEmpty(t, registered, "no listener registrations discovered — the scan is broken")

	var unwired []string
	for name, file := range declared {
		if !registered[name] {
			unwired = append(unwired, name+" ("+file+")")
		}
	}
	assert.Emptyf(t, unwired,
		"event listeners that are declared but never registered with the store:\n  %s\n"+
			"An unregistered listener compiles and unit-tests green while enforcing nothing. "+
			"Register it in production wiring, or delete it.",
		strings.Join(unwired, "\n  "))
}
