package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Every periodic worker declared in periodic.go must actually be started.
//
// This exists because one was not. DeleteExpiredRevocations shipped with a
// passing unit test and no caller anywhere in cmd/, so the revocation list —
// consulted on every agent handshake — had nothing that ever pruned it. A
// store-level test proves the query works; it cannot notice that production
// never runs it, and reads as coverage while the behaviour is absent.
//
// Self-discovering rather than a list of the six known workers: a list would
// have to be updated by the same change that forgets the call site.
func TestEveryPeriodicWorkerIsStarted(t *testing.T) {
	src, err := os.ReadFile("periodic.go")
	require.NoError(t, err)

	launchers := regexp.MustCompile(`(?m)^func (start[A-Za-z]+)\(`).FindAllStringSubmatch(string(src), -1)
	require.NotEmpty(t, launchers,
		"no start* workers discovered in periodic.go — the scan is broken and this would pass vacuously")

	callSites := stripComments(nonTestSourceExcept(t, "periodic.go"))
	require.NotEmpty(t, callSites, "no non-test sources read — the scan is broken")

	for _, m := range launchers {
		name := m[1]
		// Not assert.Contains: on failure it dumps the whole concatenated
		// package source, which buries the one line that matters.
		if !strings.Contains(callSites, name+"(") {
			t.Errorf("%s is declared in periodic.go but never called outside it — the worker is defined and "+
				"never runs, so whatever it maintains is silently unmaintained in production", name)
		}
	}
}

// stripComments removes // and /* */ comments so a worker merely NAMED in prose
// cannot satisfy the guard. Without this the check passes on a comment reading
// "startRevocationSweeper(...) runs daily" while nothing calls it — the exact
// shape of the defect this test exists to catch.
func stripComments(src string) string {
	src = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, "")
	return regexp.MustCompile(`(?m)//.*$`).ReplaceAllString(src, "")
}

// nonTestSourceExcept concatenates the package's non-test Go sources, skipping
// the named file, so a launcher's own declaration cannot satisfy the check.
func nonTestSourceExcept(t *testing.T, skip string) string {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	var b strings.Builder
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == skip {
			continue
		}
		data, err := os.ReadFile(name)
		require.NoError(t, err)
		b.Write(data)
	}
	return b.String()
}
