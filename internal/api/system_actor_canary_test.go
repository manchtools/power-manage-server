package api

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestSystemActorCanary scans internal/api for every location that
// writes an audit event with ActorID="system", lists them with file:
// line, and emits a warning (t.Logf, not t.Error) for anything that
// isn't in the documented known-cases list below.
//
// Rationale: ActorID="system" labels an audit event as "not a human
// action" and should be reserved for deliberate, documented cases
// — bootstrap events, system-action auto-creation, settings
// migration. A silent fallback from "auth context missing" to
// "system" misattributes bugs to the system itself and hides them
// (see the rc7 terminal_handler and device_handler cleanups). This
// test is the canary: it does NOT fail the suite on an unknown
// site, it warns, so the next reviewer investigates and either
// adds an entry to knownSystemActorSites with a rationale or
// replaces the fallback with requireAuth.
//
// Run with -v to see the warnings on every CI run.
//
// When you intentionally add a new system-actor append, also add a
// row to knownSystemActorSites with a one-line rationale.
var knownSystemActorSites = map[string]string{
	// Settings — initial seed + schema migrations run by the control
	// server itself, not by any user. These are legitimately "system"
	// actions: there is no user to attribute them to at bootstrap time.
	"settings_handler.go:57":  "initial settings seeded at control-server boot",
	"settings_handler.go:123": "settings schema migration on server start",
	"settings_handler.go:158": "settings schema migration on server start",

	// System actions — pm-tty-* and SSH-access actions auto-created /
	// re-bound by the control server. Not user-initiated; the server
	// owns the lifecycle.
	"system_actions.go:394": "auto-created pm-tty-* user action (first-time provision)",
	"system_actions.go:419": "auto-created pm-tty-* user action (rebind on config change)",
	"system_actions.go:439": "auto-created SSH access action (first-time provision)",
	"system_actions.go:451": "auto-created SSH access action (rebuild)",
	"system_actions.go:467": "auto-created SSH access action (schema migration)",
}

func TestSystemActorCanary(t *testing.T) {
	// Scan .go files in this package directory (internal/api) for
	// literal `ActorID: "system"` lines. Excludes test files.
	sites := scanSystemActorSites(t, ".")
	sort.Strings(sites)

	t.Logf("SystemActor canary: found %d site(s) with ActorID=\"system\"", len(sites))

	for _, site := range sites {
		// Key format is `<file-basename>:<line>`. file-basename is
		// used rather than a full path so a test running from
		// different working directories stays consistent.
		if rationale, known := knownSystemActorSites[site]; known {
			t.Logf("  [known ] %s — %s", site, rationale)
		} else {
			// The warning. Not a failure. A reviewer reading `go test
			// -v` output will see this and investigate.
			t.Logf("  [WARN  ] %s — UNKNOWN; verify this is intentional and update knownSystemActorSites with a rationale", site)
		}
	}

	// Also flag removals: entries in knownSystemActorSites that no
	// longer exist in the source indicate the call site was deleted
	// or moved. Warn so the entry can be cleaned up.
	siteSet := make(map[string]struct{}, len(sites))
	for _, s := range sites {
		siteSet[s] = struct{}{}
	}
	for expected := range knownSystemActorSites {
		if _, found := siteSet[expected]; !found {
			t.Logf("  [stale ] %s — listed in knownSystemActorSites but no longer in source; remove the entry", expected)
		}
	}
}

// scanSystemActorSites walks dir for non-test .go files and returns
// every `<file-basename>:<line>` whose contents match the literal
// `ActorID: "system"` pattern (whitespace tolerant).
func scanSystemActorSites(t *testing.T, dir string) []string {
	t.Helper()

	// Match the ActorID assignment form used in struct literals:
	//     ActorID:   "system",
	//     ActorID:    "system"
	// Tolerant of any whitespace between ActorID, :, and the string.
	re := regexp.MustCompile(`ActorID\s*:\s*"system"`)

	var hits []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		lineNo := 0
		// Default buf is fine; api/ files are not enormous but bump
		// anyway to tolerate a few oversized generated stubs.
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			lineNo++
			if re.MatchString(scanner.Text()) {
				hits = append(hits, filepath.Base(path)+":"+itoa(lineNo))
			}
		}
		return scanner.Err()
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	return hits
}

// itoa is a tiny strconv.Itoa shim; avoids another import just for
// one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
