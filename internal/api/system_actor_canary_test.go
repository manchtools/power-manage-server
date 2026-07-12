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

// TestSystemActorCanary scans internal/api for every location that writes an
// audit event with ActorID="system", keyed by ENCLOSING FUNCTION, and FAILS the
// suite for any site that is not in the documented known-cases list below (and
// for any stale list entry).
//
// Rationale: ActorID="system" labels an audit event as "not a human action" and
// must be reserved for deliberate, documented cases — bootstrap events,
// system-action auto-creation, settings migration, system-generated
// compensating events. A silent fallback from "auth context missing" to
// "system" misattributes bugs to the system itself and hides them (see the rc7
// terminal_handler and device_handler cleanups). The canary forces every new
// system-actor write to be reviewed: a reviewer either adds an entry here with a
// rationale or replaces the fallback with requireAuth.
//
// Sites are keyed by `<file>:<enclosing-func>` (not a line number) so the
// allowlist is stable across unrelated edits.
var knownSystemActorSites = map[string]string{
	// System action store — the control server owns the lifecycle of
	// server-managed actions (pm-tty-*, SSH access, etc.); there is no user to
	// attribute these writes to.
	"system_action_store.go:CreateAction":       "system action store creates a server-owned action",
	"system_action_store.go:UpdateAction":       "system action store updates a server-owned action",
	"system_action_store.go:DeleteAction":       "system action store deletes a server-owned action",
	"system_action_store.go:LinkAction":         "system action store links a server-owned action into a set/definition",
	"system_action_store.go:AssignActionToUser": "system action store assigns a server-owned action to a user",

	// Terminal-admin membership is server-managed, not user-initiated.
	"system_actions.go:emitTerminalAdminMembershipRevoked": "server emits terminal-admin membership revocation",

	// Dispatch compensating events — the SERVER records an ExecutionFailed when
	// the dispatch enqueue itself fails; it is a system event, not the
	// dispatching user's action.
	"action_dispatch.go:DispatchAction":        "system-generated ExecutionFailed compensating event on enqueue failure",
	"action_dispatch.go:DispatchInstantAction": "system-generated ExecutionFailed compensating event on enqueue failure",

	// LUKS device-key revocation lifecycle is recorded by the server.
	"device_handler.go:RevokeLuksDeviceKey": "server records the LUKS device-key revocation lifecycle event",

	// LPS sealing keypair is boot infrastructure the control server owns
	// (#495): both the fresh-generation append and the upgrade backfill of
	// the singleton LpsKeypairGenerated event have no user actor.
	"lps_keypair.go:EnsureLpsKeypair":         "server generates the singleton LPS sealing keypair at boot; no user actor",
	"lps_keypair.go:backfillLpsKeypairStream": "server backfills the LpsKeypairGenerated event for pre-#495 deployments; no user actor",

	// Settings cascades into server-owned system actions on a bulk toggle — no
	// per-user actor. (The top-level ServerSettingUpdated event is now attributed
	// to the acting admin — spec 29 S12 — so UpdateServerSettings is no longer a
	// system-actor site.)
	"settings_handler.go:enableSshAccessForAllUsers":    "bulk SSH-access enablement creates server-owned actions",
	"settings_handler.go:enableProvisioningForAllUsers": "bulk provisioning enablement creates server-owned actions",
}

func TestSystemActorCanary(t *testing.T) {
	// Scan .go files in this package directory (internal/api) for
	// literal `ActorID: "system"` lines. Excludes test files.
	sites := scanSystemActorSites(t, ".")
	sort.Strings(sites)

	t.Logf("SystemActor canary: found %d site(s) with ActorID=\"system\"", len(sites))

	// Matches-zero guard: the scan walks the package source for the literal
	// pattern. If it ever finds NOTHING (a regex/path drift, or the file moved),
	// the canary would silently pass while no longer guarding anything.
	if len(sites) == 0 {
		t.Fatal(`SystemActor canary found ZERO ActorID="system" sites — the scanner drifted and can no longer catch an unreviewed system-actor write`)
	}

	for _, site := range sites {
		// Key format is `<file-basename>:<enclosing-func>` — file basename (not a
		// full path) so the key is working-directory-independent, and the
		// enclosing function (not a line number) so it survives unrelated edits.
		if rationale, known := knownSystemActorSites[site]; known {
			t.Logf("  [known ] %s — %s", site, rationale)
		} else {
			// A new, unreviewed system-actor write site is a FAILURE: every such
			// site bypasses the actor-authorization model and must be reviewed
			// and recorded in knownSystemActorSites with a rationale.
			t.Errorf(`UNKNOWN ActorID="system" site %s — verify it is intentional and add it to knownSystemActorSites with a rationale`, site)
		}
	}

	// A stale exemption (listed but no longer in source) is real drift, not a
	// warning: left in place it could later mask a genuine new site at the same
	// key. Fail so it is cleaned up.
	siteSet := make(map[string]struct{}, len(sites))
	for _, s := range sites {
		siteSet[s] = struct{}{}
	}
	for expected := range knownSystemActorSites {
		if _, found := siteSet[expected]; !found {
			t.Errorf("stale knownSystemActorSites entry %s — listed but no longer in source; remove it", expected)
		}
	}
}

// scanSystemActorSites walks dir for non-test .go files and returns the
// DEDUPED set of `<file-basename>:<enclosing-func>` for every line matching the
// literal `ActorID: "system"` pattern (whitespace tolerant).
func scanSystemActorSites(t *testing.T, dir string) []string {
	t.Helper()

	// Match the ActorID assignment form used in struct literals:
	//     ActorID:   "system",
	//     ActorID:    "system"
	// Tolerant of any whitespace between ActorID, :, and the string.
	re := regexp.MustCompile(`ActorID\s*:\s*"system"`)
	// Enclosing function: `func Name(` or `func (recv) Name(`. Keying sites by
	// their enclosing function rather than a line number keeps the allowlist
	// STABLE across unrelated edits — a line-number key drifts on every change
	// above the site, turning the gate into churn.
	funcRe := regexp.MustCompile(`^func\s+(?:\([^)]*\)\s+)?([A-Za-z0-9_]+)\s*\(`)

	seen := map[string]struct{}{}
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
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		currentFunc := "<file-scope>"
		for scanner.Scan() {
			line := scanner.Text()
			if m := funcRe.FindStringSubmatch(line); m != nil {
				currentFunc = m[1]
			}
			if re.MatchString(line) {
				seen[filepath.Base(path)+":"+currentFunc] = struct{}{}
			}
		}
		return scanner.Err()
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}
