package projectors

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/stretchr/testify/require"
)

// unprojectedAllowlist is the EXACT set of event types that are intentionally
// NOT handled by a projector listener in this package. Each is consumed
// elsewhere (a live-stream sink, an api-side handler/listener, or an async
// dispatch trigger) rather than projected into a *_projection table. Keeping the
// set explicit means a NEW event type that nobody projects fails
// TestEventTypes_AllHandledByProjectorOrAllowlisted instead of silently becoming
// an orphan; and an entry here that later DOES get a projector (or isn't a real
// event) also fails, so the allowlist can't go stale.
var unprojectedAllowlist = map[eventtypes.EventType]string{
	eventtypes.OutputChunk:                      "live execution output — sunk by control/inbox_worker, never projected",
	eventtypes.TerminalSessionStarted:           "terminal_sessions written directly by api/terminal_handler",
	eventtypes.TerminalSessionStopped:           "terminal_sessions written directly by api/terminal_handler",
	eventtypes.TerminalSessionTerminated:        "terminal_sessions written directly by api/terminal_handler",
	eventtypes.TerminalAdminMembershipRevoked:   "consumed by api/system_actions reconciler, not a projection",
	eventtypes.LuksDeviceKeyRevocationRequested: "triggers async revocation dispatch in api/device_handler, no projection",
	// #496 audit-only events: they record WHO did WHAT to WHICH
	// device/session for the audit log; there is no projection to
	// materialise (the underlying result/token/denylist tables are
	// transient operational state, and users_projection needs no new
	// column for a logout/refresh).
	eventtypes.OSQueryDispatched:               "audit-only (#496): who dispatched an osquery read; no projection",
	eventtypes.DeviceLogsQueried:               "audit-only (#496): who queried device logs; no projection",
	eventtypes.DeviceInventoryRefreshRequested: "audit-only (#496): who refreshed inventory; no projection",
	eventtypes.LuksTokenCreated:                "audit-only (#496): who issued a LUKS token; no projection",
	eventtypes.UserLoggedOut:                   "audit-only (#496): session end; the denylist row is operational state",
	eventtypes.UserSessionRefreshed:            "audit-only (#496): session rotation; no projection",
	eventtypes.EventLogPruned:                  "retention marker (spec 19): records a prune checkpoint + archive pointer; no projection — doctor reads it directly for retention posture",
}

// TestEventTypes_AllHandledByProjectorOrAllowlisted is a self-discovering guard
// (#13) that every event in eventtypes.All() is either handled by a projector
// listener in this package OR explicitly allow-listed as intentionally
// unprojected. It discovers the handled set by AST-scanning this package for
// `eventtypes.<Name>` references (listeners and their Apply* bodies dispatch on
// these), so it can't fall stale against a hardcoded list. A new orphan event
// fails here; so does a stale allowlist entry.
func TestEventTypes_AllHandledByProjectorOrAllowlisted(t *testing.T) {
	all := eventtypes.All()
	require.NotEmpty(t, all, "eventtypes.All() is empty — the parity check would be vacuous")

	handled := handledEventTypes(t)
	require.NotEmpty(t, handled, "no eventtypes.<X> references found in projectors — the scan is broken")

	// Every registered event must be projected here or allow-listed.
	var orphans []string
	for _, e := range all {
		if handled[string(e)] {
			continue
		}
		if _, ok := unprojectedAllowlist[e]; ok {
			continue
		}
		orphans = append(orphans, string(e))
	}
	sort.Strings(orphans)
	require.Emptyf(t, orphans,
		"event types with NO projector and not allow-listed (#13):\n  %s\n"+
			"Wire a projector listener, or add an entry to unprojectedAllowlist with the reason it is intentionally unprojected.",
		strings.Join(orphans, "\n  "))

	// Keep the allowlist honest: every entry must be a real event AND not also
	// handled by a projector (else it's stale).
	allSet := make(map[string]bool, len(all))
	for _, e := range all {
		allSet[string(e)] = true
	}
	for e := range unprojectedAllowlist {
		require.Truef(t, allSet[string(e)], "allowlisted %q is not in eventtypes.All() — remove the stale entry", e)
		require.Falsef(t, handled[string(e)], "allowlisted %q IS handled by a projector — remove it from unprojectedAllowlist", e)
	}
}

// handledEventTypes returns the set of event-type names referenced as
// `eventtypes.<Name>` in non-test .go files of this package.
func handledEventTypes(t *testing.T) map[string]bool {
	t.Helper()
	handled := map[string]bool{}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	for _, ent := range entries {
		name := ent.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		require.NoErrorf(t, err, "parse %s", name)
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "eventtypes" {
				handled[sel.Sel.Name] = true
			}
			return true
		})
	}
	return handled
}
