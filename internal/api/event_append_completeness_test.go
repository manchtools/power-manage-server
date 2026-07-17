package api

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage-sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// This file is the self-discovering fitness guard for #495: every
// state-changing ControlService RPC must append an event — the events table IS
// the audit log ("every state-changing RPC is audit-logged"), and the
// event→projector path is the only sanctioned write path for domain state.
//
// Two assertions, following the house AST-guard pattern
// (admin_guard_completeness_test.go / object_scope_parity_test.go /
// scope_enforcement_parity_test.go):
//
//  1. TestEveryMutatingControlRPCAppendsEvent — the full RPC surface is
//     discovered from pmv1connect.ControlServiceHandler (never a hardcoded
//     list), each RPC is classified mutating/read-only by its leading verb
//     (an unclassifiable verb fails the test), and every mutating RPC's
//     intra-package call graph must reach Store.AppendEvent /
//     Store.AppendEventWithVersion.
//
//  2. TestNoDirectStoreWritesFromHandlers — no non-test file in this package
//     may call a generated write query (Insert*/Update*/Delete*/Upsert* on
//     db.Queries) or a repo write method (Create*/Mark*/Consume*/... on a
//     store.Repos interface) except at explicitly allowlisted sites, each
//     with a why-comment for the by-design non-event-sourced write.

// readOnlyRPCPrefixes are the leading verbs of RPCs that perform no
// state change (reads MAY still append events — sensitive-read auditing,
// cf. #494 — so assertion 1 simply does not require anything of them).
var readOnlyRPCPrefixes = []string{"Get", "List", "Search", "Validate", "Evaluate", "Export"}

// mutatingRPCPrefixes are the leading verbs of state-changing RPCs. A new RPC
// whose name starts with none of the prefixes in either set fails the
// classification guard below, forcing an explicit decision here.
var mutatingRPCPrefixes = []string{
	"Add", "AdminDisable", "Assign", "Cancel", "Create", "Delete", "Disable",
	"Dispatch", "Enable", "Login", "Logout", "Query", "Rebuild", "Refresh",
	"Regenerate", "Register", "Remove", "Rename", "Renew", "Reorder", "Revoke",
	"Rotate", "SSOCallback", "Set", "Setup", "Start", "Stop", "Terminate",
	"Unassign", "Unlink", "Update", "Verify",
}

// nonEventMutations are mutating RPCs VERIFIED to be by-design
// non-event-sourced. Each entry carries its why. The guard asserts these do
// NOT reach AppendEvent — if one starts appending, the entry must be removed
// (anti-rot, mirroring validateExemptControlRPCs).
var nonEventMutations = map[string]string{
	// RebuildSearchIndex re-derives the valkey FT search index from the
	// Postgres projections. It writes no Postgres state at all — the source
	// of truth is untouched, so there is no state change to audit.
	"RebuildSearchIndex": "valkey-only rebuild of the derived search index; no Postgres state is written",
}

// knownGaps holds mutating RPCs that change state without appending an event.
// #496 CLOSED every gap found here (DispatchOSQuery, QueryDeviceLogs,
// RefreshDeviceInventory, CreateLuksToken, Logout, RefreshToken now all
// append an audit event), so the map is intentionally EMPTY: the guard below
// requires every mutating RPC to reach AppendEvent, with no tracked-debt
// escape hatch. A future gap must be FIXED, not parked here.
var knownGaps = map[string]string{}

// TestEveryMutatingControlRPCAppendsEvent is assertion 1 of the #495 guard:
// mutating RPC ⇒ AppendEvent reachable through the handler's intra-package
// call graph.
//
// Discovery mechanics: the RPC surface comes from the
// pmv1connect.ControlServiceHandler interface via reflection (a newly wired
// proto RPC appears there at compile time); handler bodies come from parsing
// every non-test .go file in this package. The call graph is walked by callee
// NAME (the same over-approximation admin_guard_completeness_test.go uses):
// RPC method names are globally unique in the proto, so the ControlService
// delegation method and the sub-handler method it forwards to share a name
// and are traversed together. Calls into other packages are leaves; only
// AppendEvent / AppendEventWithVersion count as the win condition, so the
// walk cannot be satisfied by a projection write or a task enqueue.
func TestEveryMutatingControlRPCAppendsEvent(t *testing.T) {
	rpcs := controlServiceRPCNames(t)
	require.Greater(t, len(rpcs), 100,
		"expected the full ControlService surface (>100 RPCs), got %d — discovery is broken", len(rpcs))

	decls := parsePackageDecls(t)
	require.NotEmpty(t, decls, "parsed zero declarations — discovery is broken")

	var unclassified, ambiguous []string
	var mutating []string
	for _, name := range rpcs {
		isRead := hasAnyPrefix(name, readOnlyRPCPrefixes)
		isMut := hasAnyPrefix(name, mutatingRPCPrefixes)
		switch {
		case isRead && isMut:
			ambiguous = append(ambiguous, name)
		case isMut:
			mutating = append(mutating, name)
		case !isRead:
			unclassified = append(unclassified, name)
		}
	}
	require.Emptyf(t, ambiguous,
		"RPCs matching BOTH prefix sets (overlapping prefixes — fix the sets): %s", strings.Join(ambiguous, ", "))
	require.Emptyf(t, unclassified,
		"RPCs with an unknown leading verb — classify each in readOnlyRPCPrefixes or mutatingRPCPrefixes: %s",
		strings.Join(unclassified, ", "))
	require.Greater(t, len(mutating), 50,
		"expected a substantial mutating surface (>50 RPCs), got %d — classification is broken", len(mutating))

	var missing, staleAllowlist, fixedGaps []string
	reached := 0
	for _, name := range mutating {
		require.NotEmptyf(t, decls[name], "RPC %s has no declaration in this package — parse/discovery is broken", name)
		ok := reachesEventAppend(name, decls, map[string]bool{})
		switch {
		case nonEventMutations[name] != "":
			if ok {
				staleAllowlist = append(staleAllowlist, name)
			}
		case knownGaps[name] != "":
			if ok {
				fixedGaps = append(fixedGaps, name)
			}
		case !ok:
			missing = append(missing, name)
		default:
			reached++
		}
	}
	sort.Strings(missing)

	require.Positive(t, reached, "no mutating RPC reached AppendEvent — the call-graph walk is broken (it must never pass vacuously)")
	require.Emptyf(t, staleAllowlist,
		"nonEventMutations entries that now DO append an event — remove them: %s", strings.Join(staleAllowlist, ", "))
	require.Emptyf(t, fixedGaps,
		"knownGaps entries that now append an event — the gap is fixed, remove them: %s", strings.Join(fixedGaps, ", "))
	require.Emptyf(t, missing,
		"state-changing RPCs whose handler flow never reaches AppendEvent/AppendEventWithVersion (#495 — the events table is the audit log):\n  %s\n"+
			"Each must append an event, or be a verified by-design entry in nonEventMutations, or a tracked finding in knownGaps.",
		strings.Join(missing, "\n  "))
}

// TestEventAppendGuardListsAreReal guards the three lists above against rot:
// every entry must name a live ControlService RPC, and the two exemption maps
// must stay disjoint.
func TestEventAppendGuardListsAreReal(t *testing.T) {
	real := map[string]bool{}
	for _, name := range controlServiceRPCNames(t) {
		real[name] = true
	}
	for name := range nonEventMutations {
		require.Truef(t, real[name], "nonEventMutations names %q but no such ControlService RPC — stale entry", name)
		require.Emptyf(t, knownGaps[name], "%q is in BOTH nonEventMutations and knownGaps — pick one", name)
	}
	for name := range knownGaps {
		require.Truef(t, real[name], "knownGaps names %q but no such ControlService RPC — stale entry", name)
	}
}

// apiAllowedDirectWrites are the ONLY sanctioned direct-store-write call sites
// in the api package, keyed "file.go:Func:CalleeName" (function-granular, so two
// sites calling the same write method in one file each need their own entry —
// see assertNoDirectStoreWrites). Every entry is a verified by-design
// non-event-sourced write with its why. A stale entry (no longer observed) fails
// the guard so the list can only shrink honestly.
//
// The dividing line: these all write OPERATIONAL tables (flow state, staging
// rows, live-session inventory, infra rows) — none writes domain state that
// the event→projector path owns. The one projection-column exception
// (UpdateSignature) backfills columns the projector deliberately does not
// set, immediately after the event append, with a compensating-event
// rollback (see persistActionSignature / rollbackUnsignedCreate).
var apiAllowedDirectWrites = map[string]string{
	// NOTE(#495): the lps_keypair row — historically the one Postgres write
	// bypassing the event store (#483 / ADR 0028) — is now a real projection
	// of LpsKeypairGenerated; EnsureLpsKeypair appends, the projector writes.
	// No allowlist entry exists for it, and none may be re-added.

	// Two-phase sign-after-append: the signature/params-canonical columns are
	// backfilled onto the projection row AFTER appendEvent(ActionCreated /
	// ActionParamsUpdated) — the projector doesn't set them. Failure emits a
	// compensating ActionDeleted (rollbackUnsignedCreate).
	"action_crud.go:persistActionSignature:UpdateSignature": "post-append signature backfill; projector-owned row, columns the projector doesn't set",
	"system_action_store.go:SignActionByID:UpdateSignature": "same sign-after-append backfill for system-managed actions",

	// JWT refresh-token revocation list — TTL'd session infra rows, not
	// domain state. Logout and RefreshToken each revoke the presented token;
	// both audit-log the session lifecycle (#496), only the denylist row stays
	// by-design non-event-sourced. Two distinct call sites, one per flow.
	"auth_handler.go:Logout:Revoke":       "revoked_tokens session-infra row (WS11) on logout; the RPC audit event is appended (#496), the denylist row itself is not event-sourced",
	"auth_handler.go:RefreshToken:Revoke": "revoked_tokens session-infra row (WS11) rotating the old refresh token; the RPC audit event is appended (#496), the denylist row itself is not event-sourced",

	// Short-lived OIDC flow rows: staged at GetSSOLoginURL, destructively
	// consumed on first read at SSOCallback (replay defense). Flow infra;
	// the login OUTCOME is audited via UserLoggedIn in SSOCallback.
	"sso_handler.go:GetSSOLoginURL:Create": "auth_states OIDC flow row, consumed at callback; login outcome is event-audited",
	"sso_handler.go:SSOCallback:Consume":   "destructive first-read consumption of the auth_states flow row (replay defense)",

	// One-time LUKS key-storage tokens (hashed at rest, WS10): staged by
	// CreateLuksToken, redeemed exactly once by the agent via the internal
	// proxy. The resulting key STORAGE is event-sourced (ProxyStoreLuksKey
	// appends). CreateLuksToken now appends its own audit event (#496).
	"device_handler.go:CreateLuksToken:CreateToken":           "luks_tokens one-time token row (WS10); the RPC audit event is appended (#496), the token row itself is not event-sourced",
	"internal_handler.go:ProxyValidateLuksToken:ConsumeToken": "destructive one-time redemption of the luks_tokens row; key storage itself is event-sourced",

	// Async result staging for device-pull operations: a pending row is
	// created at dispatch, expired on signing/enqueue failure (dispatch site)
	// or read-side timeout (get site); the agent's reply fills it via the inbox
	// path. Transient operational state. DispatchOSQuery/QueryDeviceLogs now
	// audit the dispatch (#496); only these staging rows stay non-event-sourced.
	"osquery_handler.go:DispatchOSQuery:CreateResult":             "osquery_results staging row; the dispatch audit event is appended (#496), the staging row itself is not event-sourced",
	"osquery_handler.go:DispatchOSQuery:ExpirePendingResult":      "dispatch-time signing/enqueue-failure bookkeeping on the osquery_results staging row",
	"osquery_handler.go:GetOSQueryResult:ExpirePendingResult":     "read-side timeout bookkeeping on the osquery_results staging row",
	"logs_handler.go:QueryDeviceLogs:CreateQueryResult":           "log_query_results staging row; the dispatch audit event is appended (#496), the staging row itself is not event-sourced",
	"logs_handler.go:QueryDeviceLogs:ExpirePendingQueryResult":    "dispatch-time signing/enqueue-failure bookkeeping on the log_query_results staging row",
	"logs_handler.go:GetDeviceLogResult:ExpirePendingQueryResult": "read-side timeout bookkeeping on the log_query_results staging row",

	// Live terminal-session operational inventory, written ALONGSIDE the
	// TerminalSessionStarted/Stopped/Terminated events the same handlers
	// append (terminal_handler.go) — the audit trail is the event; the row
	// is the liveness inventory the reconciler/listeners work from.
	"terminal_handler.go:StartTerminal:UpsertStart":               "terminal_sessions liveness row; TerminalSessionStarted event appended in the same handler",
	"terminal_handler.go:StopTerminal:MarkStopped":                "terminal_sessions liveness row; TerminalSessionStopped event appended in the same handler",
	"terminal_handler.go:TerminateTerminalSession:MarkTerminated": "terminal_sessions liveness row; TerminalSessionTerminated event appended in the same handler",
}

// scimAllowedDirectWrites — the SCIM v2 provisioning package (internal/scim)
// reads state through h.store.Repos()/.Queries() but performs EVERY mutation
// through AppendEvent/AppendEvents: it is fully event-sourced and has no
// by-design direct write. The set is empty and the scan runs as a tripwire
// (expectWrites=false) — a future direct write through a Queries()/Repos()
// chain (the same accessor its reads use) would fail the guard.
var scimAllowedDirectWrites = map[string]string{}

// controlAllowedDirectWrites — by-design direct writes in the control:inbox
// worker package (internal/control), the gateway→control task handlers.
var controlAllowedDirectWrites = map[string]string{
	// The inbox worker IS a projection writer for device-pushed inventory:
	// the agent streams osquery tables and the worker upserts them into
	// inventory_projection directly. There is no domain event for "device
	// reported its current package/service inventory" — the inventory is
	// derived observational state, not an audited command, so it is written
	// straight to the projection (spec 22). Freshness/interval is the only
	// audited part and rides its own events elsewhere.
	"inbox_worker.go:handleInventoryUpdate:Upsert": "inventory_projection is written directly from device-pushed osquery tables; observational state, not an event-sourced command (spec 22)",
}

// idpAllowedDirectWrites — the OIDC SSO linker (internal/idp) mutates state
// ONLY through an injected appender.AppendEvent interface and holds no store
// handle, so it has no direct writes today. The entry set is empty and the
// scan runs as a tripwire (expectWrites=false): a future direct store write
// through a Queries()/Repos() chain would fail the guard.
var idpAllowedDirectWrites = map[string]string{}

// writeGuardTarget is one handler/worker package the no-direct-write guard
// scans. Dir is relative to this package's directory (internal/api), which is
// the working directory `go test` uses.
type writeGuardTarget struct {
	dir          string
	label        string
	expectWrites bool // require ≥1 observed direct-write site (proves the scan fires here)
	allow        map[string]string
}

// writeGuardTargets are every trust-boundary handler/worker package that
// appends events / mutates state. The no-direct-write invariant (audit F-07 /
// #495: mutations go through AppendEvent + projectors, never a raw projection
// write) must hold across all of them, not just api. api = ControlService RPC
// handlers (has by-design projection-staging writes); control = control:inbox
// task handlers (one by-design inventory-projection upsert); scim = SCIM v2
// provisioning and idp = OIDC SSO linker are both fully event-sourced today, so
// they run as tripwires (expectWrites=false) that fail if a direct write is
// ever introduced.
var writeGuardTargets = []writeGuardTarget{
	{dir: ".", label: "api", expectWrites: true, allow: apiAllowedDirectWrites},
	{dir: "../scim", label: "scim", expectWrites: false, allow: scimAllowedDirectWrites},
	{dir: "../control", label: "control", expectWrites: true, allow: controlAllowedDirectWrites},
	{dir: "../idp", label: "idp", expectWrites: false, allow: idpAllowedDirectWrites},
}

// TestNoDirectStoreWritesFromHandlers is assertion 2 of the #495 guard: no
// handler file bypasses the event→projector path with a direct write.
//
// Discovery mechanics: the write-method sets are derived from the code, not
// hardcoded — generated write queries from the db.Queries method set
// (Insert*/Update*/Delete*/Upsert*), repo write methods from the store.Repos
// interface method sets filtered by write verb. A call site is flagged when
// its callee name is in either set AND its receiver chain demonstrably comes
// from Store.Queries()/Store.Repos() (inline chain, or a local variable bound
// from one — `q := h.store.Queries(); q.InsertX(...)` is caught). Storing a
// *db.Queries in a struct field for later writes would evade the receiver
// check; no production code does that today, and assertion 1 still covers the
// RPC surface.
func TestNoDirectStoreWritesFromHandlers(t *testing.T) {
	writeNames := map[string]bool{}
	for name := range generatedWriteQueryNames() {
		writeNames[name] = true
	}
	for name := range repoWriteMethodNames() {
		writeNames[name] = true
	}
	require.NotEmpty(t, writeNames, "discovered zero write-method names — the scan is broken")

	for _, tgt := range writeGuardTargets {
		assertNoDirectStoreWrites(t, tgt, writeNames)
	}
}

// assertNoDirectStoreWrites scans one target package's non-test .go files for
// direct store-write call sites — a write-method name (from writeNames) whose
// receiver chain demonstrably originates from Store.Queries()/Store.Repos()
// (inline chain or a local binding of one) — and fails on any not present in
// the target's allow-list. Same mechanics as the original api-only guard,
// parameterized over (dir, allow-list) so scim / control / idp are covered too
// (audit F-07). Relative dirs resolve against the api package directory, which
// is the working directory `go test` runs in.
func assertNoDirectStoreWrites(t *testing.T, tgt writeGuardTarget, writeNames map[string]bool) {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(tgt.dir)
	require.NoErrorf(t, err, "[%s] read dir %s", tgt.label, tgt.dir)

	// observed is the set of direct-write sites seen, keyed file:function:callee
	// — function-granular, NOT just file:callee (CR). That distinction matters:
	// a new write of a DIFFERENT method in an already-allow-listed function keys
	// differently (different callee) and is flagged; the same method in a
	// DIFFERENT function keys differently and is flagged; so the only residual is
	// a second call to the SAME method in the SAME allow-listed function. That is
	// left un-distinguished on purpose — a handler legitimately calls one cleanup
	// method from several error branches (e.g. QueryDeviceLogs / DispatchOSQuery
	// each Expire the staging row on both the signing-failure and enqueue-failure
	// paths), so a per-call-count invariant would false-fail by-design code, and
	// the only finer key is the line number, which rots on every edit.
	observed := map[string]bool{}
	var violations []string
	sawFile := false
	for _, e := range entries {
		fname := e.Name()
		if !strings.HasSuffix(fname, ".go") || strings.HasSuffix(fname, "_test.go") {
			continue
		}
		sawFile = true
		f, err := parser.ParseFile(fset, filepath.Join(tgt.dir, fname), nil, 0)
		require.NoErrorf(t, err, "[%s] parse %s", tgt.label, fname)

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			bound := storeBoundIdents(fn)
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !writeNames[sel.Sel.Name] {
					return true
				}
				if !isStoreAccess(sel.X, bound) {
					return true
				}
				key := fname + ":" + fn.Name.Name + ":" + sel.Sel.Name
				observed[key] = true
				if tgt.allow[key] == "" {
					violations = append(violations,
						fmt.Sprintf("%s/%s: %s calls %s — a direct store write outside the event→projector path (key %q)", tgt.label, fname, fn.Name.Name, sel.Sel.Name, key))
				}
				return true
			})
		}
	}
	require.Truef(t, sawFile, "[%s] scanned zero source files in %s — discovery is broken", tgt.label, tgt.dir)
	if tgt.expectWrites {
		require.NotEmptyf(t, observed,
			"[%s] discovered zero direct-write call sites — the scan heuristic is not firing for this package (the allow-listed by-design sites must at least match)", tgt.label)
	}

	var stale []string
	for key := range tgt.allow {
		if !observed[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	sort.Strings(violations)
	require.Emptyf(t, stale, "[%s] allow-list entries no longer observed — remove them:\n  %s", tgt.label, strings.Join(stale, "\n  "))
	require.Emptyf(t, violations,
		"[%s] direct store writes from handler files (#495 / audit F-07 — mutations go through AppendEvent + projectors):\n  %s\n"+
			"Event-source the write, or add a verified by-design entry to the package allow-list with its why.",
		tgt.label, strings.Join(violations, "\n  "))
}

// --- discovery helpers -----------------------------------------------------

// controlServiceRPCNames discovers the full RPC surface from the connect
// handler interface — the same compile-time source service.go implements.
func controlServiceRPCNames(t *testing.T) []string {
	t.Helper()
	ifaceType := reflect.TypeOf((*pmv1connect.ControlServiceHandler)(nil)).Elem()
	require.NotZero(t, ifaceType.NumMethod(), "no ControlService RPCs discovered")
	names := make([]string, 0, ifaceType.NumMethod())
	for i := 0; i < ifaceType.NumMethod(); i++ {
		names = append(names, ifaceType.Method(i).Name)
	}
	return names
}

// parsePackageDecls indexes every non-test function/method body in this
// package by bare name. Methods on different receivers that share a name are
// merged — the call-graph walk traverses all of them (see the guard doc).
func parsePackageDecls(t *testing.T) map[string][]*ast.FuncDecl {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	decls := map[string][]*ast.FuncDecl{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		require.NoErrorf(t, err, "parse %s", name)
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				decls[fn.Name.Name] = append(decls[fn.Name.Name], fn)
			}
		}
	}
	return decls
}

// reachesEventAppend reports whether any function named name — or anything it
// transitively calls inside this package — calls AppendEvent or
// AppendEventWithVersion. visited memoizes explored names (a cyclic revisit
// reports false, which can only under-approximate — a visible failure, never
// a silent pass).
//
// Calls whose receiver is a store access (Repos()/Queries() chain or a local
// binding of one) are NEVER followed into same-named in-package functions:
// a repo method like Luks.CreateToken must not resolve to the CreateToken RPC
// handler, which would let an unaudited mutation borrow another handler's
// append and pass silently.
func reachesEventAppend(name string, decls map[string][]*ast.FuncDecl, visited map[string]bool) bool {
	if visited[name] {
		return false
	}
	visited[name] = true
	for _, fn := range decls[name] {
		found := false
		bound := storeBoundIdents(fn)
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee := calleeName(call.Fun)
			if callee == "AppendEvent" || callee == "AppendEventWithVersion" {
				found = true
				return false
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && isStoreAccess(sel.X, bound) {
				return true // repo/queries method — external, never an in-package edge
			}
			if _, local := decls[callee]; local && reachesEventAppend(callee, decls, visited) {
				found = true
				return false
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

// generatedWriteQueryNames derives the write-query name set from the sqlc
// method set — self-discovering, so a new generated write is covered the
// moment it exists.
func generatedWriteQueryNames() map[string]bool {
	names := map[string]bool{}
	qt := reflect.TypeOf((*db.Queries)(nil))
	for i := 0; i < qt.NumMethod(); i++ {
		name := qt.Method(i).Name
		if hasAnyPrefix(name, []string{"Insert", "Update", "Delete", "Upsert"}) {
			names[name] = true
		}
	}
	return names
}

// repoWriteVerbs are the leading verbs that mark a store.Repos interface
// method as a write. Read verbs (Get/List/Count/Is/Has/Next/Load...) are
// deliberately absent.
var repoWriteVerbs = []string{
	"Insert", "Update", "Upsert", "Delete", "Create", "Mark", "Revoke",
	"Consume", "Expire", "Rotate", "Set", "Save", "Record", "Store", "Renew",
	"Add", "Remove", "Assign", "Unassign", "Enable", "Disable", "Purge",
	"Prune", "Clear", "Reset",
}

// repoWriteMethodNames derives the repo write-method name set from the
// store.Repos struct's interface fields.
func repoWriteMethodNames() map[string]bool {
	names := map[string]bool{}
	rt := reflect.TypeOf(store.Repos{})
	for i := 0; i < rt.NumField(); i++ {
		ft := rt.Field(i).Type
		if ft.Kind() != reflect.Interface {
			continue
		}
		for j := 0; j < ft.NumMethod(); j++ {
			name := ft.Method(j).Name
			if hasAnyPrefix(name, repoWriteVerbs) {
				names[name] = true
			}
		}
	}
	return names
}

// storeBoundIdents collects local identifiers bound (directly or through a
// chain) from a Store.Queries()/Store.Repos() call inside fn, so writes on
// `q := h.store.Queries()` style bindings are still attributed to the store.
func storeBoundIdents(fn *ast.FuncDecl) map[string]bool {
	bound := map[string]bool{}
	ast.Inspect(fn, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		fromStore := false
		for _, rhs := range assign.Rhs {
			if exprMentions(rhs, "Queries") || exprMentions(rhs, "Repos") {
				fromStore = true
			}
		}
		if !fromStore {
			return true
		}
		for _, lhs := range assign.Lhs {
			if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" {
				bound[id.Name] = true
			}
		}
		return true
	})
	return bound
}

// isStoreAccess reports whether a call receiver demonstrably originates from
// the store: the chain mentions Queries/Repos inline, or its root identifier
// was locally bound from one.
func isStoreAccess(recv ast.Expr, bound map[string]bool) bool {
	if exprMentions(recv, "Queries") || exprMentions(recv, "Repos") {
		return true
	}
	if root := rootIdent(recv); root != "" && bound[root] {
		return true
	}
	return false
}

// rootIdent unwraps a selector/call chain to its leftmost identifier
// (h.store.Repos().Luks → "h"; q.InsertX → "q").
func rootIdent(e ast.Expr) string {
	for {
		switch v := e.(type) {
		case *ast.Ident:
			return v.Name
		case *ast.SelectorExpr:
			e = v.X
		case *ast.CallExpr:
			e = v.Fun
		case *ast.IndexExpr:
			e = v.X
		default:
			return ""
		}
	}
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
