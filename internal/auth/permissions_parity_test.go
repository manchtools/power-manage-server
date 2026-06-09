package auth_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
)

// rpcMethodNames returns the set of method names declared on the
// generated ControlServiceHandler interface. These are the names
// that match permission keys (stripped of :self / :assigned suffix)
// and that PublicProcedures entries terminate in.
func rpcMethodNames(t *testing.T) map[string]bool {
	t.Helper()
	iface := reflect.TypeOf((*pmv1connect.ControlServiceHandler)(nil)).Elem()
	out := make(map[string]bool, iface.NumMethod())
	for i := 0; i < iface.NumMethod(); i++ {
		out[iface.Method(i).Name] = true
	}
	return out
}

// stripScope drops the optional :self / :assigned suffix from a
// permission key. The base name is the RPC method name the
// permission gates.
func stripScope(key string) string {
	if i := strings.IndexByte(key, ':'); i >= 0 {
		return key[:i]
	}
	return key
}

// procedureName extracts the trailing RPC name from a fully-qualified
// procedure string like "/pm.v1.ControlService/Login".
func procedureName(procedure string) string {
	if i := strings.LastIndexByte(procedure, '/'); i >= 0 && i < len(procedure)-1 {
		return procedure[i+1:]
	}
	return procedure
}

// nonRPCBackedPermissions are intentionally not gated by an RPC of
// the same name. Two sub-categories live here:
//
//   - **Reconciler-only**: gate background server-side work
//     (TerminalAdmin* — #70 reconciler in system_actions.go
//     materializes pm-sudo-* membership). The reconciler reads the
//     projection; no handler check fires.
//   - **Gate-authority**: consulted as a precondition by ANOTHER
//     permission's handler, not by an RPC of the same name
//     (AssignRoleScope — #7 gates the scope_kind/scope_id args on
//     AssignRoleToUser / AssignRoleToUserGroup).
//
// Adding an entry here documents the intent so the parity
// invariant below stays a meaningful drift-catcher for the
// "I added a permission but forgot to add its RPC" mistake.
var nonRPCBackedPermissions = map[string]bool{
	"TerminalAdminLimited": true, // #70 — reconciler-only
	"TerminalAdminFull":    true, // #70 — reconciler-only
	"AssignRoleScope":      true, // #7 — gate-authority for scoped grants
}

// TestEveryPermissionMatchesAnRPC asserts that every PermissionInfo
// in AllPermissions() has a base key (sans :self/:assigned scope
// suffix) that is the name of an actual RPC on
// pmv1connect.ControlServiceHandler. A drift here means a permission
// can be assigned to a role but no handler will ever consult it —
// invisible-deadweight UX in the role builder.
//
// Three exemption paths:
//   - nonRPCBackedPermissions (reconciler-only or gate-authority).
//   - ProcedureAlternatives: a split / renamed permission that
//     gates a procedure whose name differs (CreateStaticDeviceGroup
//     gates /CreateDeviceGroup via the alternatives map).
func TestEveryPermissionMatchesAnRPC(t *testing.T) {
	rpcs := rpcMethodNames(t)
	for _, p := range auth.AllPermissions() {
		base := stripScope(p.Key)
		if nonRPCBackedPermissions[base] {
			continue
		}
		if auth.PermissionIsAlternative(base) {
			continue
		}
		if !rpcs[base] {
			t.Errorf("permission %q references non-existent RPC %q (no method on ControlServiceHandler, no alternatives entry, not in nonRPCBackedPermissions)",
				p.Key, base)
		}
	}
}

// TestNonRPCBackedPermissionsAreRegistered guards the inverse
// invariant: every entry in nonRPCBackedPermissions must actually
// be a registered permission in AllPermissions(). Otherwise a
// future rename of TerminalAdminLimited would leave a stale
// exemption that quietly papers over a real parity violation.
func TestNonRPCBackedPermissionsAreRegistered(t *testing.T) {
	registered := make(map[string]bool, len(auth.AllPermissions()))
	for _, p := range auth.AllPermissions() {
		registered[stripScope(p.Key)] = true
	}
	for key := range nonRPCBackedPermissions {
		if !registered[key] {
			t.Errorf("nonRPCBackedPermissions includes %q but it's not in AllPermissions() — exemption is stale",
				key)
		}
	}
}

// TestEveryPublicProcedureIsAnRPC asserts that every entry in
// PublicProcedures terminates in a method name that exists on
// pmv1connect.ControlServiceHandler. A typo here would silently
// leave the procedure auth-required (mostly safe — but a Login
// typo would break login because the rate-limiter and the
// auth-bypass check both key on the literal procedure string).
func TestEveryPublicProcedureIsAnRPC(t *testing.T) {
	rpcs := rpcMethodNames(t)
	for procedure := range auth.PublicProcedures {
		// Procedure must be the canonical Connect-RPC shape.
		const prefix = "/pm.v1.ControlService/"
		if !strings.HasPrefix(procedure, prefix) {
			t.Errorf("PublicProcedures entry %q does not start with %q", procedure, prefix)
			continue
		}
		method := procedureName(procedure)
		if !rpcs[method] {
			t.Errorf("PublicProcedures entry %q points at non-existent RPC %q (no method on ControlServiceHandler)",
				procedure, method)
		}
	}
}

// TestEveryRPCIsCoveredByPermissionOrPublic is the inverse of the
// two checks above: for every RPC on the generated handler, the RPC
// must be covered by ONE of:
//   - PublicProcedures (auth bypass)
//   - A permission whose base key matches the RPC name
//   - An entry in ProcedureAlternatives (one or more permissions
//     gate the procedure via the alternatives map)
//
// Catches new RPCs added without permission wiring.
func TestEveryRPCIsCoveredByPermissionOrPublic(t *testing.T) {
	rpcs := rpcMethodNames(t)

	// Build the inverse map: RPC name → covered (bool).
	covered := make(map[string]bool, len(rpcs))
	for name := range rpcs {
		covered[name] = false
	}

	for procedure := range auth.PublicProcedures {
		covered[procedureName(procedure)] = true
	}
	for procedure := range auth.ProcedureAlternativesSnapshot() {
		covered[procedureName(procedure)] = true
	}
	for _, p := range auth.AllPermissions() {
		covered[stripScope(p.Key)] = true
	}

	var uncovered []string
	for name, ok := range covered {
		if !ok {
			uncovered = append(uncovered, name)
		}
	}
	if len(uncovered) > 0 {
		t.Errorf("RPCs with no permission, not in PublicProcedures, and not in ProcedureAlternatives (drift hazard — every new RPC needs one of the three): %v", uncovered)
	}
}

// TestProcedureAlternatives_Exact pins the exact set of procedures
// gated via the alternatives map. Adding to or removing from this
// map is intentional but consequential (it changes the interceptor
// gating semantics), so the assertion lists the expected set
// verbatim — a future PR that wants to widen the alternatives must
// update this test consciously.
func TestProcedureAlternatives_Exact(t *testing.T) {
	expected := map[string][]string{
		"/pm.v1.ControlService/CreateDeviceGroup": {
			"CreateStaticDeviceGroup",
			"CreateDynamicDeviceGroup",
		},
		"/pm.v1.ControlService/CreateUserGroup": {
			"CreateStaticUserGroup",
			"CreateDynamicUserGroup",
		},
		"/pm.v1.ControlService/UpdateDeviceGroupQuery": {
			"UpdateDynamicDeviceGroupQuery",
		},
		"/pm.v1.ControlService/UpdateUserGroupQuery": {
			"UpdateDynamicUserGroupQuery",
		},
	}
	live := auth.ProcedureAlternativesSnapshot()
	if len(expected) != len(live) {
		t.Fatalf("ProcedureAlternatives length drifted: have %d, expected %d", len(live), len(expected))
	}
	for proc, wantAlts := range expected {
		gotAlts, ok := live[proc]
		if !ok {
			t.Errorf("ProcedureAlternatives missing entry for %q", proc)
			continue
		}
		if len(gotAlts) != len(wantAlts) {
			t.Errorf("ProcedureAlternatives[%q] length mismatch: got %d, want %d", proc, len(gotAlts), len(wantAlts))
			continue
		}
		for i, w := range wantAlts {
			if gotAlts[i] != w {
				t.Errorf("ProcedureAlternatives[%q][%d] = %q, want %q", proc, i, gotAlts[i], w)
			}
		}
	}
}

// TestProcedureAlternativesSnapshot_IsIndependentCopy guards the
// hardening done in #333 review: a snapshot caller must not be able
// to mutate the live authorization policy by writing into the
// returned map. The interceptor reads `procedureAlternatives`
// directly, so the snapshot must be a deep copy. Without this guard
// the public accessor would be a thin alias on the policy and the
// "immutability" benefit of unexporting the var would be lost.
func TestProcedureAlternativesSnapshot_IsIndependentCopy(t *testing.T) {
	first := auth.ProcedureAlternativesSnapshot()
	// Pick any existing key for the smoke check; if the map is
	// empty the matches-zero guard below catches it.
	if len(first) == 0 {
		t.Fatal("ProcedureAlternativesSnapshot returned empty — matches-zero guard")
	}
	var pickedProc string
	for k := range first {
		pickedProc = k
		break
	}
	// Mutate the snapshot.
	first[pickedProc] = append(first[pickedProc], "AttackerInjectedPermission")
	first["/pm.v1.ControlService/Forged"] = []string{"AttackerInjectedPermission"}

	// Re-snapshot and compare.
	second := auth.ProcedureAlternativesSnapshot()
	if len(second) != len(first)-1 {
		t.Fatalf("snapshot accessor shared state with live policy: second size %d unexpectedly differs from first-1 size %d", len(second), len(first)-1)
	}
	if _, leaked := second["/pm.v1.ControlService/Forged"]; leaked {
		t.Errorf("forged procedure leaked into the live policy via snapshot mutation")
	}
	for _, alt := range second[pickedProc] {
		if alt == "AttackerInjectedPermission" {
			t.Errorf("attacker-injected permission leaked into live policy on procedure %q via snapshot mutation", pickedProc)
		}
	}
}

// TestProcedureAlternatives_EveryAlternativeIsARegisteredPermission
// pins that every permission listed as an alternative actually
// exists in AllPermissions(). A typo here would silently leave the
// procedure ungated for users who hold the typo'd permission name
// (i.e. zero users) — effectively closed but invisible.
//
// Uses EXACT key matching (not stripScope) per #333 review: a
// scoped variant like `Foo:self` must not satisfy a lookup for the
// unscoped base `Foo`. The alternatives must reference the literal
// permission key the actor would hold in their JWT.
func TestProcedureAlternatives_EveryAlternativeIsARegisteredPermission(t *testing.T) {
	registered := make(map[string]bool, len(auth.AllPermissions()))
	for _, p := range auth.AllPermissions() {
		registered[p.Key] = true
	}
	for proc, alts := range auth.ProcedureAlternativesSnapshot() {
		for _, alt := range alts {
			if !registered[alt] {
				t.Errorf("ProcedureAlternatives[%q] lists permission %q which is not in AllPermissions()", proc, alt)
			}
		}
	}
}

// TestProcedureAlternatives_EveryKeyIsAnRPC pins that the procedure
// path on the LHS of the alternatives map actually corresponds to
// an RPC on the generated handler. A typo in the trailing method
// name OR the service prefix would silently leave the alternatives
// override inactive for the real procedure (which would fall through
// to the default Authorize path). Per #333 review, both pieces are
// asserted.
func TestProcedureAlternatives_EveryKeyIsAnRPC(t *testing.T) {
	rpcs := rpcMethodNames(t)
	const wantPrefix = "/pm.v1.ControlService/"
	for proc := range auth.ProcedureAlternativesSnapshot() {
		if !strings.HasPrefix(proc, wantPrefix) {
			t.Errorf("ProcedureAlternatives key %q does not start with the canonical Connect prefix %q", proc, wantPrefix)
			continue
		}
		method := procedureName(proc)
		if !rpcs[method] {
			t.Errorf("ProcedureAlternatives key %q references non-existent RPC %q", proc, method)
		}
	}
}
