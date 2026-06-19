package archtest

import (
	"go/ast"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/gen/go/pm/v1/pmv1connect"
)

// projectionMutationRe matches the SQL of a generated query that writes a
// projection table (any table whose name ends in _projection). The
// event-sourcing contract is that only projectors mutate projection
// tables; handlers append events and read projections.
var projectionMutationRe = regexp.MustCompile(`(?i)(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+"?([a-z_]+_projection)`)

// projectionWriteAllowlist names the specialized engines that legitimately
// write projection tables OUTSIDE internal/projectors. Projection rows in
// this codebase carry both event-sourced columns (written by projectors
// replaying events) and computed/derived columns (written by the engines
// below). The event-sourcing invariant this guard protects is therefore
// "request handlers append events; they never write a projection
// directly" — these engines are not request handlers, they own derived
// state. Each entry is justified; assertNoStale fails the build if one
// stops matching. Keyed by "<module-rel dir> :: <method>".
//
// NOTE for review: if any entry below is considered a smell to refactor
// into an event + projector (rather than a computed read-model), removing
// it here will turn that call site red — that is the intended forcing
// function.
var projectionWriteAllowlist = map[string]string{
	"internal/compliance :: UpdateDeviceComplianceSummary": "Computed read-model: the compliance evaluator computes per-device compliance and writes the summary columns on device_projection. Evaluation results are derived state, not event-sourced.",
	"internal/compliance :: UpsertComplianceEvaluation":    "Computed read-model: per-policy evaluation results written by the compliance evaluator. Derived state, not event-sourced.",
	"internal/dyngroupeval :: InsertDeviceGroupMember":     "Computed read-model: DYNAMIC device-group membership is materialized by evaluating the group query (static membership is event-sourced via projectors).",
	"internal/dyngroupeval :: DeleteDeviceGroupMember":     "Computed read-model: dynamic device-group membership reconciliation removes stale members.",
	"internal/dyngroupeval :: RecountDeviceGroupMembers":   "Computed read-model: recomputes the dynamic device-group member count after materialization.",
	"internal/dyngroupeval :: InsertUserGroupMember":       "Computed read-model: DYNAMIC user-group membership materialized from the group query.",
	"internal/dyngroupeval :: DeleteUserGroupMember":       "Computed read-model: dynamic user-group membership reconciliation removes stale members.",
	"internal/dyngroupeval :: RecountUserGroupMembers":     "Computed read-model: recomputes the dynamic user-group member count after materialization.",
	"internal/auth :: UpdateSystemRolePermissions":         "Bootstrap reconcile: ReconcileSystemRoles syncs the Admin/User system-role permissions to the code-defined sets at startup so new permissions land without a manual toggle. System-role permission sets are code-owned, not user-event-sourced.",
	"internal/store/postgres :: UpdateActionSignature":     "Store adapter: writes the server-computed CA signature back onto action_projection after signing. Tied to the WS1 action-signing rework — revisit when SignedActionEnvelope lands.",
}

// TestProjectionTablesWrittenOnlyByProjectors enforces the CQRS write
// boundary: the generated queries that mutate *_projection tables may
// only be CALLED from internal/projectors (the listeners/appliers that
// own projection state). A handler that writes a projection directly
// bypasses the event store — the bug class this guard makes impossible.
//
// Self-discovering: it derives the mutating-query set from the generated
// SQL (no hardcoded list) and fails if that set or the call-site set is
// empty.
func TestProjectionTablesWrittenOnlyByProjectors(t *testing.T) {
	root := moduleRoot(t)

	// Phase 1: from the generated sqlc package, discover which Queries
	// methods mutate a *_projection table.
	mutators := discoverProjectionMutators(t, root)
	if len(mutators) == 0 {
		t.Fatal("matches-zero guard: discovered no projection-mutating generated queries — the SQL detector or generated path is mis-scoped")
	}

	// A method name shared with a ControlService RPC is a handler
	// delegation (e.g. ControlService.UpdateServerSettings ->
	// SettingsHandler.UpdateServerSettings), NOT a call to the generated
	// query of the same name — the real projection write for those flows
	// is event-sourced inside a projector. Self-discovered from the connect
	// registry so it cannot drift.
	rpcNames := controlServiceRPCNames(t)

	// Phase 2: scan every NON-generated production file for calls to a
	// projection-mutating query; assert each call site is a projector, a
	// handler delegation (name collision), or a justified computed-writer.
	files := walkGoFiles(t, root, func(rel string) bool {
		return !strings.HasPrefix(rel, "internal/store/generated/")
	})
	allow := newAllowlist(projectionWriteAllowlist)
	callSites := 0
	for _, gf := range files {
		dir := pathDir(gf.rel)
		fromProjectors := strings.HasPrefix(gf.rel, "internal/projectors/")
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !mutators[sel.Sel.Name] {
				return true
			}
			if rpcNames[sel.Sel.Name] {
				return true // handler delegation, not a generated-query call
			}
			callSites++
			if fromProjectors {
				return true
			}
			if allow.exempt(dir + " :: " + sel.Sel.Name) {
				return true
			}
			t.Errorf("projection write outside internal/projectors at %s:%d — %s\n  calls projection-mutating query %q from a request/handler path. Handlers must append an event and let a projector write the projection. (If this is a legitimate computed read-model engine, add a justified, guarded entry to projectionWriteAllowlist.)",
				gf.rel, gf.line(call), render(gf.fset, call), sel.Sel.Name)
			return true
		})
	}
	if callSites == 0 {
		t.Fatal("matches-zero guard: no call sites to any projection-mutating query were found — the method-name match is broken, the guard would pass vacuously")
	}
	allow.assertNoStale(t)
}

// discoverProjectionMutators parses the generated sqlc package and returns
// the set of exported Queries methods whose backing SQL const mutates a
// *_projection table.
func discoverProjectionMutators(t *testing.T, root string) map[string]bool {
	t.Helper()
	gen := walkGoFiles(t, root, func(rel string) bool {
		return strings.HasPrefix(rel, "internal/store/generated/")
	})
	if len(gen) == 0 {
		t.Fatal("matches-zero guard: generated sqlc package not found at internal/store/generated/")
	}

	// const name -> mutates a projection table?
	mutatingConst := make(map[string]bool)
	for _, gf := range gen {
		for _, decl := range gf.ast.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok.String() != "const" {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok {
						continue
					}
					if projectionMutationRe.MatchString(unquoteLit(lit)) {
						mutatingConst[name.Name] = true
					}
				}
			}
		}
	}

	// A Queries method is a mutator if its body references a mutating
	// const (the generated method passes the const to q.db.Exec).
	mutators := make(map[string]bool)
	for _, gf := range gen {
		for _, decl := range gf.ast.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && mutatingConst[id.Name] {
					mutators[fn.Name.Name] = true
				}
				return true
			})
		}
	}
	return mutators
}

// controlServiceRPCNames returns the set of method names on the generated
// ControlServiceHandler interface. A generated-query name that collides
// with one of these denotes a handler delegation, not a direct query call.
func controlServiceRPCNames(t *testing.T) map[string]bool {
	t.Helper()
	iface := reflect.TypeOf((*pmv1connect.ControlServiceHandler)(nil)).Elem()
	out := make(map[string]bool, iface.NumMethod())
	for i := 0; i < iface.NumMethod(); i++ {
		out[iface.Method(i).Name] = true
	}
	if len(out) == 0 {
		t.Fatal("matches-zero guard: ControlServiceHandler exposes no methods — registry reflection is broken")
	}
	return out
}

// pathDir returns the slash-separated directory of a module-relative
// file path (its parent), e.g. "internal/projectors/device.go" ->
// "internal/projectors".
func pathDir(rel string) string {
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		return rel[:i]
	}
	return "."
}
