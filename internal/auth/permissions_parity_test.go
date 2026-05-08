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

// TestEveryPermissionMatchesAnRPC asserts that every PermissionInfo
// in AllPermissions() has a base key (sans :self/:assigned scope
// suffix) that is the name of an actual RPC on
// pmv1connect.ControlServiceHandler. A drift here means a permission
// can be assigned to a role but no handler will ever consult it —
// invisible-deadweight UX in the role builder.
func TestEveryPermissionMatchesAnRPC(t *testing.T) {
	rpcs := rpcMethodNames(t)
	for _, p := range auth.AllPermissions() {
		base := stripScope(p.Key)
		if !rpcs[base] {
			t.Errorf("permission %q references non-existent RPC %q (no method on ControlServiceHandler)",
				p.Key, base)
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
// two checks above: for every RPC on the generated handler, EITHER
// it's listed in PublicProcedures (auth bypass) OR there's at least
// one permission whose base key matches it. Catches new RPCs added
// without permission wiring.
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
		t.Errorf("RPCs with no permission and not in PublicProcedures (drift hazard — every new RPC needs one or the other): %v", uncovered)
	}
}
