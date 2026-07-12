package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestObjectGetHandlers_AllReadScopeEnforced is the read-side (Get) per-handler
// companion to TestObjectListHandlers_AllScopeEnforced (List) and
// TestObjectMutationHandlers_AllWriteScopeEnforced (mutations). Together the
// three give the object family per-handler coverage on every operation, closing
// the spec 29 S1 blind spot on each axis.
//
// The prior read guard (TestObjectScope_EnforcementMatchesIndexFiltering) is
// type-level PRESENCE: it asserts enforceObjectReadScope("action") appears
// SOMEWHERE, which GetAction satisfies — so a SECOND action reader that skipped
// the gate would pass, exactly the shape that let ListActions leak. Here every
// Get<ObjectType> handler must itself call enforceObjectReadScope with its own
// object-type literal (validated as the ARGUMENT, so a copy-paste type — e.g.
// GetDefinition enforcing "action" — is also rejected).
func TestObjectGetHandlers_AllReadScopeEnforced(t *testing.T) {
	require.NotEmpty(t, objectTypeToIndexScope, "no scopable object types discovered — guard would pass vacuously")

	// Expected Get method name -> the object-type literal it MUST pass to
	// enforceObjectReadScope (argument index 3).
	expectedType := map[string]string{}
	for objType := range objectTypeToIndexScope {
		expectedType["Get"+pascalFromSnake(objType)] = objType
	}
	found := map[string]bool{}
	for method := range expectedType {
		found[method] = false
	}

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	sawFile := false
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		sawFile = true
		f, perr := parser.ParseFile(fset, name, nil, 0)
		require.NoErrorf(t, perr, "parse %s", name)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				continue
			}
			want, tracked := expectedType[fn.Name.Name]
			if !tracked {
				continue
			}
			enforced := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				// Do not descend into nested function literals: a dead/uninvoked
				// closure containing enforceObjectReadScope must not satisfy the check
				// for a handler whose direct body never gates the request.
				if _, ok := n.(*ast.FuncLit); ok {
					return false
				}
				c, ok := n.(*ast.CallExpr)
				if !ok || calleeName(c.Fun) != "enforceObjectReadScope" {
					return true
				}
				// enforceObjectReadScope(ctx, groups, logger, objectType, id, ...):
				// objectType is arg index 3 — the literal must match THIS handler.
				if len(c.Args) > 3 {
					if s, ok := stringLit(c.Args[3]); ok && s == want {
						enforced = true
					}
				}
				return !enforced
			})
			// OR-accumulate across declarations: the ControlService delegator has
			// the same method name but only forwards; the real handler enforces.
			found[fn.Name.Name] = found[fn.Name.Name] || enforced
		}
	}
	require.True(t, sawFile, "scanned zero source files — discovery is broken")

	for method, ok := range found {
		require.Truef(t, ok,
			"%s does not call enforceObjectReadScope(ctx, objScope(h.store), logger, %q, id, ...) — "+
				"an object Get RPC that skips read-scope leaks the out-of-scope object (spec 29 S1, read side / spec 30 AC 2).",
			method, expectedType[method])
	}
}
