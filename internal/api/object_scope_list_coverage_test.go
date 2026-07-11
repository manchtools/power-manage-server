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

// TestObjectListHandlers_AllScopeEnforced is the self-discovering guard that
// closes spec 29 S1 for good: EVERY object-catalog List RPC must resolve a
// scope-restricted caller's results through scopedObjectIDs (the scope-enforcing
// search-index path). The scopable object types are DISCOVERED from
// objectTypeToIndexScope — the same registry object_scope_parity_test.go uses —
// and each List RPC name is derived from the index scope. A new scopable object
// type, or a List handler that skips scopedObjectIDs, fails the build.
//
// This exists because the prior guards were type-level PRESENCE checks
// (enforceObjectReadScope("action") appears in GetAction) and never verified that
// EVERY read handler enforces — which is exactly how ListActions leaked. Here the
// unit is the handler, discovered from the registry, so no object List can
// silently skip scope now or in the future.
func TestObjectListHandlers_AllScopeEnforced(t *testing.T) {
	require.NotEmpty(t, objectTypeToIndexScope, "no scopable object types discovered — guard would pass vacuously")

	// Expected List method name -> the index scope it MUST pass to scopedObjectIDs,
	// e.g. "ListActions" -> "actions". Validating the scope ARGUMENT (not just that
	// the call exists) rejects a copy-paste bug like ListActionSets querying
	// "actions".
	expectedScope := map[string]string{}
	for _, scope := range objectTypeToIndexScope {
		expectedScope["List"+pascalFromSnake(scope)] = scope
	}
	found := map[string]bool{}
	for method := range expectedScope {
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
			if _, tracked := found[fn.Name.Name]; !tracked {
				continue
			}
			want := expectedScope[fn.Name.Name]
			enforced := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok || calleeName(c.Fun) != "scopedObjectIDs" {
					return true
				}
				// scopedObjectIDs(ctx, idx, logger, scope, offset, pageSize, ...):
				// the scope arg (index 3) must be the literal for THIS handler, so a
				// handler that copies the wrong scope string fails the guard.
				if len(c.Args) > 3 {
					if s, ok := stringLit(c.Args[3]); ok && s == want {
						enforced = true
					}
				}
				return !enforced
			})
			// OR-accumulate: the same method name exists on both the real
			// handler (which calls scopedObjectIDs) and the ControlService
			// delegator (which just forwards). The invariant is satisfied if
			// ANY declaration enforces — don't let the delegator overwrite it.
			found[fn.Name.Name] = found[fn.Name.Name] || enforced
		}
	}
	require.True(t, sawFile, "scanned zero source files — discovery is broken")

	for method, ok := range found {
		require.Truef(t, ok,
			"%s does not route restricted callers through scopedObjectIDs(ctx, idx, logger, %q, ...) — "+
				"an object List RPC that skips scope enforcement (or passes the wrong scope) leaks the "+
				"out-of-scope catalog (spec 29 S1).", method, expectedScope[method])
	}
}

// pascalFromSnake turns a snake_case index scope ("action_sets") into the
// PascalCase suffix of its List RPC ("ActionSets").
func pascalFromSnake(scope string) string {
	parts := strings.Split(scope, "_")
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "")
}
