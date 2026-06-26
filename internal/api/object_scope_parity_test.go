package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// objectTypeToIndexScope bridges the singular assignment/object type used by the
// handler scope enforcement ("action_set") to the plural search index scope used
// by the FT index ("action_sets"). It is the canonical set of scopable object
// types (#7 spec 14). A new object type forces an entry here, which forces the
// index-field + read/write-enforcement assertions below.
var objectTypeToIndexScope = map[string]string{
	"action":            "actions",
	"action_set":        "action_sets",
	"definition":        "definitions",
	"compliance_policy": "compliance_policies",
}

// TestObjectScope_EnforcementMatchesIndexFiltering is the self-discovering guard
// for #7 spec 14: the object types enforced at the handler boundary
// (enforceObjectReadScope / enforceObjectWriteScope) MUST be exactly the search
// scopes whose index declares the scope_group_ids TAG (scopesWithScopeGroupField,
// itself derived from the schemas). If they diverge, scope leaks:
//
//   - an index field with no handler enforcement → Get/mutation leaks the object;
//   - handler enforcement with no index field → Search leaks the whole catalog.
//
// The enforced set is DISCOVERED by AST-scanning this package for the two
// enforcement calls and collecting their object-type literal — not a hardcoded
// list — so forgetting to wire a new object type fails the build.
func TestObjectScope_EnforcementMatchesIndexFiltering(t *testing.T) {
	readEnforced := map[string]bool{}
	writeEnforced := map[string]bool{}

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
		f, err := parser.ParseFile(fset, name, nil, 0)
		require.NoErrorf(t, err, "parse %s", name)

		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fn := calleeName(call.Fun)
			var sink map[string]bool
			switch fn {
			case "enforceObjectReadScope":
				sink = readEnforced
			case "enforceObjectWriteScope":
				sink = writeEnforced
			default:
				return true
			}
			// The object type is the first string-literal argument.
			for _, arg := range call.Args {
				if s, ok := stringLit(arg); ok {
					sink[s] = true
					break
				}
			}
			return true
		})
	}
	require.True(t, sawFile, "scanned zero source files — discovery is broken")
	require.NotEmpty(t, readEnforced, "no enforceObjectReadScope calls discovered — the guard would vacuously pass")
	require.NotEmpty(t, writeEnforced, "no enforceObjectWriteScope calls discovered — the guard would vacuously pass")

	// Every discovered object type must be a known scopable type with an index
	// scope, and must carry the scope_group_ids field on that index.
	for _, sink := range []map[string]bool{readEnforced, writeEnforced} {
		for objType := range sink {
			scope, ok := objectTypeToIndexScope[objType]
			require.Truef(t, ok, "object type %q is scope-enforced but has no objectTypeToIndexScope mapping", objType)
			require.Truef(t, scopesWithScopeGroupField[scope],
				"object type %q (index scope %q) is handler-enforced but its index does not declare scope_group_ids — Search would leak the whole catalog", objType, scope)
		}
	}

	// Every object type must have BOTH read and write enforcement, and every
	// scope_group_ids index scope must correspond to an enforced object type
	// (no index field without handler enforcement → Get leak).
	var missingRead, missingWrite []string
	scopeToType := map[string]string{}
	for objType, scope := range objectTypeToIndexScope {
		scopeToType[scope] = objType
		if !readEnforced[objType] {
			missingRead = append(missingRead, objType)
		}
		if !writeEnforced[objType] {
			missingWrite = append(missingWrite, objType)
		}
	}
	sort.Strings(missingRead)
	sort.Strings(missingWrite)
	require.Emptyf(t, missingRead, "object types with no Get/read scope enforcement: %s", strings.Join(missingRead, ", "))
	require.Emptyf(t, missingWrite, "object types with no mutation/write scope enforcement: %s", strings.Join(missingWrite, ", "))

	for scope := range scopesWithScopeGroupField {
		if searchScopedNonObjectScopes[scope] {
			continue
		}
		_, ok := scopeToType[scope]
		require.Truef(t, ok, "index scope %q declares scope_group_ids but no object type / handler enforcement maps to it — Get would leak", scope)
	}
}

// searchScopedNonObjectScopes are the non-object search scopes that also carry the
// scope_group_ids TAG (#7 spec 14). They are NOT confined by enforceObjectReadScope
// / enforceObjectWriteScope; their Search is filtered in scopeGroupClause via the
// dedicated device-/user-group list filters (DeviceScopeListFilter("ListDevices") /
// UserScopeListFilter("ListUsers")), and their per-object Get is already confined by
// the existing device/user handler scope (covered by scope_enforcement_*_test.go and
// TestScopablePermissions_AllEnforced). So the object-parity reverse check skips them.
var searchScopedNonObjectScopes = map[string]bool{
	"devices": true,
	"users":   true,
}
