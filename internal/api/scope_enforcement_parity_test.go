package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/stretchr/testify/require"
)

// recognizedScopeFns lists the handler-layer functions whose string-literal
// PERMISSION argument marks that permission as scope-ENFORCED. Each entry is a
// distinct enforcement MECHANISM:
//   - single-resource gates           (auth.EnforceDeviceScope* / EnforceUserScope*)
//   - group-id direct-match gates     (auth.EnforceDeviceGroupScope / EnforceUserGroupScope)
//   - list-row filters                (auth.DeviceScopeListFilter / UserScopeListFilter,
//     and auth.DeviceScopeFilterFor for the in-memory
//     terminal-session filter)
//   - dispatch fan-out                (api.enforceDeviceScopeAll)
//
// Only the small set of MECHANISMS is enumerated here; the PERMISSIONS are
// discovered from auth.AllPermissions(). Forgetting to register a NEW mechanism
// fails this test CLOSED — its permissions surface as "unenforced" — never open.
//
// Group CREATION (CreateStaticDeviceGroup / CreateStaticUserGroup) is
// intentionally NOT scopable: a brand-new group has no id and no members, so
// there is nothing to confine a scope against at create time. It is org-tier
// (TargetUnspecified); scope is enforced on the downstream group-management and
// membership operations instead. If a future change re-adds a TargetKind to a
// create permission, this test fails until the create path is genuinely enforced.
var recognizedScopeFns = map[string]bool{
	"EnforceDeviceScope":           true,
	"EnforceDeviceScopeOnBaseTier": true,
	"EnforceUserScope":             true,
	"EnforceUserScopeOrSelf":       true,
	"EnforceDeviceGroupScope":      true,
	"EnforceUserGroupScope":        true,
	"DeviceScopeListFilter":        true,
	"UserScopeListFilter":          true,
	"DeviceScopeFilterFor":         true,
	"enforceDeviceScopeAll":        true,
}

// TestScopablePermissions_AllEnforced is the load-bearing self-discovering guard
// for finding #3/#19: the set of SCOPABLE permissions (those carrying a
// TargetKind in auth.AllPermissions) must EQUAL the set of permissions actually
// scope-enforced somewhere in the api handler layer. "Scopable == enforced" is
// kept honest — there is no advisory-scope allowlist. A permission that cannot
// be enforced must be de-scoped (its TargetKind removed in permissions.go), not
// excused here.
//
// It discovers the enforced set by AST-scanning every non-test .go file in this
// package for permission-string literals passed to a recognized scope-enforcement
// function (see recognizedScopeFns) or handled as a case in the reconciler's
// `switch g.Permission` (the TerminalAdmin* cohort mechanism). Both sides derive
// from their sources — neither is a hardcoded list that can fall stale — so the
// test fails when a new TargetDevice/TargetUser permission is added without
// enforcement, or when a permission is enforced that the registry no longer marks
// scopable (a stale TargetKind).
func TestScopablePermissions_AllEnforced(t *testing.T) {
	scopable := map[string]bool{}
	for _, p := range auth.AllPermissions() {
		if p.TargetKind != auth.TargetUnspecified {
			scopable[p.Key] = true
		}
	}
	require.NotEmpty(t, scopable, "no scopable permissions discovered — the parity check would vacuously pass")

	validPerm := auth.ValidPermissionKeys()

	enforced := map[string]bool{}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err, "read package dir")

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
			switch node := n.(type) {
			case *ast.CallExpr:
				if recognizedScopeFns[calleeName(node.Fun)] {
					for _, arg := range node.Args {
						if s, ok := stringLit(arg); ok && validPerm[s] {
							enforced[s] = true
						}
					}
				}
			case *ast.SwitchStmt:
				// The reconciler's `switch g.Permission { case "TerminalAdmin*": }`
				// enforces those device-target permissions via per-scope cohort
				// computation rather than a request-time gate. Recognize a case
				// value as enforcement ONLY when the switch tag is a permission
				// expression, so unrelated string switches don't count.
				if node.Tag != nil && exprMentions(node.Tag, "Permission") {
					for _, stmt := range node.Body.List {
						cc, ok := stmt.(*ast.CaseClause)
						if !ok {
							continue
						}
						for _, expr := range cc.List {
							if s, ok := stringLit(expr); ok && validPerm[s] {
								enforced[s] = true
							}
						}
					}
				}
			}
			return true
		})
	}
	require.True(t, sawFile, "scanned zero source files — the discovery is broken")

	var missing []string
	for p := range scopable {
		if !enforced[p] {
			missing = append(missing, p)
		}
	}
	sort.Strings(missing)

	var stale []string // enforced but not scopable → a TargetKind that should be restored, or a mis-typed perm
	for p := range enforced {
		if !scopable[p] {
			stale = append(stale, p)
		}
	}
	sort.Strings(stale)

	require.Emptyf(t, missing,
		"scopable permissions with NO handler-level scope enforcement (#3/#19):\n  %s\n"+
			"Each must be enforced (single-resource gate / group-id match / list filter / dispatch fan-out / reconciler cohort) "+
			"OR de-scoped (remove its TargetKind in auth/permissions.go).",
		strings.Join(missing, "\n  "))
	require.Emptyf(t, stale,
		"permissions scope-enforced in handlers but NOT marked scopable in auth/permissions.go (stale TargetKind / mis-typed perm):\n  %s",
		strings.Join(stale, "\n  "))
}

// calleeName returns the called function's identifier — the selector's final
// name for a qualified call (auth.EnforceDeviceScope → "EnforceDeviceScope") or
// the bare identifier for an unqualified call.
func calleeName(fn ast.Expr) string {
	switch f := fn.(type) {
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.Ident:
		return f.Name
	}
	return ""
}

// stringLit unquotes a string-literal expression.
func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// exprMentions reports whether e references an identifier named name (as a bare
// ident or the selector field, e.g. `g.Permission` mentions "Permission").
func exprMentions(e ast.Expr, name string) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch id := n.(type) {
		case *ast.Ident:
			if id.Name == name {
				found = true
			}
		case *ast.SelectorExpr:
			if id.Sel.Name == name {
				found = true
			}
		}
		return !found
	})
	return found
}
