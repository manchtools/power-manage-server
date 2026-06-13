package api_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestEveryAdminRemovingHandlerAcquiresLastAdminLock is a self-discovering
// completeness guard for the atomic last-admin invariant (#369 / #5). It scans
// every non-test function in this package, finds those that APPEND an
// admin-removing event — one whose projection can drop a user's Admin grant —
// and asserts each routes the mutation through the advisory lock
// (guardedAdminMutation / guardedAdminMutationGuard).
//
// This is the anti-asymmetry defense: a NEW handler that emits such an event
// without taking the lock fails here, so the guard cannot be silently bypassed
// as the request surface grows. It discovers emitters from the AST rather than a
// hardcoded handler list (which would fail open), and pins a non-empty set so it
// can never pass vacuously.
func TestEveryAdminRemovingHandlerAcquiresLastAdminLock(t *testing.T) {
	// Events whose projection can REMOVE a user's Admin grant (directly or via a
	// group). Enabling/assigning events are excluded — they cannot orphan admins.
	adminRemoving := map[string]bool{
		"UserDeleted":            true,
		"UserDisabled":           true,
		"UserRoleRevoked":        true,
		"UserGroupRoleRevoked":   true,
		"UserGroupMemberRemoved": true,
		"UserGroupDeleted":       true,
	}
	guardNames := map[string]bool{
		"guardedAdminMutation":      true,
		"guardedAdminMutationGuard": true,
	}

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	var emitters []string // "FuncName emits EventType"
	missing := []string{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ev, emits := funcEmitsAdminRemovingEvent(fn, adminRemoving)
			if !emits {
				continue
			}
			emitters = append(emitters, fn.Name.Name+" emits "+ev)
			if !funcReferencesAny(fn, guardNames) {
				missing = append(missing, name+": "+fn.Name.Name+" appends "+ev+" without the last-admin advisory lock")
			}
		}
	}

	if len(emitters) == 0 {
		t.Fatal("discovery matched zero admin-removing emitters — the scan is broken (it must never pass vacuously)")
	}
	if len(missing) > 0 {
		t.Fatalf("admin-removing handlers that do NOT acquire the last-admin lock (#369/#5):\n  %s\n(discovered emitters: %v)",
			strings.Join(missing, "\n  "), emitters)
	}
}

// funcEmitsAdminRemovingEvent reports whether fn contains a store.Event literal
// whose EventType field references eventtypes.<an admin-removing event>. The
// EventType composite-literal field distinguishes an APPEND from a read
// (listeners compare ev.EventType, never build a store.Event).
func funcEmitsAdminRemovingEvent(fn *ast.FuncDecl, adminRemoving map[string]bool) (string, bool) {
	found := ""
	ast.Inspect(fn, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "EventType" {
			return true
		}
		ast.Inspect(kv.Value, func(m ast.Node) bool {
			sel, ok := m.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "eventtypes" && adminRemoving[sel.Sel.Name] {
				found = sel.Sel.Name
			}
			return true
		})
		return true
	})
	return found, found != ""
}

// funcReferencesAny reports whether fn's body references any identifier in names.
func funcReferencesAny(fn *ast.FuncDecl, names map[string]bool) bool {
	ref := false
	ast.Inspect(fn, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && names[id.Name] {
			ref = true
			return false
		}
		return true
	})
	return ref
}
