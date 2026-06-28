package archtest

import (
	"go/ast"
	"go/token"
	"strings"
	"testing"
)

// TestNotFoundChecksUseStoreRecognizer enforces the dead-branch error-sentinel
// rule (global CLAUDE.md; internal/store/notfound.go contract): OUTSIDE the
// store package, a missing row is recognized ONLY via store.IsNotFound(err) —
// never errors.Is(err, store.ErrNotFound), errors.Is(err, pgx.ErrNoRows),
// errors.Is(err, sql.ErrNoRows), nor == against those sentinels.
//
// Why this is load-bearing: generated/driver queries return the RAW backend
// sentinel (pgx.ErrNoRows). errors.Is(err, store.ErrNotFound) therefore
// silently never matches, the "not found -> handle gracefully" branch goes
// dead, and the caller returns Internal (or worse) on a missing row. This
// exact bug shipped once — the compliance evaluator used
// errors.Is(err, store.ErrNotFound) while the query returned pgx.ErrNoRows, so
// any device with a fresh/first-failing rule silently errored out of
// evaluation (WS17b #6). store.IsNotFound recognizes every backend sentinel;
// it is the single recognizer.
//
// The store package itself (internal/store/...) OWNS the raw driver sentinels
// and defines the recognizer, so it is out of scope — that is the one place
// pgx.ErrNoRows legitimately appears.
func TestNotFoundChecksUseStoreRecognizer(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(rel string) bool {
		// The store package and its backends own the raw driver sentinels and
		// define store.IsNotFound; the recognizer rule binds everyone else.
		return !strings.HasPrefix(rel, "internal/store/")
	})
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero production Go files — detector is mis-scoped")
	}

	// No exceptions today — the invariant holds cleanly. The allowlist exists
	// (guarded by assertNoStale) so a future genuinely-justified site can be
	// recorded with a reason rather than silently weakening the guard.
	allow := newAllowlist(map[string]string{})

	// Liveness probe: count store.IsNotFound recognizer calls. If this hits
	// zero, either not-found recognition vanished or the scan broke — the guard
	// would pass vacuously, so fail instead.
	sawRecognizer := 0
	for _, gf := range files {
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				if isRecognizerCall(x) {
					sawRecognizer++
					return true
				}
				if isErrorsIsCall(x) {
					for _, arg := range x.Args {
						if name := forbiddenNotFoundSentinel(arg); name != "" {
							flagRawSentinel(t, allow, gf, x, name)
						}
					}
				}
			case *ast.BinaryExpr:
				if x.Op == token.EQL || x.Op == token.NEQ {
					if name := forbiddenNotFoundSentinel(x.X); name != "" {
						flagRawSentinel(t, allow, gf, x, name)
					} else if name := forbiddenNotFoundSentinel(x.Y); name != "" {
						flagRawSentinel(t, allow, gf, x, name)
					}
				}
			}
			return true
		})
	}
	if sawRecognizer == 0 {
		t.Fatal("matches-zero guard: found no store.IsNotFound call outside the store package — not-found recognition vanished or the detector is dead; the guard would pass vacuously")
	}
	allow.assertNoStale(t)
}

// flagRawSentinel records a violation unless the rendered site is allowlisted.
func flagRawSentinel(t *testing.T, allow *allowlist, gf *goFile, n ast.Node, sentinel string) {
	rendered := render(gf.fset, n)
	if allow.exempt(gf.rel + " :: " + rendered) {
		return
	}
	t.Errorf("%s at %s:%d tests the raw not-found sentinel %s directly — outside the store package, recognize a missing row via store.IsNotFound(err). The raw sentinel silently never matches a generated/driver error (pgx.ErrNoRows), so the not-found branch goes dead (see internal/store/notfound.go; the WS17b #6 compliance-evaluator bug).",
		rendered, gf.rel, gf.line(n), sentinel)
}

// forbiddenNotFoundSentinel returns the qualified name when e is one of the raw
// not-found sentinels that callers outside the store package must not test
// directly: pgx.ErrNoRows, sql.ErrNoRows, store.ErrNotFound.
func forbiddenNotFoundSentinel(e ast.Expr) string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	switch {
	case (pkg.Name == "pgx" || pkg.Name == "sql") && sel.Sel.Name == "ErrNoRows":
		return pkg.Name + "." + sel.Sel.Name
	case pkg.Name == "store" && sel.Sel.Name == "ErrNotFound":
		return "store.ErrNotFound"
	}
	return ""
}

// isErrorsIsCall reports whether call is errors.Is(...).
func isErrorsIsCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Is" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "errors"
}

// isRecognizerCall reports whether call invokes the .IsNotFound recognizer
// (store.IsNotFound and any aliased qualifier). Liveness anchor only.
func isRecognizerCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "IsNotFound"
}
