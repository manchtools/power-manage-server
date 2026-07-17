package archtest

import (
	"go/ast"
	"go/token"
	"strings"
	"testing"
)

// TestNoContextBackgroundInRequestPaths enforces the NIS2 / spec-10 /
// CLAUDE rule: request-path code MUST propagate the caller's context and
// MUST NOT root a fresh context.Background()/context.TODO(). A fresh root
// silently drops the request deadline, client cancellation, and the
// per-handler statement_timeout (ADR 0018 / WS13) — turning a cancelled
// RPC into an unbounded operation against Postgres or a peer. The
// companion clock guard (TestNoUnabstractedTimeNow) pins the same kind of
// invariant for the wall clock; this one pins it for the request context.
//
// Two CATEGORY exemptions, deliberately not per-site blessings:
//
//   - package main under cmd/ — process bootstrap and graceful shutdown
//     legitimately ROOT the lifecycle context; there is no caller context
//     to inherit. cmd/ files are still walked (only the error is skipped)
//     so their main.go roots keep the matches-zero liveness probe alive.
//
//   - detached-by-design work that MUST outlive the RPC: post-commit
//     fan-out, post-commit event-bus listeners, and self-stopping
//     background tickers. These are not request paths. Each is allowlisted
//     by its enclosing function with a justification and is bounded by its
//     own timeout; assertNoStale fails the build if one of these functions
//     stops rooting a context, so the escape hatch cannot rot open.
//
// The allowlist is keyed by enclosing function (not file, not line):
// file-level would fail open — every context.Background() renders
// identically, so a file key would silently bless a future root anywhere
// in that file. Function-level still blesses a second root in the same
// detached function (acceptable: that function is already detached work),
// while a root in any NEW handler function is flagged.
func TestNoContextBackgroundInRequestPaths(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(rel string) bool {
		if strings.HasPrefix(rel, "internal/store/generated/") {
			return false
		}
		if strings.HasPrefix(rel, "internal/testutil/") {
			return false
		}
		return true
	})
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero production Go files — detector is mis-scoped")
	}

	allow := newAllowlist(map[string]string{
		"internal/api/settings_handler.go :: runSettingsPropagation":                 "detached post-update settings fan-out; must outlive the RPC, bounded 5m, panic-recovered (WS16 #9)",
		"internal/api/terminal_revocation_listener.go :: TerminalRevocationListener": "post-commit event-bus listener goroutine; not a request path, bounded by terminalRevocationCloseTimeout, panic-recovered",
		"internal/gateway/registry/registry.go :: heartbeat":                         "detached TTL-refresh goroutine + shutdown-cleanup closure, each with its own stop signal and a 5s WithTimeout bound; not a request path (shared by RegisterGateway/RegisterGatewayAlive/RegisterGatewayInternal)",
	})

	// Liveness probe: every context.Background()/context.TODO() seen
	// anywhere (cmd/ included). Keying matches-zero off this — rather than
	// off non-cmd violations — keeps the guard non-vacuous even once every
	// request path is clean, because cmd/ bootstrap always roots a context.
	sawCtxRoot := 0
	for _, gf := range files {
		underCmd := strings.HasPrefix(gf.rel, "cmd/")
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := contextRootCall(call)
			if !ok {
				return true
			}
			sawCtxRoot++
			if underCmd {
				return true // category exemption: process lifecycle root
			}
			fn := enclosingFuncName(gf.ast, call.Pos())
			if allow.exempt(gf.rel + " :: " + fn) {
				return true
			}
			t.Errorf("context.%s() rooted in a request path at %s:%d (enclosing func %q) — propagate the caller's context.Context instead; a fresh root drops the request deadline, cancellation, and statement_timeout. If this is detached-by-design work that must outlive the RPC, allowlist it by enclosing function with a justification.",
				name, gf.rel, gf.line(call), fn)
			return true
		})
	}
	if sawCtxRoot == 0 {
		t.Fatal("matches-zero guard: found no context.Background()/context.TODO() anywhere (not even in cmd/ bootstrap) — the detector is dead, the guard would pass vacuously")
	}
	allow.assertNoStale(t)
}

// contextRootCall reports whether call is exactly context.Background() or
// context.TODO() (zero args), returning the bare method name.
func contextRootCall(call *ast.CallExpr) (string, bool) {
	if len(call.Args) != 0 {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	if sel.Sel.Name != "Background" && sel.Sel.Name != "TODO" {
		return "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Name != "context" {
		return "", false
	}
	return sel.Sel.Name, true
}

// enclosingFuncName returns the name of the top-level FuncDecl whose source
// range contains pos (covering calls nested inside closures), or
// "<file-scope>" when pos sits outside any function.
func enclosingFuncName(file *ast.File, pos token.Pos) string {
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if pos >= fd.Pos() && pos <= fd.End() {
			return fd.Name.Name
		}
	}
	return "<file-scope>"
}
