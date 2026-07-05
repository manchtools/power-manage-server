package archtest

import (
	"go/ast"
	"go/token"
	"strings"
	"testing"
)

// sqlMethodNames are the database driver methods (database/sql and pgx)
// whose query/statement argument MUST be a string literal or named
// string constant. A non-literal argument means the SQL text was built
// at runtime — the raw/concatenated-SQL smell this guard forbids.
var sqlMethodNames = map[string]bool{
	"Exec": true, "ExecContext": true,
	"Query": true, "QueryContext": true,
	"QueryRow": true, "QueryRowContext": true,
	"Prepare": true, "PrepareContext": true,
}

// dynamicSQLAllowlist lists the only sites permitted to pass a
// non-literal SQL string to a database method, each with the reason it is
// safe. Keyed by "<module-rel path> :: <rendered call>" so it survives
// line moves. assertNoStale fails the build if any entry stops matching.
var dynamicSQLAllowlist = map[string]string{
	"internal/store/rebuild.go :: tx.Exec(ctx, stmt)": "DDL `TRUNCATE TABLE <name>` during projection rebuild: the table name comes from the trusted in-process rebuildTarget registry (t.Tables), never from request input, and table identifiers cannot be bound as SQL parameters.",
	"internal/store/rebuild.go :: tx.Exec(ctx, seed)": "Post-TRUNCATE re-seed during projection rebuild (spec 21): `seed` ranges over rebuildTarget.SeedSQL, whose only values are the package-level seed*SQL string CONSTANTS mirroring 008_seeds.sql — compile-time fixed, never request input.",
	"internal/store/snapshot.go :: tx.Exec(ctx, fmt.Sprintf(`CREATE TEMP TABLE %s (LIKE public.%s INCLUDING ALL) ON COMMIT DROP`, tbl, tbl))": "DDL `CREATE TEMP TABLE <name>` during snapshot capture (spec 19): the table name comes from snapshotTables (AllRebuildTargets registry + a pg_tables projection-name scan), never request input; table identifiers cannot be bound as SQL parameters.",
	"internal/store/snapshot.go :: tx.Query(ctx, fmt.Sprintf(`SELECT to_jsonb(t) FROM %s t`, tbl))":                                           "Serializing a snapshot shadow table (spec 19): the same registry/pg_tables-derived name as the CREATE above; not request input, and a table identifier cannot be bound.",
	"internal/testutil/postgres.go :: shared.admin.ExecContext(ctx, fmt.Sprintf(`CREATE DATABASE %q TEMPLATE %q`, dbName, templateDatabase))": "Test harness only: per-test database isolation. `CREATE DATABASE` is DDL whose database/template identifiers cannot be bound as parameters; dbName is a fixed internal format (pm_test_<n>), never request input.",
	"internal/testutil/postgres.go :: shared.admin.ExecContext(dropCtx, fmt.Sprintf(`DROP DATABASE IF EXISTS %q WITH (FORCE)`, dbName))":      "Test harness only: per-test database teardown. `DROP DATABASE` is DDL whose database identifier cannot be bound as a parameter; dbName is a fixed internal format (pm_test_<n>), never request input.",
}

// TestNoDynamicSQL pins the sqlc / parameterized-SQL discipline: outside
// the generated query package, every call to a database query/exec method
// must receive a string-literal or named-string-const SQL argument. This
// makes "build a query string with fmt.Sprintf / string concatenation"
// fail the build — the canonical SQL-injection footgun — and locks the
// good state the 2026-06 sweep found (only the rebuild TRUNCATE DDL is a
// non-literal, and it is allowlisted with justification).
func TestNoDynamicSQL(t *testing.T) {
	root := moduleRoot(t)

	// A query whose SQL arg is a named string const (e.g. an
	// sqlc-generated const) is still a literal query.
	consts := stringConstNames(t, root)

	// Scan all production Go EXCEPT the generated sqlc package, which is
	// machine-emitted and guarded by the regenerate-diff job.
	files := walkGoFiles(t, root, func(rel string) bool {
		return !strings.HasPrefix(rel, "internal/store/generated/")
	})
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero production Go files — detector is mis-scoped")
	}

	allow := newAllowlist(dynamicSQLAllowlist)
	candidates := 0
	for _, gf := range files {
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !sqlMethodNames[sel.Sel.Name] {
				return true
			}
			sqlArg, ok := sqlArgOf(call)
			if !ok {
				return true
			}
			candidates++
			if isLiteralSQL(sqlArg, consts) {
				return true
			}
			key := gf.rel + " :: " + render(gf.fset, call)
			if allow.exempt(key) {
				return true
			}
			t.Errorf("dynamic SQL at %s:%d — %s\n  passes a non-literal SQL string. Use an sqlc-generated query or a parameterized literal; never build SQL with fmt.Sprintf/concatenation. If genuinely unavoidable, add a justified, guarded entry to dynamicSQLAllowlist.",
				gf.rel, gf.line(call), render(gf.fset, call))
			return true
		})
	}
	if candidates == 0 {
		t.Fatal("matches-zero guard: found no database query/exec call sites at all — the SQL-method set is mis-scoped, the guard would pass vacuously")
	}
	allow.assertNoStale(t)
}

// sqlArgOf returns the SQL-text argument of a database method call,
// accounting for the pgx shape (ctx, sql, args...) vs the database/sql
// shape (sql, args...).
func sqlArgOf(call *ast.CallExpr) (ast.Expr, bool) {
	if len(call.Args) == 0 {
		return nil, false
	}
	idx := 0
	if isContextArg(call.Args[0]) {
		idx = 1
	}
	if idx >= len(call.Args) {
		return nil, false
	}
	return call.Args[idx], true
}

// isLiteralSQL reports whether the SQL argument is a string literal or a
// named string constant (both safe), as opposed to a runtime-built value.
func isLiteralSQL(e ast.Expr, consts map[string]bool) bool {
	switch x := e.(type) {
	case *ast.BasicLit:
		return x.Kind == token.STRING
	case *ast.Ident:
		return consts[x.Name]
	case *ast.SelectorExpr:
		return consts[x.Sel.Name]
	case *ast.ParenExpr:
		return isLiteralSQL(x.X, consts)
	}
	return false
}
