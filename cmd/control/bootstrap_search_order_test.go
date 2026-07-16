package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMain_WiresSearchListenerBeforeBootstrapEvents pins the fresh-deploy boot
// invariant: newValkeySubsystem registers api.SearchListener, so it MUST run
// before every bootstrap helper below emits searchable events. Otherwise the
// event is projected into Postgres but never enqueued for the search index; if
// indexer's concurrent startup rebuild already finished, the entity stays
// missing until an operator manually rebuilds search.
func TestMain_WiresSearchListenerBeforeBootstrapEvents(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, parser.SkipObjectResolution)
	require.NoError(t, err)

	positions := map[string]token.Pos{}
	var mainBody *ast.BlockStmt
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "main" {
			mainBody = fn.Body
			break
		}
	}
	require.NotNil(t, mainBody, "main function must exist")

	ast.Inspect(mainBody, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		switch id.Name {
		case "newValkeySubsystem", "ensureAdminUser", "seedSSHAccessForAll", "bootstrapAllDevicesGroup":
			if positions[id.Name] == token.NoPos {
				positions[id.Name] = call.Pos()
			}
		}
		return true
	})

	searchWiredAt := positions["newValkeySubsystem"]
	require.NotEqual(t, token.NoPos, searchWiredAt, "main must initialize the Valkey/search subsystem")
	for _, emitter := range []string{"ensureAdminUser", "seedSSHAccessForAll", "bootstrapAllDevicesGroup"} {
		emittedAt := positions[emitter]
		require.NotEqual(t, token.NoPos, emittedAt, "%s must remain covered by the boot-order guard", emitter)
		require.Less(t, int(searchWiredAt), int(emittedAt),
			"newValkeySubsystem must register SearchListener before %s emits an event", emitter)
	}
}
