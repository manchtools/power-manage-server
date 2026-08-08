package agentstream

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/delivery"
	"github.com/manchtools/power-manage/server/internal/execution"
)

// The classification itself, error by error. Continuing on a rejection is the
// default, so these cases pin the two directions independently: a benign
// rejection that ended the stream and a cross-actor claim that did not would
// both look identical from a single-direction test.
func TestFrameNotAuthorizedSeparatesRejectionFromCrossActorClaims(t *testing.T) {
	terminating := map[string]error{
		"foreign terminal session": errForeignTerminalSession,
		"another device's execution": fmt.Errorf("apply action result: %w",
			execution.ErrWrongDevice),
		"another delivery's occurrence": execution.ErrWrongDelivery,
		"another action's occurrence":   execution.ErrWrongAction,
		"another device's delivery":     delivery.ErrWrongDevice,
		"another manifest":              delivery.ErrWrongManifest,
		"unauthenticated":               connect.NewError(connect.CodeUnauthenticated, errors.New("no identity")),
		"permission denied":             connect.NewError(connect.CodePermissionDenied, errors.New("denied")),
	}
	for name, err := range terminating {
		t.Run("terminates/"+name, func(t *testing.T) {
			assert.True(t, frameNotAuthorized(err))
		})
	}

	surviving := map[string]error{
		"malformed result":     execution.ErrInvalidInput,
		"stale transition":     execution.ErrInvalidTransition,
		"conflicting replay":   execution.ErrConflictingReplay,
		"malformed delivery":   delivery.ErrInvalidInput,
		"stale delivery epoch": delivery.ErrStaleEpoch,
		"unsupported frame":    errors.New("unsupported agent frame"),
		"internal":             connect.NewError(connect.CodeInternal, errors.New("boom")),
		"not found":            connect.NewError(connect.CodeNotFound, errors.New("gone")),
	}
	for name, err := range surviving {
		t.Run("continues/"+name, func(t *testing.T) {
			assert.False(t, frameNotAuthorized(err))
		})
	}
}

// The guard that keeps the classification honest as the sinks grow.
//
// frameNotAuthorized defaults to "keep the stream", which is the right
// default for a rejection and exactly the wrong one for a claim on another
// actor's rows. A new ErrWrong… sentinel in either sink would therefore be
// silently downgraded to a logged warning. This discovers those sentinels
// from source instead of restating them, so the list cannot go stale.
func TestFrameAuthorizationClassificationCoversEveryCrossActorSentinel(t *testing.T) {
	classifier := functionSource(t, "handler.go", "frameNotAuthorized")

	discovered := 0
	for _, pkg := range []string{"execution", "delivery"} {
		for _, sentinel := range crossActorSentinels(t, filepath.Join("..", pkg)) {
			discovered++
			assert.Contains(t, classifier, pkg+"."+sentinel,
				"%s.%s names a claim on another actor's rows and must end the stream", pkg, sentinel)
		}
	}
	require.NotZero(t, discovered,
		"the sweep found no cross-actor sentinels — it is matching nothing and proves nothing")
}

// crossActorSentinels returns the ErrWrong… package-level error variables
// declared in dir. That prefix is the codebase's existing name for "the
// caller named a record that is not theirs".
func crossActorSentinels(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var names []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, entry.Name()), nil, 0)
		require.NoError(t, err)
		for _, decl := range file.Decls {
			general, ok := decl.(*ast.GenDecl)
			if !ok || general.Tok != token.VAR {
				continue
			}
			for _, spec := range general.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, name := range value.Names {
					if strings.HasPrefix(name.Name, "ErrWrong") {
						names = append(names, name.Name)
					}
				}
			}
		}
	}
	return names
}

// functionSource returns the source text of one top-level function.
func functionSource(t *testing.T, path, name string) string {
	t.Helper()
	source, err := os.ReadFile(path)
	require.NoError(t, err)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, source, 0)
	require.NoError(t, err)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name || fn.Recv != nil {
			continue
		}
		return string(source[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset])
	}
	t.Fatalf("%s declares no function %s", path, name)
	return ""
}
