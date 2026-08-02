package architecture_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestAbolishedArchitectureCannotReturn(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))

	for _, path := range []string{
		"cmd/gateway",
		"cmd/indexer",
		"internal/api",
		"internal/eventtypes",
		"internal/projectors",
		"internal/search",
		"internal/taskqueue",
	} {
		err := filepath.WalkDir(filepath.Join(root, path), func(found string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() {
				t.Errorf("abolished architecture returned at %s", found)
				return fs.SkipAll
			}
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("inspect %s: %v", path, err)
		}
	}

	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for _, dependency := range []string{
		"github.com/alicebob/miniredis",
		"github.com/hibiken/asynq",
		"github.com/pquerna/otp",
		"github.com/redis/go-redis",
	} {
		if strings.Contains(string(mod), dependency) {
			t.Errorf("abolished dependency returned: %s", dependency)
		}
	}
}

func TestAbolishedRuntimeAPIsCannotReturn(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))

	forbiddenImports := []string{
		"github.com/hibiken/asynq",
		"github.com/redis/go-redis",
		"github.com/alicebob/miniredis",
		"power-manage-sdk/verify",
		"net/smtp",
	}
	forbiddenIdentifiers := []string{
		"ActionEnvelope",
		"AppendEvent",
		"Asynq",
		"CertificateRevocationList",
		"CRLDistribution",
		"DomainEvent",
		"EventStore",
		"EmailNotifier",
		"EmailSender",
		"Gateway",
		"GetCertificateRevocationList",
		"Projector",
		"Redis",
		"ReplayEvent",
		"SignedAction",
		"SMTP",
		"Valkey",
	}

	files := 0
	identifiers := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "vendor", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		files++
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			for _, forbidden := range forbiddenImports {
				if strings.Contains(importPath, forbidden) {
					t.Errorf("abolished runtime import %q returned in %s", importPath, path)
				}
			}
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			identifiers++
			for _, forbidden := range forbiddenIdentifiers {
				if strings.Contains(identifier.Name, forbidden) {
					t.Errorf("abolished runtime identifier %q returned in %s", identifier.Name, path)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 || identifiers == 0 {
		t.Fatalf("matches-zero guard: inspected %d production Go files and %d identifiers", files, identifiers)
	}
}
