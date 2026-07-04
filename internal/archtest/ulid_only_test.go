package archtest

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestULIDOnlyIdentifiers pins the repo-wide mandatory-ULID rule
// (spec 20 / audit F-15: "uuid usage is debt to fix, not to
// accept-and-document"). Two enforcement surfaces, both with EMPTY
// allowlists — a third domain cannot copy the retired uuid pattern:
//
//  1. Go: no github.com/google/uuid import anywhere, INCLUDING the
//     sqlc-generated package — a new uuid column would resurface the
//     import there even if no hand-written code touches it.
//  2. Migrations: no `gen_random_uuid()` default and no `uuid`-typed
//     column in any non-comment line — identifiers are text ULIDs
//     minted in Go (crypto/rand-backed ulid.Make), so the DB never
//     mints a random identifier the event replay cannot reproduce.
func TestULIDOnlyIdentifiers(t *testing.T) {
	root := moduleRoot(t)

	// (1) Go imports — scan everything, generated included.
	files := walkGoFiles(t, root, func(string) bool { return true })
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero Go files")
	}
	sawImports := 0
	for _, gf := range files {
		for _, imp := range gf.ast.Imports {
			sawImports++
			if strings.Contains(imp.Path.Value, "github.com/google/uuid") {
				t.Errorf("google/uuid imported at %s — identifiers are ULIDs (oklog/ulid), never UUIDs (F-15). If sqlc regenerated this, a uuid-typed column crept back into the schema.", gf.rel)
			}
		}
	}
	if sawImports == 0 {
		t.Fatal("matches-zero guard: saw zero imports — scan is broken")
	}

	// (2) Migration SQL.
	migDir := filepath.Join(root, "internal", "store", "migrations")
	entries, err := os.ReadDir(migDir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	scanned := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		scanned++
		f, err := os.Open(filepath.Join(migDir, e.Name()))
		if err != nil {
			t.Fatalf("open %s: %v", e.Name(), err)
		}
		sc := bufio.NewScanner(f)
		line := 0
		for sc.Scan() {
			line++
			text := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(text, "--") {
				continue // comment
			}
			lower := strings.ToLower(text)
			if strings.Contains(lower, "gen_random_uuid") {
				t.Errorf("gen_random_uuid() in migration %s:%d — the DB must not mint random identifiers (non-deterministic under replay); mint a ULID in Go", e.Name(), line)
			}
			// A uuid-typed column: "<name> uuid" optionally followed by
			// constraints. Word-boundary match avoids substrings.
			for _, tok := range strings.Fields(lower) {
				if tok == "uuid" || tok == "uuid," {
					t.Errorf("uuid-typed column in migration %s:%d (%q) — identifiers are text ULIDs (F-15)", e.Name(), line, text)
					break
				}
			}
		}
		f.Close()
		if err := sc.Err(); err != nil {
			t.Fatalf("scan %s: %v", e.Name(), err)
		}
	}
	if scanned == 0 {
		t.Fatal("matches-zero guard: scanned zero migration files")
	}
}
