package archtest

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCIRunsEveryTestBearingPackage guards the hardcoded package lists in
// .github/workflows/test.yml against failing open. The unit job and the
// integration shard matrix enumerate packages by hand (a deliberate choice:
// the unit/integration split is load-bearing because integration packages
// bring up testcontainers and take 5-20x longer). The failure mode of a
// hand-maintained list is silent: a new package with tests that lands in no
// list is never tested by CI at all — which is exactly how
// internal/{compliance,dyngroupeval,resolution,terminal} and cmd/{control,
// gateway} accumulated test files that had never run on any PR (#481).
//
// This guard discovers every package in the module that contains _test.go
// files and asserts each one is matched by at least one `./pkg/...` pattern
// referenced in test.yml. It is package-granular by design: shard `-run`
// filters (the ^Test[A-L] api split) partition WITHIN a package and are not
// this guard's concern.
//
// release.yml is intentionally out of scope: it re-tests a subset as a
// pre-publish smoke gate, while test.yml gates every PR and push — the
// list that must be complete is test.yml's.
func TestCIRunsEveryTestBearingPackage(t *testing.T) {
	root := moduleRoot(t)

	testedPkgs := discoverTestBearingPackages(t, root)
	if len(testedPkgs) == 0 {
		t.Fatal("matches-zero guard: discovered no packages with _test.go files; the walk is broken")
	}

	workflow := filepath.Join(root, ".github", "workflows", "test.yml")
	raw, err := os.ReadFile(workflow)
	if err != nil {
		t.Fatalf("read %s: %v", workflow, err)
	}
	patterns := extractPackagePatterns(string(raw))
	if len(patterns) == 0 {
		t.Fatal("matches-zero guard: extracted no ./pkg/... patterns from test.yml; the parser is broken")
	}

	// A pattern referencing a directory that no longer exists is a stale
	// list entry — the same rot this guard exists to prevent, in the other
	// direction.
	for _, p := range patterns {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(p))); err != nil {
			t.Errorf("test.yml references ./%s/... but that directory does not exist (stale list entry)", p)
		}
	}

	for _, pkg := range testedPkgs {
		if !coveredBy(pkg, patterns) {
			t.Errorf("package %s has _test.go files but is matched by no ./pkg/... pattern in test.yml — its tests never run in CI; add it to the unit list or an integration shard", pkg)
		}
	}
}

// discoverTestBearingPackages returns the module-relative, slash-separated
// directory of every package under root that contains at least one _test.go
// file. vendor/, testdata/, .git/ and hidden directories are skipped.
func discoverTestBearingPackages(t *testing.T, root string) []string {
	t.Helper()
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == "testdata" || (strings.HasPrefix(name, ".") && path != root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		seen[filepath.ToSlash(rel)] = true
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	pkgs := make([]string, 0, len(seen))
	for p := range seen {
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// pkgPattern matches the `./internal/api/...` package-tree arguments used in
// test.yml `go test` invocations and shard matrix `packages:` values.
var pkgPattern = regexp.MustCompile(`\./([A-Za-z0-9_/-]+)/\.\.\.`)

// extractPackagePatterns returns the deduplicated module-relative directory
// prefixes referenced as ./dir/... anywhere in the workflow text.
func extractPackagePatterns(workflow string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range pkgPattern.FindAllStringSubmatch(workflow, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// coveredBy reports whether pkg (e.g. internal/compliance) is inside any
// ./pattern/... tree (e.g. internal/compliance or internal).
func coveredBy(pkg string, patterns []string) bool {
	for _, p := range patterns {
		if pkg == p || strings.HasPrefix(pkg, p+"/") {
			return true
		}
	}
	return false
}
