package eventtypes

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"testing"
)

// TestAll_NoDuplicates ensures the All() slice has no duplicate values.
// A duplicate would mean two constants share a wire string and a typo
// or copy-paste mistake during a future addition would silently
// shadow an existing event.
func TestAll_NoDuplicates(t *testing.T) {
	seen := make(map[EventType]bool, len(All()))
	for _, et := range All() {
		if seen[et] {
			t.Errorf("duplicate event type in All(): %q", et)
		}
		seen[et] = true
	}
}

// TestAll_NonEmpty ensures every constant has a non-empty wire string.
// An empty event type would never match in any switch and would also
// fail the events table CHECK constraint.
func TestAll_NonEmpty(t *testing.T) {
	for i, et := range All() {
		if et == "" {
			t.Errorf("All()[%d] is empty", i)
		}
	}
}

// TestAll_MatchesPattern ensures every constant follows PascalCase
// (the project convention for event-type identifiers). This catches
// accidental snake_case or kebab-case slips at refactor time.
func TestAll_MatchesPattern(t *testing.T) {
	// Allow PascalCase with embedded uppercase runs (TOTPVerified,
	// SCIMGroupMapped, IdentityProviderSCIMEnabled). Identifiers must
	// start with an uppercase letter and contain only ASCII letters
	// and digits.
	pattern := regexp.MustCompile(`^[A-Z][A-Za-z0-9]+$`)
	for _, et := range All() {
		if !pattern.MatchString(string(et)) {
			t.Errorf("event type %q does not match PascalCase pattern", et)
		}
	}
}

// TestAll_CompleteCoverage parses types.go via go/ast and asserts that
// every declared `EventType` constant in the package is also present in
// the All() slice. The slice is hand-maintained — without this guard,
// adding a new constant without appending it to All() silently drops
// the new event from every parity-style test that consumes All() (e.g.
// the eventtypes-vs-handler audits, the no-duplicates / non-empty /
// pattern checks above). Audit N015.
func TestAll_CompleteCoverage(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "types.go", nil, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse types.go: %v", err)
	}

	declared := make(map[string]struct{})
	ast.Inspect(f, func(n ast.Node) bool {
		gen, ok := n.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			return true
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			// Type may be inferred from a previous spec inside the
			// same const ( ... ) block; capture only specs whose own
			// Type is the EventType identifier we care about.
			ident, ok := vs.Type.(*ast.Ident)
			if !ok || ident.Name != "EventType" {
				continue
			}
			for _, name := range vs.Names {
				declared[name.Name] = struct{}{}
			}
		}
		return true
	})

	if len(declared) == 0 {
		t.Fatal("parsed types.go but found zero EventType constants — parser drift?")
	}

	// Build a name set for All() by reflecting the wire string back to
	// the source-code constant name. Simpler: re-read types.go into a
	// map[wire]name and assert the wire-set in All() matches.
	wireToName := make(map[EventType]string)
	ast.Inspect(f, func(n ast.Node) bool {
		gen, ok := n.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			return true
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			ident, ok := vs.Type.(*ast.Ident)
			if !ok || ident.Name != "EventType" {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				// Strip the surrounding quotes from the literal.
				wire := lit.Value
				if len(wire) >= 2 {
					wire = wire[1 : len(wire)-1]
				}
				wireToName[EventType(wire)] = name.Name
			}
		}
		return true
	})

	inAll := make(map[EventType]struct{}, len(All()))
	for _, et := range All() {
		inAll[et] = struct{}{}
	}

	var missing []string
	for wire, name := range wireToName {
		if _, ok := inAll[wire]; !ok {
			missing = append(missing, name+" ("+string(wire)+")")
		}
	}
	if len(missing) > 0 {
		t.Errorf("EventType constants declared but missing from All() — append them to types.go:All():\n  %v", missing)
	}
}
