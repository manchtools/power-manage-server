package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// Spec 19 AC 17a: projector determinism is ENFORCED statically, not just
// tested. The AC 16/17 round-trip tests catch non-determinism only when
// the offending input happens to differ between two runs — a projector
// that consults a non-deterministic source can pass CI by coincidence.
// This guard fails the build for the two sources the WS0 clock seam
// (TestNoUnabstractedTimeNow) does not cover:
//
//   - math/rand (v1 or v2) anywhere in the projector set;
//   - iteration over a MAP, whose order Go randomizes per run. A map
//     range inside an applier is only safe when the loop body is
//     order-independent (pure per-key upserts, map→map transforms);
//     every such site must be allowlisted with that justification.
//
// Detection is pure-AST (archtest convention — no type checker), so
// map-typed expressions are recognized heuristically:
//
//   - a composite literal / make() of an *ast.MapType;
//   - an identifier declared map-typed in the SAME FILE (var decl,
//     := / = from a map literal or make(map…), func param or result);
//   - a selector (x.Labels) whose FIELD NAME is map-typed in any struct
//     declared in the projector or payloads packages.
//
// The heuristic over-approximates (a same-named non-map field elsewhere
// would flag too) — that is the right failure mode for a guard: flag
// loud, justify in the allowlist.

// mapRangeAllowlist lists the only sanctioned map iterations in the
// projector set, each with the reason its loop body is order-independent.
// Keyed "<module-rel path> :: <ranged expression>". assertNoStale fails
// the build if an entry stops matching.
var mapRangeAllowlist = map[string]string{
	"internal/projectors/device.go :: any":                     "map→map transform (raw JSON labels → map[string]string): writes only out[k] per key, no I/O, no ordering side effects — the resulting map is identical regardless of iteration order.",
	"internal/projectors/device_listener.go :: payload.Labels": "Per-key SetDeviceLabel upsert (ON CONFLICT (device_id, key)): each key writes exactly its own row, so the final device_labels row set is identical regardless of iteration order.",
}

// TestProjectorDeterminism pins spec 19 AC 17a for the projector set.
func TestProjectorDeterminism(t *testing.T) {
	root := moduleRoot(t)

	files := walkGoFiles(t, root, func(rel string) bool {
		return strings.HasPrefix(rel, "internal/projectors/")
	})
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero projector files — the guard is mis-scoped")
	}

	// Map-typed struct FIELD names, indexed across the projector and
	// payloads packages (covers `payload.Labels` where the struct is
	// declared in another file/package, and inline decode structs).
	fieldFiles := walkGoFiles(t, root, func(rel string) bool {
		return strings.HasPrefix(rel, "internal/projectors/") ||
			strings.HasPrefix(rel, "internal/eventtypes/payloads/")
	})
	mapFields := map[string]bool{}
	for _, gf := range fieldFiles {
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok {
				return true
			}
			for _, f := range st.Fields.List {
				if _, isMap := f.Type.(*ast.MapType); isMap {
					for _, name := range f.Names {
						mapFields[name.Name] = true
					}
				}
			}
			return true
		})
	}
	if len(mapFields) == 0 {
		t.Fatal("matches-zero guard: found no map-typed struct fields in projectors/payloads — the field index is broken and selector ranges would pass vacuously")
	}

	allow := newAllowlist(mapRangeAllowlist)
	rangeStmts := 0
	for _, gf := range files {
		// (a) math/rand is banned outright in the projector set.
		for _, imp := range gf.ast.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if path == "math/rand" || path == "math/rand/v2" {
				t.Errorf("non-deterministic source at %s: import %q — projectors must be deterministic (spec 19 AC 17a); derive randomness-free values from the event", gf.rel, path)
			}
		}

		// (b) map iterations must be allowlisted as order-independent.
		localMaps := fileLocalMapIdents(gf.ast)
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			rs, ok := n.(*ast.RangeStmt)
			if !ok {
				return true
			}
			rangeStmts++
			if !looksMapTyped(rs.X, localMaps, mapFields) {
				return true
			}
			key := gf.rel + " :: " + render(gf.fset, rs.X)
			if allow.exempt(key) {
				return true
			}
			t.Errorf("map iteration at %s:%d — `range %s`\n  Go randomizes map order per run, so an order-dependent body breaks snapshot equivalence (spec 19 AC 17/17a). Make the body order-independent (per-key upserts only) and add a justified mapRangeAllowlist entry, or iterate sorted keys.",
				gf.rel, gf.line(rs), render(gf.fset, rs.X))
			return true
		})
	}
	if rangeStmts == 0 {
		t.Fatal("matches-zero guard: found no range statements in the projector set at all — the detector is mis-scoped and would pass vacuously")
	}
	allow.assertNoStale(t)
}

// TestFileLocalMapIdents_DetectsEveryDeclarationForm pins the detector
// itself: every way a file can visibly declare a map-typed identifier
// must be recognized, or a projector ranging over one silently passes
// the determinism guard (the false-negative CR flagged for
// `var x = make(map…)`).
func TestFileLocalMapIdents_DetectsEveryDeclarationForm(t *testing.T) {
	src := `package p
func f(param map[string]int) (ret map[string]int) {
	var typed map[string]bool
	var inferredMake = make(map[string]int)
	var inferredLit = map[string]int{"a": 1}
	shortMake := make(map[string]string)
	shortLit := map[string]bool{}
	notAMap := []string{"x"}
	_ = typed; _ = inferredMake; _ = inferredLit; _ = shortMake; _ = shortLit; _ = notAMap
	return nil
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "snippet.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse snippet: %v", err)
	}
	got := fileLocalMapIdents(f)
	for _, want := range []string{"param", "ret", "typed", "inferredMake", "inferredLit", "shortMake", "shortLit"} {
		if !got[want] {
			t.Errorf("map-typed identifier %q not detected — a `range %s` would silently evade the determinism guard", want, want)
		}
	}
	if got["notAMap"] {
		t.Error("slice identifier misclassified as a map")
	}
}

// fileLocalMapIdents collects identifier names visibly declared
// map-typed within one file: var declarations, := / = assignments from a
// map literal or make(map…), and function parameters/results.
func fileLocalMapIdents(f *ast.File) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ValueSpec:
			if _, isMap := x.Type.(*ast.MapType); isMap {
				for _, name := range x.Names {
					out[name.Name] = true
				}
			}
			// `var x = make(map…)` / `var x = map[…]{…}`: no explicit
			// type, the map-ness lives in the initializer (CR).
			for i, val := range x.Values {
				if i >= len(x.Names) {
					break
				}
				if isMapProducer(val) {
					out[x.Names[i].Name] = true
				}
			}
		case *ast.AssignStmt:
			for i, rhs := range x.Rhs {
				if i >= len(x.Lhs) {
					break
				}
				if !isMapProducer(rhs) {
					continue
				}
				if id, ok := x.Lhs[i].(*ast.Ident); ok {
					out[id.Name] = true
				}
			}
		case *ast.FuncType:
			for _, fl := range []*ast.FieldList{x.Params, x.Results} {
				if fl == nil {
					continue
				}
				for _, fld := range fl.List {
					if _, isMap := fld.Type.(*ast.MapType); isMap {
						for _, name := range fld.Names {
							out[name.Name] = true
						}
					}
				}
			}
		}
		return true
	})
	return out
}

// isMapProducer reports whether an expression syntactically yields a map:
// a map composite literal or make(map[...]...).
func isMapProducer(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.CompositeLit:
		_, isMap := x.Type.(*ast.MapType)
		return isMap
	case *ast.CallExpr:
		if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "make" && len(x.Args) > 0 {
			_, isMap := x.Args[0].(*ast.MapType)
			return isMap
		}
	}
	return false
}

// looksMapTyped reports whether a ranged expression is (heuristically)
// map-typed: a map literal, a file-locally-declared map identifier, or a
// selector whose field name is map-typed somewhere in the indexed
// packages.
func looksMapTyped(e ast.Expr, localMaps, mapFields map[string]bool) bool {
	switch x := e.(type) {
	case *ast.CompositeLit:
		_, isMap := x.Type.(*ast.MapType)
		return isMap
	case *ast.Ident:
		return localMaps[x.Name]
	case *ast.SelectorExpr:
		return mapFields[x.Sel.Name]
	case *ast.ParenExpr:
		return looksMapTyped(x.X, localMaps, mapFields)
	}
	return false
}
