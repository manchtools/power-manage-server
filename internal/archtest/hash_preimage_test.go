package archtest

import (
	"go/ast"
	"go/token"
	"regexp"
	"testing"
)

// hashPreimageAllowlist exempts hashing call sites whose multi-field preimage is
// nonetheless unambiguous (e.g. a fixed-width, self-delimiting layout). Empty
// today: every hashing site in the module either hashes a single value or builds
// a length-prefixed/domain-separated preimage (stableExecutionID's writeFramed,
// the signing canonicalDigest). Keyed by "<module-rel path> :: <rendered call>".
var hashPreimageAllowlist = map[string]string{}

// hashReceiverRe matches identifiers that conventionally name a hash/MAC writer,
// so `<recv>.Write(preimage)` is treated as a hashing sink. Documented heuristic
// per the archtest design constraints.
var hashReceiverRe = regexp.MustCompile(`(?i)^(h|hash|hasher|mac|hmac|digest|sum|sha\d*)$`)

// hashSumFuncs are the package-qualified one-shot hashing constructors whose
// FIRST argument is the preimage (crypto/sha256, sha512, sha1, md5).
var hashSumFuncs = map[string]map[string]bool{
	"sha256": {"Sum256": true, "Sum224": true},
	"sha512": {"Sum512": true, "Sum384": true, "Sum512_256": true, "Sum512_224": true},
	"sha1":   {"Sum": true},
	"md5":    {"Sum": true},
}

// TestNoUnframedHashPreimage forbids feeding a hash/MAC a preimage built by
// +-concatenation or fmt.Sprintf of multiple fields. Such a preimage is
// ambiguous: ("a","bc") and ("ab","c") hash identically, so a value that can
// contain the (implicit) separator lets one input forge another's digest — the
// same pre-image-ambiguity class as the action-signing bug (WS1) and the dedup
// execution-id bug (WS1b#3). Preimages must be length-prefixed / domain-separated
// (e.g. the writeFramed helper) or a single value.
//
// Detected sinks: sha{256,512,1}/md5 one-shot Sum* calls (first arg), and
// `<recv>.Write(arg)` where recv looks like a hash writer (hashReceiverRe).
// A site is a violation when the preimage arg is a `+` BinaryExpr or a
// fmt.Sprintf(...) call. Genuinely-unambiguous multi-field layouts go in the
// guarded hashPreimageAllowlist.
func TestNoUnframedHashPreimage(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(string) bool { return true })
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero production Go files")
	}
	allow := newAllowlist(hashPreimageAllowlist)
	sawSink := false

	for _, gf := range files {
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			preimage, isSink := hashSinkPreimage(call)
			if !isSink {
				return true
			}
			sawSink = true
			if !isUnframedPreimage(preimage) {
				return true
			}
			key := gf.rel + " :: " + render(gf.fset, call)
			if allow.exempt(key) {
				return true
			}
			t.Errorf("hash preimage built by concatenation/Sprintf at %s:%d — %s\n  a +-joined or fmt.Sprintf preimage is field-boundary ambiguous; length-prefix/domain-separate it (see writeFramed / canonicalDigest). If the layout is genuinely unambiguous, justify it in hashPreimageAllowlist.",
				gf.rel, gf.line(call), render(gf.fset, call))
			return true
		})
	}

	if !sawSink {
		t.Fatal("matches-zero guard: detected no hashing sinks in the module — the detector is dead, the guard would pass vacuously")
	}
	allow.assertNoStale(t)
}

// hashSinkPreimage reports whether call is a hashing sink and returns the
// expression that becomes the hash preimage.
func hashSinkPreimage(call *ast.CallExpr) (ast.Expr, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}
	// pkg.Sum256(preimage) one-shot forms.
	if pkg, ok := sel.X.(*ast.Ident); ok {
		if funcs, ok := hashSumFuncs[pkg.Name]; ok && funcs[sel.Sel.Name] && len(call.Args) >= 1 {
			return call.Args[0], true
		}
	}
	// <recv>.Write(preimage) where recv looks like a hash writer.
	if sel.Sel.Name == "Write" && len(call.Args) == 1 {
		if recv, ok := sel.X.(*ast.Ident); ok && hashReceiverRe.MatchString(recv.Name) {
			return call.Args[0], true
		}
	}
	return nil, false
}

// isUnframedPreimage reports whether e is a multi-field concatenation (`a + b`)
// or a fmt.Sprintf(...) call — the ambiguous shapes this guard forbids.
func isUnframedPreimage(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.BinaryExpr:
		return x.Op == token.ADD
	case *ast.CallExpr:
		// fmt.Sprintf(...) (or any *.Sprintf) used to build the preimage.
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Sprintf" {
			return true
		}
		// A conversion like []byte(a + b) — unwrap a single-arg conversion.
		if len(x.Args) == 1 {
			if _, isArr := x.Fun.(*ast.ArrayType); isArr {
				return isUnframedPreimage(x.Args[0])
			}
		}
	case *ast.ParenExpr:
		return isUnframedPreimage(x.X)
	}
	return false
}
