package archtest

import (
	"go/ast"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	// Imported for its init() side effect: registers every pm.v1 file
	// descriptor in protoregistry.GlobalFiles so the proto-reflection arm below
	// can walk them.
	_ "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// signCallAllowlist enumerates the application-level call sites of the action
// signer's Sign method. The action-signing design (ADR 0003) requires the CA
// signature to be minted from exactly ONE canonicalization seam
// (actionparams.BuildAndSignEnvelope), so the bytes that are signed are exactly
// the deterministic SignedActionEnvelope wire bytes that get transported and
// executed. A second Sign call site would reintroduce the divergent-representation
// risk WS1 removed. Keyed by "<module-rel path> :: <rendered call expression>".
var signCallAllowlist = map[string]string{
	"internal/actionparams/sign_envelope.go :: signer.Sign(envelopeBytes)": "the single canonicalization seam: signs verify.MarshalEnvelope(env) deterministic bytes (ADR 0003)",
}

const protoPackageName = "pm.v1"

// TestSignatureIsOverDeterministicProtoAndSingleRepresentation pins the two
// structural invariants behind the action-signing design (ADR 0003 / WS1):
//
//	(a) proto reflection — NO message field is named "*_canonical". The clean
//	    break removed Action.params_canonical and the params_canonical/typed-params
//	    split; a re-introduced "*_canonical" field is the smell returning (two
//	    representations of the same data that can diverge under signing).
//	(b) AST — the action signer's Sign method is invoked from exactly one
//	    canonicalization seam (actionparams.BuildAndSignEnvelope). Every Sign
//	    call site must be in signCallAllowlist; a new one fails the build.
//
// Together they pin "one deterministic representation, signed once" so a future
// change cannot silently reintroduce a second, divergent canonical form.
func TestSignatureIsOverDeterministicProtoAndSingleRepresentation(t *testing.T) {
	t.Run("no _canonical proto fields", func(t *testing.T) {
		messages := 0
		violations := 0
		protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
			if string(fd.Package()) != protoPackageName {
				return true
			}
			walkMessages(fd.Messages(), func(md protoreflect.MessageDescriptor) {
				messages++
				fields := md.Fields()
				for i := 0; i < fields.Len(); i++ {
					name := string(fields.Get(i).Name())
					if strings.HasSuffix(name, "_canonical") {
						violations++
						t.Errorf("proto field %s.%s ends in _canonical — a *_canonical field paired with a typed twin is the divergent-representation smell WS1 removed; carry the single typed/deterministic form instead", md.FullName(), name)
					}
				}
			})
			return true
		})
		if messages == 0 {
			t.Fatal("matches-zero guard: walked zero pm.v1 proto messages — the proto package is not registered, the check would pass vacuously")
		}
	})

	t.Run("Sign called only from the canonicalization seam", func(t *testing.T) {
		root := moduleRoot(t)
		files := walkGoFiles(t, root, func(string) bool { return true })
		if len(files) == 0 {
			t.Fatal("matches-zero guard: walked zero production Go files")
		}
		allow := newAllowlist(signCallAllowlist)
		sawSignCall := false
		for _, gf := range files {
			ast.Inspect(gf.ast, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Sign" {
					return true
				}
				sawSignCall = true
				key := gf.rel + " :: " + render(gf.fset, call)
				if allow.exempt(key) {
					return true
				}
				t.Errorf("action-signer Sign() called outside the single canonicalization seam at %s:%d — %s\n  all action signing must route through actionparams.BuildAndSignEnvelope so the signed bytes are the deterministic SignedActionEnvelope wire bytes (ADR 0003). If this is a legitimate new seam, justify it in signCallAllowlist.",
					gf.rel, gf.line(call), render(gf.fset, call))
				return true
			})
		}
		if !sawSignCall {
			t.Fatal("matches-zero guard: detected no .Sign(...) calls in the module — the detector is dead, the guard would pass vacuously")
		}
		allow.assertNoStale(t)
	})
}

// walkMessages invokes fn for every message descriptor in mds, recursing into
// nested message types so a *_canonical field cannot hide inside a nested message.
func walkMessages(mds protoreflect.MessageDescriptors, fn func(protoreflect.MessageDescriptor)) {
	for i := 0; i < mds.Len(); i++ {
		md := mds.Get(i)
		fn(md)
		walkMessages(md.Messages(), fn)
	}
}
