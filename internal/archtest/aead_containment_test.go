package archtest

import (
	"go/ast"
	"strings"
	"testing"
)

// TestAEADStaysInCryptoPackage pins spec 20 / F-06's anti-regression:
// the ONLY at-rest encryption surface is internal/crypto's AAD-bound
// EncryptWithContext/DecryptWithContext. Two ways a new call site could
// regress to unbound ciphertext, both forbidden here:
//
//  1. calling the AEAD primitives directly (gcm.Seal / gcm.Open)
//     outside internal/crypto — that reopens the nil-AAD path the
//     removed naked Encrypt/Decrypt used to hide;
//  2. passing a literal nil/empty AAD to *WithContext — the runtime
//     check refuses it, but the build should too.
//
// Seal is flagged unconditionally (no legitimate non-AEAD Seal exists
// in this module); Open only at the AEAD arity (4 args: dst, nonce,
// ciphertext, aad) so sql.Open / os.Open (1–2 args) stay untouched.
func TestAEADStaysInCryptoPackage(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(rel string) bool {
		return !strings.HasPrefix(rel, "internal/store/generated/")
	})
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero production Go files — detector is mis-scoped")
	}

	sawInsideCrypto := 0
	for _, gf := range files {
		insideCrypto := strings.HasPrefix(gf.rel, "internal/crypto/")
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "Seal":
				if insideCrypto {
					sawInsideCrypto++
					return true
				}
				t.Errorf("AEAD Seal outside internal/crypto at %s:%d — at-rest encryption goes through crypto.EncryptWithContext (single AAD-bound format, spec 20)", gf.rel, gf.line(call))
			case "Open":
				if len(call.Args) != 4 {
					return true // sql.Open / os.Open etc.
				}
				if insideCrypto {
					sawInsideCrypto++
					return true
				}
				t.Errorf("AEAD Open outside internal/crypto at %s:%d — at-rest decryption goes through crypto.DecryptWithContext", gf.rel, gf.line(call))
			case "EncryptWithContext", "DecryptWithContext":
				// aad is the last argument; a literal nil / empty
				// composite is a compile-visible unbound call.
				if len(call.Args) == 0 {
					return true
				}
				aad := call.Args[len(call.Args)-1]
				if id, ok := aad.(*ast.Ident); ok && id.Name == "nil" {
					t.Errorf("nil AAD passed to %s at %s:%d — every at-rest secret is context-bound (spec 20 / F-06); build a crypto.SecretAAD/RowAAD", sel.Sel.Name, gf.rel, gf.line(call))
				}
			}
			return true
		})
	}
	if sawInsideCrypto == 0 {
		t.Fatal("matches-zero guard: found no AEAD Seal/Open inside internal/crypto — the detector is dead, the guard would pass vacuously")
	}
}
