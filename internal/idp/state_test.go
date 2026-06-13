package idp

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// WS5 #13 — CSRF state / nonce / PKCE primitives. These guard the SSO flow
// against CSRF (state), replay (nonce) and code interception (PKCE), so they
// need real entropy and a spec-correct S256 transform — pinned here against
// intent, not against the implementation.

func TestGenerateState_Nonce_CodeVerifier_EntropyAndShape(t *testing.T) {
	gens := map[string]func() (string, error){
		"state":         GenerateState,
		"nonce":         GenerateNonce,
		"code_verifier": GenerateCodeVerifier,
	}
	for name, gen := range gens {
		t.Run(name, func(t *testing.T) {
			a, err := gen()
			require.NoError(t, err)
			b, err := gen()
			require.NoError(t, err)

			assert.NotEmpty(t, a)
			assert.NotEqual(t, a, b, "two successive %s values must differ (entropy)", name)

			// RawURLEncoding-decodes to exactly 32 bytes (256 bits).
			raw, err := base64.RawURLEncoding.DecodeString(a)
			require.NoErrorf(t, err, "%s must be RawURLEncoding", name)
			assert.Lenf(t, raw, 32, "%s must carry 32 bytes of entropy", name)
		})
	}
}

// TestCodeChallengeS256_KnownAnswer pins the PKCE S256 transform against the
// RFC 7636 Appendix B known-answer vector — proving correctness against the
// spec, not against the implementation.
func TestCodeChallengeS256_KnownAnswer(t *testing.T) {
	const (
		verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	assert.Equal(t, challenge, CodeChallengeS256(verifier))
}
