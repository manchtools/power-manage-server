package idp_test

// OIDC token-verify happy-path coverage — extends the discovery
// fixture from #217 with a real RSA-signed id_token so
// VerifyAndExtractClaims can be exercised end-to-end. Closes the
// "OIDC token+verify follow-up" item from
// manchtools/power-manage-server#161.
//
// Strategy: generate an in-test RSA key pair, sign a JWT with
// go-jose/v4, expose the public key via the existing fake JWKS
// endpoint pattern, and hand the signed token to
// VerifyAndExtractClaims via an oauth2.Token whose id_token Extra
// is the signed JWS. Skips the network ExchangeCode round-trip —
// that's just golang.org/x/oauth2 internals which the upstream
// library tests already cover.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/manchtools/power-manage/server/internal/idp"
)

// signedOIDCFixture stands up an httptest.Server that publishes a
// discovery doc + JWKS containing the test RSA public key.
// signIDToken signs a JWT against the same key so VerifyAndExtractClaims
// will accept it.
type signedOIDCFixture struct {
	srv  *httptest.Server
	priv *rsa.PrivateKey
	kid  string
}

func newSignedOIDCFixture(t *testing.T) *signedOIDCFixture {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	kid := "test-key-1"

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/authorize",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/jwks.json",
			"response_types_supported":              []string{"code"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{
				Key:       &priv.PublicKey,
				KeyID:     kid,
				Algorithm: "RS256",
				Use:       "sig",
			}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	return &signedOIDCFixture{srv: srv, priv: priv, kid: kid}
}

// signIDToken builds + signs a minimal id_token with the given
// custom claims merged on top of the standard JWT claims. The
// fixture's RSA key signs it; go-oidc's verifier will then accept
// it via the JWKS published by the fixture.
func (f *signedOIDCFixture) signIDToken(t *testing.T, audience, nonce string, extra map[string]any) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: f.priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", f.kid),
	)
	require.NoError(t, err)

	now := time.Now()
	claims := map[string]any{
		"iss":   f.srv.URL,
		"sub":   "test-subject-123",
		"aud":   audience,
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"nonce": nonce,
	}
	for k, v := range extra {
		claims[k] = v
	}

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return raw
}

func TestVerifyAndExtractClaims_HappyPath(t *testing.T) {
	f := newSignedOIDCFixture(t)
	p, err := idp.NewOIDCProvider(context.Background(), idp.ProviderConfig{
		IssuerURL:   f.srv.URL,
		ClientID:    "test-client",
		RedirectURL: "https://app.example.com/cb",
	})
	require.NoError(t, err)

	idToken := f.signIDToken(t, "test-client", "the-expected-nonce", map[string]any{
		"email": "alice@example.com",
		// email_verified gates whether the email is usable for linking /
		// auto-create (#359). The happy path is a verified email.
		"email_verified": true,
		"name":           "Alice Test",
		"given_name":     "Alice",
	})
	tok := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": idToken})

	claims, err := p.VerifyAndExtractClaims(context.Background(), tok, "the-expected-nonce")
	require.NoError(t, err)
	assert.Equal(t, "test-subject-123", claims.Subject)
	assert.Equal(t, "alice@example.com", claims.Email)
	assert.Equal(t, "Alice Test", claims.Name)
	assert.Equal(t, "Alice", claims.GivenName)
}

// TestVerifyAndExtractClaims_EmailVerifiedGate pins the #359 fix: an email
// claim is only populated (and thus usable for auto-link / auto-create) when
// email_verified is true. An attacker who can set an arbitrary, UNVERIFIED
// email at the IdP (common with multi-tenant Azure AD / self-service IdPs)
// must not be able to drive account linking by claiming a victim's address.
// The subject is always populated — identity is keyed on sub, not email.
func TestVerifyAndExtractClaims_EmailVerifiedGate(t *testing.T) {
	cases := []struct {
		name            string
		email           string
		emailPresent    bool
		emailVerified   any
		verifiedPresent bool
		wantEmail       string
	}{
		{name: "verified (bool true)", email: "alice@example.com", emailPresent: true, emailVerified: true, verifiedPresent: true, wantEmail: "alice@example.com"},
		{name: "verified (string \"true\")", email: "alice@example.com", emailPresent: true, emailVerified: "true", verifiedPresent: true, wantEmail: "alice@example.com"},
		{name: "unverified (bool false)", email: "alice@example.com", emailPresent: true, emailVerified: false, verifiedPresent: true, wantEmail: ""},
		{name: "unverified (string \"false\")", email: "alice@example.com", emailPresent: true, emailVerified: "false", verifiedPresent: true, wantEmail: ""},
		{name: "email_verified claim absent", email: "alice@example.com", emailPresent: true, verifiedPresent: false, wantEmail: ""},
		{name: "email claim absent (verified true)", emailPresent: false, emailVerified: true, verifiedPresent: true, wantEmail: ""},
		{name: "email empty string (verified true)", email: "", emailPresent: true, emailVerified: true, verifiedPresent: true, wantEmail: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSignedOIDCFixture(t)
			p, err := idp.NewOIDCProvider(context.Background(), idp.ProviderConfig{
				IssuerURL:   f.srv.URL,
				ClientID:    "test-client",
				RedirectURL: "https://app.example.com/cb",
			})
			require.NoError(t, err)

			extra := map[string]any{}
			if tc.emailPresent {
				extra["email"] = tc.email
			}
			if tc.verifiedPresent {
				extra["email_verified"] = tc.emailVerified
			}
			idToken := f.signIDToken(t, "test-client", "n", extra)
			tok := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": idToken})

			claims, err := p.VerifyAndExtractClaims(context.Background(), tok, "n")
			require.NoError(t, err)
			assert.Equal(t, "test-subject-123", claims.Subject, "subject is always populated")
			assert.Equalf(t, tc.wantEmail, claims.Email,
				"email must be populated only when email_verified is true")
		})
	}
}

func TestVerifyAndExtractClaims_NonceMismatch(t *testing.T) {
	// Critical anti-replay defence: an id_token that doesn't carry
	// the nonce the SSO handler issued in the auth request must
	// fail verification. Without this, a captured-and-replayed
	// id_token from another session could be accepted.
	f := newSignedOIDCFixture(t)
	p, err := idp.NewOIDCProvider(context.Background(), idp.ProviderConfig{
		IssuerURL:   f.srv.URL,
		ClientID:    "test-client",
		RedirectURL: "https://app.example.com/cb",
	})
	require.NoError(t, err)

	idToken := f.signIDToken(t, "test-client", "captured-nonce-from-other-session", nil)
	tok := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": idToken})

	_, err = p.VerifyAndExtractClaims(context.Background(), tok, "the-expected-nonce")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonce mismatch",
		"nonce mismatch must surface with the explicit 'nonce mismatch' message — operators rely on this string for anti-replay diagnostics")
}

func TestVerifyAndExtractClaims_NoIDToken(t *testing.T) {
	// An oauth2.Token without an id_token (e.g. a non-OIDC OAuth2
	// flow) must fail verification — we never want to silently
	// accept "the access_token must be valid because it exists".
	f := newSignedOIDCFixture(t)
	p, err := idp.NewOIDCProvider(context.Background(), idp.ProviderConfig{
		IssuerURL:   f.srv.URL,
		ClientID:    "test-client",
		RedirectURL: "https://app.example.com/cb",
	})
	require.NoError(t, err)

	tokWithoutID := &oauth2.Token{} // no id_token Extra
	_, err = p.VerifyAndExtractClaims(context.Background(), tokWithoutID, "any")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no id_token in token response")
}

func TestVerifyAndExtractClaims_InvalidSignature(t *testing.T) {
	// id_token signed with a different key (not in JWKS) must fail.
	f := newSignedOIDCFixture(t)
	p, err := idp.NewOIDCProvider(context.Background(), idp.ProviderConfig{
		IssuerURL:   f.srv.URL,
		ClientID:    "test-client",
		RedirectURL: "https://app.example.com/cb",
	})
	require.NoError(t, err)

	// Sign with a fresh key the fixture's JWKS doesn't publish.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: otherKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "rogue-key"),
	)
	require.NoError(t, err)
	now := time.Now()
	raw, err := jwt.Signed(signer).Claims(map[string]any{
		"iss":   f.srv.URL,
		"sub":   "test-subject",
		"aud":   "test-client",
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"nonce": "n",
	}).Serialize()
	require.NoError(t, err)

	tok := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": raw})
	_, err = p.VerifyAndExtractClaims(context.Background(), tok, "n")
	require.Error(t, err, "id_token signed by a non-JWKS key MUST fail verification")
	assert.Contains(t, err.Error(), "verify id_token")
}

// verifyProviderForFixture builds a provider bound to the fixture for the WS5
// #12 rejection tests.
func verifyProviderForFixture(t *testing.T, f *signedOIDCFixture) *idp.OIDCProvider {
	t.Helper()
	p, err := idp.NewOIDCProvider(context.Background(), idp.ProviderConfig{
		IssuerURL:   f.srv.URL,
		ClientID:    "test-client",
		RedirectURL: "https://app.example.com/cb",
	})
	require.NoError(t, err)
	return p
}

// TestVerifyAndExtractClaims_RejectsWrongAudience pins WS5 #12: an id_token
// minted for a DIFFERENT client (aud != ClientID) must be rejected — otherwise
// a token issued to another relying party could be replayed here.
func TestVerifyAndExtractClaims_RejectsWrongAudience(t *testing.T) {
	f := newSignedOIDCFixture(t)
	p := verifyProviderForFixture(t, f)
	idToken := f.signIDToken(t, "some-other-client", "n", map[string]any{"email_verified": true})
	tok := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": idToken})
	_, err := p.VerifyAndExtractClaims(context.Background(), tok, "n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify id_token")
}

// TestVerifyAndExtractClaims_RejectsExpired pins WS5 #12: an expired id_token is
// rejected (exp in the past).
func TestVerifyAndExtractClaims_RejectsExpired(t *testing.T) {
	f := newSignedOIDCFixture(t)
	p := verifyProviderForFixture(t, f)
	idToken := f.signIDToken(t, "test-client", "n", map[string]any{
		"exp": time.Now().Add(-1 * time.Hour).Unix(), // overrides the standard claim
	})
	tok := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": idToken})
	_, err := p.VerifyAndExtractClaims(context.Background(), tok, "n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify id_token")
}

// TestVerifyAndExtractClaims_RejectsWrongIssuer pins WS5 #12: an id_token whose
// iss is not this provider's issuer is rejected.
func TestVerifyAndExtractClaims_RejectsWrongIssuer(t *testing.T) {
	f := newSignedOIDCFixture(t)
	p := verifyProviderForFixture(t, f)
	idToken := f.signIDToken(t, "test-client", "n", map[string]any{
		"iss": "https://evil.example", // overrides the standard claim
	})
	tok := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": idToken})
	_, err := p.VerifyAndExtractClaims(context.Background(), tok, "n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify id_token")
}

// TestVerifyAndExtractClaims_ByteTamperedSignature pins WS5 #12: flipping a
// single character of a validly-signed token's signature segment is rejected —
// proving the signature BYTES are checked, not just the kid/structure (distinct
// from the wrong-key case above).
func TestVerifyAndExtractClaims_ByteTamperedSignature(t *testing.T) {
	f := newSignedOIDCFixture(t)
	p := verifyProviderForFixture(t, f)
	idToken := f.signIDToken(t, "test-client", "n", map[string]any{"email_verified": true})

	// JWS is header.payload.signature; tamper one char of the signature.
	// Mutate a NON-terminal char: the final base64url char of an RS256
	// signature carries only a couple of meaningful bits, so flipping it can
	// decode to the same bytes (a no-op that would let verification pass).
	// A mid-segment char always changes the decoded signature bytes.
	parts := strings.Split(idToken, ".")
	require.Len(t, parts, 3)
	sig := []byte(parts[2])
	require.Greater(t, len(sig), 2)
	idx := len(sig) / 2
	if sig[idx] == 'A' {
		sig[idx] = 'B'
	} else {
		sig[idx] = 'A'
	}
	parts[2] = string(sig)
	tampered := strings.Join(parts, ".")

	tok := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": tampered})
	_, err := p.VerifyAndExtractClaims(context.Background(), tok, "n")
	require.Error(t, err, "a byte-tampered signature MUST fail verification")
	assert.Contains(t, err.Error(), "verify id_token")
}
