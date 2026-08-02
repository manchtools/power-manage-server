package auth_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/auth"
)

func newManager(t *testing.T, now time.Time) (*auth.JWTManager, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := auth.GenerateSessionKey()
	require.NoError(t, err)
	m, err := auth.NewJWTManager(auth.JWTConfig{
		PrivateKey: priv,
		Now:        func() time.Time { return now },
	})
	require.NoError(t, err)
	return m, priv
}

func TestJWTManager_RefusesToBuildWithoutAKey(t *testing.T) {
	t.Parallel()
	_, err := auth.NewJWTManager(auth.JWTConfig{})
	assert.ErrorIs(t, err, auth.ErrNoSigningKey,
		"a manager with no key could neither sign nor verify; failing at startup beats failing per request")

	_, err = auth.NewJWTManager(auth.JWTConfig{PrivateKey: ed25519.PrivateKey("too short")})
	assert.ErrorIs(t, err, auth.ErrNoSigningKey)
}

func TestSessionTokens_AreSignedWithEdDSA(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	m, _ := newManager(t, now)

	pair, err := m.GenerateTokens("01J0000000000000000000000A", "person@test.example",
		[]string{"ListUsers"}, []auth.ScopedGrant{{Permission: "ListUsers"}}, 3)
	require.NoError(t, err)

	assert.Equal(t, "EdDSA", tokenAlg(t, pair.AccessToken),
		"Ed25519 is the one signature algorithm in this system")
	assert.Equal(t, "EdDSA", tokenAlg(t, pair.RefreshToken))

	claims, err := m.ValidateToken(pair.AccessToken, auth.TokenTypeAccess)
	require.NoError(t, err)
	assert.Equal(t, "01J0000000000000000000000A", claims.UserID)
	assert.Equal(t, []string{"ListUsers"}, claims.Permissions)
	assert.Equal(t, int32(3), claims.SessionVersion)
	assert.Equal(t, now.Add(auth.DefaultAccessTokenExpiry).Unix(), claims.ExpiresAt.Unix())

	// The refresh token carries identity, never authority: the
	// permissions it would grant are re-read at refresh time.
	refresh, err := m.ValidateToken(pair.RefreshToken, auth.TokenTypeRefresh)
	require.NoError(t, err)
	assert.Empty(t, refresh.Permissions)
	assert.Empty(t, refresh.ScopedGrants)
}

func TestValidateToken_RefusesAnotherKeysSignature(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	m, _ := newManager(t, now)
	other, _ := newManager(t, now)

	pair, err := other.GenerateTokens("01J0000000000000000000000A", "person@test.example", nil, nil, 0)
	require.NoError(t, err)

	_, err = m.ValidateToken(pair.AccessToken, auth.TokenTypeAccess)
	assert.Error(t, err, "a token signed by an unknown key must never validate")
}

// The classic algorithm-substitution forgery: an attacker who knows the
// public key resigns the token as HMAC and hopes the verifier hands the
// public key over as a shared secret.
func TestValidateToken_RefusesAnAlgorithmSubstitution(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	pub, priv, err := auth.GenerateSessionKey()
	require.NoError(t, err)
	m, err := auth.NewJWTManager(auth.JWTConfig{
		PrivateKey: priv, Now: func() time.Time { return now },
	})
	require.NoError(t, err)

	claims := &auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "01J0000000000000000000000B",
			Issuer:    auth.DefaultIssuer,
			Subject:   "01J0000000000000000000000A",
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		UserID:      "01J0000000000000000000000A",
		Permissions: []string{"EraseJITUser"},
		TokenType:   auth.TokenTypeAccess,
	}
	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(pub))
	require.NoError(t, err)

	_, err = m.ValidateToken(forged, auth.TokenTypeAccess)
	assert.Error(t, err, "the public key must never be accepted as an HMAC secret")

	// And the unsigned "alg: none" variant.
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	_, err = m.ValidateToken(unsigned, auth.TokenTypeAccess)
	assert.Error(t, err)
}

func TestValidateToken_RefusesTheWrongTokenType(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	m, _ := newManager(t, now)
	pair, err := m.GenerateTokens("01J0000000000000000000000A", "person@test.example", nil, nil, 0)
	require.NoError(t, err)

	_, err = m.ValidateToken(pair.RefreshToken, auth.TokenTypeAccess)
	assert.Error(t, err, "a refresh token is not a bearer credential for the API")
	_, err = m.ValidateToken(pair.AccessToken, auth.TokenTypeRefresh)
	assert.Error(t, err)
}

func TestValidateToken_RefusesAnExpiredTokenWithADistinguishableError(t *testing.T) {
	t.Parallel()
	issued := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	m, priv := newManager(t, issued)
	pair, err := m.GenerateTokens("01J0000000000000000000000A", "person@test.example", nil, nil, 0)
	require.NoError(t, err)

	later, err := auth.NewJWTManager(auth.JWTConfig{
		PrivateKey: priv,
		Now:        func() time.Time { return issued.Add(2 * auth.DefaultAccessTokenExpiry) },
	})
	require.NoError(t, err)

	_, err = later.ValidateToken(pair.AccessToken, auth.TokenTypeAccess)
	require.Error(t, err)
	assert.ErrorIs(t, err, jwt.ErrTokenExpired,
		"expiry is distinguishable so a client can refresh instead of forcing a re-login")
}

func TestValidateToken_RefusesAnotherIssuer(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	_, priv, err := auth.GenerateSessionKey()
	require.NoError(t, err)

	foreign, err := auth.NewJWTManager(auth.JWTConfig{
		PrivateKey: priv, Issuer: "somebody-else", Now: func() time.Time { return now },
	})
	require.NoError(t, err)
	ours, err := auth.NewJWTManager(auth.JWTConfig{
		PrivateKey: priv, Now: func() time.Time { return now },
	})
	require.NoError(t, err)

	pair, err := foreign.GenerateTokens("01J0000000000000000000000A", "person@test.example", nil, nil, 0)
	require.NoError(t, err)
	_, err = ours.ValidateToken(pair.AccessToken, auth.TokenTypeAccess)
	assert.Error(t, err, "a token minted for another deployment must not validate here")
}

func TestValidateRefreshToken_ConsultsTheRevocationList(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	m, _ := newManager(t, now)
	pair, err := m.GenerateTokens("01J0000000000000000000000A", "person@test.example", nil, nil, 0)
	require.NoError(t, err)

	result, err := m.ValidateRefreshToken(pair.RefreshToken, func(string) (bool, error) { return false, nil })
	require.NoError(t, err)
	assert.NotEmpty(t, result.OldJTI)

	_, err = m.ValidateRefreshToken(pair.RefreshToken, func(string) (bool, error) { return true, nil })
	assert.Error(t, err, "a revoked refresh token is dead even though its signature verifies")
}

// tokenAlg reads the `alg` header of a JWT without validating it.
func tokenAlg(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header struct {
		Alg string `json:"alg"`
	}
	require.NoError(t, json.Unmarshal(raw, &header))
	return header.Alg
}

// The token ids are ULIDs minted from the cryptographic random source,
// so two tokens issued in the same instant still differ.
func TestSessionTokens_CarryDistinctULIDIdentifiers(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	m, _ := newManager(t, now)

	seen := make(map[string]bool)
	for i := 0; i < 25; i++ {
		pair, err := m.GenerateTokens("01J0000000000000000000000A", "person@test.example", nil, nil, 0)
		require.NoError(t, err)
		access, err := m.ValidateToken(pair.AccessToken, auth.TokenTypeAccess)
		require.NoError(t, err)
		refresh, err := m.ValidateToken(pair.RefreshToken, auth.TokenTypeRefresh)
		require.NoError(t, err)
		for _, id := range []string{access.ID, refresh.ID} {
			assert.Len(t, id, 26, "a token id is a ULID")
			assert.False(t, seen[id], "token id %s was issued twice", id)
			seen[id] = true
		}
	}
	require.Len(t, seen, 50)
}

var _ = rand.Reader
