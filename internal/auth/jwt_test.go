package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// algConfusionClaims builds a minimal valid access-token claims body for the
// alg-confusion tests. Only the signing algorithm varies between cases; the
// claims are always well-formed and unexpired so a failure can only be the
// signing-method rejection, never expiry/type.
func algConfusionClaims() *Claims {
	now := time.Now()
	return &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
			Issuer:    "test",
			Subject:   "user-1",
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		UserID:    "user-1",
		Email:     "a@b.com",
		TokenType: TokenTypeAccess,
	}
}

// TestValidateToken_RejectsAlgNone pins that a token whose header advertises
// alg:none (unsigned, RFC-7519 §6) is rejected. Issuance is always HS256, so
// an unsigned token is by definition forged. The "wrong" algorithm is sourced
// from intent (the literal `none` method), not from the keyfunc under test.
// Correct path is the HS256 token from GenerateTokens (covered elsewhere);
// this is the present-but-WRONG case.
func TestValidateToken_RejectsAlgNone(t *testing.T) {
	m := newTestJWTManager()

	tok, err := jwt.NewWithClaims(jwt.SigningMethodNone, algConfusionClaims()).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, err = m.ValidateToken(tok, TokenTypeAccess)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected signing method",
		"alg:none must be rejected on the HS256 signing-method pin, not on expiry/type")
}

// TestValidateToken_RejectsHSFamilyConfusion pins HS384/HS512 rejection EVEN
// THOUGH the same shared secret would verify them. Signing with the manager's
// own secret proves the pin is on token.Method != HS256, not merely on whether
// the secret matches.
func TestValidateToken_RejectsHSFamilyConfusion(t *testing.T) {
	m := newTestJWTManager()
	secret := []byte("test-secret-for-jwt") // the manager's own secret

	for _, method := range []*jwt.SigningMethodHMAC{jwt.SigningMethodHS384, jwt.SigningMethodHS512} {
		t.Run(method.Alg(), func(t *testing.T) {
			tok, err := jwt.NewWithClaims(method, algConfusionClaims()).SignedString(secret)
			require.NoError(t, err)

			_, err = m.ValidateToken(tok, TokenTypeAccess)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unexpected signing method",
				"%s signed with the real secret must still be rejected — the pin is on the method, not the key", method.Alg())
		})
	}
}

// TestValidateToken_RejectsRS256PublicKeyConfusion pins the classic RS↔HS
// algorithm-confusion attack: an RS256-signed token must be rejected, NOT
// verified by treating the HMAC secret as an RSA public key. The wrong
// algorithm is sourced from intent (issuance is always HS256), never from the
// keyfunc.
func TestValidateToken_RejectsRS256PublicKeyConfusion(t *testing.T) {
	m := newTestJWTManager()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tok, err := jwt.NewWithClaims(jwt.SigningMethodRS256, algConfusionClaims()).SignedString(key)
	require.NoError(t, err)

	_, err = m.ValidateToken(tok, TokenTypeAccess)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected signing method",
		"RS256 must be rejected on the signing-method pin, not silently treated as an HMAC key")
}

// decodeJWTPayload base64url-decodes the claims segment of a JWT so a
// test can assert on the raw wire shape (e.g. an omitempty claim's
// absence), not just the parsed struct.
func decodeJWTPayload(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	return string(payload)
}

func newTestJWTManager() *JWTManager {
	return NewJWTManager(JWTConfig{
		Secret:             []byte("test-secret-for-jwt"),
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 1 * time.Hour,
		Issuer:             "test",
	})
}

// TestGenerateTokens_TimestampsFromClock pins that token issue/expiry
// timestamps derive from the injected clock, not the wall clock. The
// clock is fixed in the PAST so the resulting tokens are already expired
// today — impossible if issuance read time.Now().
func TestGenerateTokens_TimestampsFromClock(t *testing.T) {
	fixed := time.Date(2020, 6, 1, 12, 0, 0, 0, time.UTC)
	m := NewJWTManager(JWTConfig{
		Secret:            []byte("test-secret-for-jwt"),
		AccessTokenExpiry: 15 * time.Minute,
		Issuer:            "test",
		Now:               func() time.Time { return fixed },
	})

	pair, err := m.GenerateTokens("uid", "e@x", nil, nil, 0)
	require.NoError(t, err)

	assert.True(t, pair.ExpiresAt.Equal(fixed.Add(15*time.Minute)),
		"access expiry must be clock+TTL; got %s want %s", pair.ExpiresAt, fixed.Add(15*time.Minute))
	assert.True(t, pair.ExpiresAt.Before(time.Now()),
		"tokens minted under a past clock are already expired, proving the timestamp is not from the wall clock")

	// The iat claim equals the injected clock. Decoded without validation,
	// since a past-clock token would otherwise fail expiry validation.
	payload := decodeJWTPayload(t, pair.AccessToken)
	assert.Contains(t, payload, fmt.Sprintf(`"iat":%d`, fixed.Unix()))
}

func TestNewJWTManager_Defaults(t *testing.T) {
	m := NewJWTManager(JWTConfig{Secret: []byte("s")})
	// Default access-token TTL is 5 min (audit F-01 follow-up —
	// see NewJWTManager comment). The shorter window bounds
	// permission-revocation staleness when SessionVersion isn't
	// bumped explicitly.
	assert.Equal(t, 5*time.Minute, m.config.AccessTokenExpiry)
	assert.Equal(t, 7*24*time.Hour, m.config.RefreshTokenExpiry)
	assert.Equal(t, "power-manage", m.config.Issuer)
}

func TestGenerateTokens(t *testing.T) {
	m := newTestJWTManager()

	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices", "GetUser:self"}, nil, 0)
	require.NoError(t, err)

	assert.NotEmpty(t, pair.AccessToken)
	assert.NotEmpty(t, pair.RefreshToken)
	assert.False(t, pair.ExpiresAt.IsZero())
	assert.True(t, pair.ExpiresAt.After(time.Now()))
	assert.NotEqual(t, pair.AccessToken, pair.RefreshToken)
}

func TestValidateToken_Access(t *testing.T) {
	m := newTestJWTManager()

	perms := []string{"ListDevices", "GetUser:self"}
	pair, err := m.GenerateTokens("user-1", "a@b.com", perms, nil, 5)
	require.NoError(t, err)

	claims, err := m.ValidateToken(pair.AccessToken, TokenTypeAccess)
	require.NoError(t, err)

	assert.Equal(t, "user-1", claims.UserID)
	assert.Equal(t, "a@b.com", claims.Email)
	assert.Equal(t, perms, claims.Permissions)
	assert.Equal(t, TokenTypeAccess, claims.TokenType)
	assert.Equal(t, int32(5), claims.SessionVersion)
	assert.Equal(t, "user-1", claims.Subject)
	assert.Equal(t, "test", claims.Issuer)
	assert.NotEmpty(t, claims.ID)
}

func TestValidateToken_ScopedGrantsRoundTrip(t *testing.T) {
	m := newTestJWTManager()

	grants := []ScopedGrant{
		{Permission: "StartTerminal"}, // global
		{Permission: "StartTerminal", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"}, // scoped
		{Permission: "GetUser", ScopeKind: ScopeKindUserGroup, ScopeID: "ug2"},
	}
	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"StartTerminal", "GetUser"}, grants, 0)
	require.NoError(t, err)

	claims, err := m.ValidateToken(pair.AccessToken, TokenTypeAccess)
	require.NoError(t, err)
	assert.Equal(t, grants, claims.ScopedGrants, "scoped grants must round-trip through the access token")
}

// An unscoped user (no scoped grants) gets a token with the claim
// omitted entirely — backward compatible with pre-#7 tokens.
func TestValidateToken_NoScopedGrantsOmitsClaim(t *testing.T) {
	m := newTestJWTManager()

	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, nil, 0)
	require.NoError(t, err)
	assert.NotContains(t, decodeJWTPayload(t, pair.AccessToken), "sgrants",
		"the sgrants claim must be omitted when there are no scoped grants")

	claims, err := m.ValidateToken(pair.AccessToken, TokenTypeAccess)
	require.NoError(t, err)
	assert.Nil(t, claims.ScopedGrants)
}

// Scoped grants, like permissions, must NOT be embedded in the refresh
// token.
func TestValidateToken_RefreshHasNoScopedGrants(t *testing.T) {
	m := newTestJWTManager()

	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"StartTerminal"},
		[]ScopedGrant{{Permission: "StartTerminal", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"}}, 0)
	require.NoError(t, err)

	claims, err := m.ValidateToken(pair.RefreshToken, TokenTypeRefresh)
	require.NoError(t, err)
	assert.Nil(t, claims.ScopedGrants, "refresh token must not carry scoped grants")
}

func TestValidateToken_RefreshHasNoPermissions(t *testing.T) {
	m := newTestJWTManager()

	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, nil, 0)
	require.NoError(t, err)

	claims, err := m.ValidateToken(pair.RefreshToken, TokenTypeRefresh)
	require.NoError(t, err)

	assert.Equal(t, "user-1", claims.UserID)
	assert.Equal(t, TokenTypeRefresh, claims.TokenType)
	assert.Nil(t, claims.Permissions, "refresh token should not contain permissions")
}

func TestValidateToken_WrongType(t *testing.T) {
	m := newTestJWTManager()

	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, nil, 0)
	require.NoError(t, err)

	// Access token validated as refresh should fail
	_, err = m.ValidateToken(pair.AccessToken, TokenTypeRefresh)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected token type")

	// Refresh token validated as access should fail
	_, err = m.ValidateToken(pair.RefreshToken, TokenTypeAccess)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected token type")
}

func TestValidateToken_WrongSecret(t *testing.T) {
	m1 := newTestJWTManager()
	m2 := NewJWTManager(JWTConfig{Secret: []byte("different-secret")})

	pair, err := m1.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, nil, 0)
	require.NoError(t, err)

	_, err = m2.ValidateToken(pair.AccessToken, TokenTypeAccess)
	assert.Error(t, err)
}

func TestValidateToken_Expired(t *testing.T) {
	m := NewJWTManager(JWTConfig{
		Secret:             []byte("test-secret"),
		AccessTokenExpiry:  1 * time.Millisecond,
		RefreshTokenExpiry: 1 * time.Millisecond,
	})

	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, nil, 0)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	_, err = m.ValidateToken(pair.AccessToken, TokenTypeAccess)
	assert.Error(t, err)
}

func TestValidateToken_Garbage(t *testing.T) {
	m := newTestJWTManager()

	_, err := m.ValidateToken("not.a.jwt", TokenTypeAccess)
	assert.Error(t, err)

	_, err = m.ValidateToken("", TokenTypeAccess)
	assert.Error(t, err)
}

func TestValidateRefreshToken_Success(t *testing.T) {
	m := newTestJWTManager()

	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, nil, 3)
	require.NoError(t, err)

	neverRevoked := func(jti string) (bool, error) { return false, nil }

	result, err := m.ValidateRefreshToken(pair.RefreshToken, neverRevoked)
	require.NoError(t, err)

	assert.Equal(t, "user-1", result.Claims.UserID)
	assert.Equal(t, "a@b.com", result.Claims.Email)
	assert.Equal(t, int32(3), result.Claims.SessionVersion)
	assert.NotEmpty(t, result.OldJTI)
}

func TestValidateRefreshToken_Revoked(t *testing.T) {
	m := newTestJWTManager()

	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, nil, 0)
	require.NoError(t, err)

	alwaysRevoked := func(jti string) (bool, error) { return true, nil }

	_, err = m.ValidateRefreshToken(pair.RefreshToken, alwaysRevoked)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

func TestValidateRefreshToken_WithAccessToken(t *testing.T) {
	m := newTestJWTManager()

	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, nil, 0)
	require.NoError(t, err)

	neverRevoked := func(jti string) (bool, error) { return false, nil }

	_, err = m.ValidateRefreshToken(pair.AccessToken, neverRevoked)
	assert.Error(t, err)
}

func TestValidateRefreshToken_NilCallback(t *testing.T) {
	m := newTestJWTManager()

	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, nil, 0)
	require.NoError(t, err)

	result, err := m.ValidateRefreshToken(pair.RefreshToken, nil)
	require.NoError(t, err)
	assert.Equal(t, "user-1", result.Claims.UserID)
}

func TestGenerateTokens_UniqueJTIs(t *testing.T) {
	m := newTestJWTManager()

	jtis := make(map[string]bool)
	for i := 0; i < 10; i++ {
		pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, nil, 0)
		require.NoError(t, err)

		accessClaims, err := m.ValidateToken(pair.AccessToken, TokenTypeAccess)
		require.NoError(t, err)
		assert.False(t, jtis[accessClaims.ID], "duplicate access JTI")
		jtis[accessClaims.ID] = true

		refreshClaims, err := m.ValidateToken(pair.RefreshToken, TokenTypeRefresh)
		require.NoError(t, err)
		assert.False(t, jtis[refreshClaims.ID], "duplicate refresh JTI")
		jtis[refreshClaims.ID] = true
	}
}
