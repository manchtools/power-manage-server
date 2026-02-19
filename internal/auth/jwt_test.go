package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestJWTManager() *JWTManager {
	return NewJWTManager(JWTConfig{
		Secret:             []byte("test-secret-for-jwt"),
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 1 * time.Hour,
		Issuer:             "test",
	})
}

func TestNewJWTManager_Defaults(t *testing.T) {
	m := NewJWTManager(JWTConfig{Secret: []byte("s")})
	assert.Equal(t, 15*time.Minute, m.config.AccessTokenExpiry)
	assert.Equal(t, 7*24*time.Hour, m.config.RefreshTokenExpiry)
	assert.Equal(t, "power-manage", m.config.Issuer)
}

func TestGenerateTokens(t *testing.T) {
	m := newTestJWTManager()

	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices", "GetUser:self"}, 0)
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
	pair, err := m.GenerateTokens("user-1", "a@b.com", perms, 5)
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

func TestValidateToken_RefreshHasNoPermissions(t *testing.T) {
	m := newTestJWTManager()

	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, 0)
	require.NoError(t, err)

	claims, err := m.ValidateToken(pair.RefreshToken, TokenTypeRefresh)
	require.NoError(t, err)

	assert.Equal(t, "user-1", claims.UserID)
	assert.Equal(t, TokenTypeRefresh, claims.TokenType)
	assert.Nil(t, claims.Permissions, "refresh token should not contain permissions")
}

func TestValidateToken_WrongType(t *testing.T) {
	m := newTestJWTManager()

	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, 0)
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

	pair, err := m1.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, 0)
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

	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, 0)
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

	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, 3)
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

	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, 0)
	require.NoError(t, err)

	alwaysRevoked := func(jti string) (bool, error) { return true, nil }

	_, err = m.ValidateRefreshToken(pair.RefreshToken, alwaysRevoked)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

func TestValidateRefreshToken_WithAccessToken(t *testing.T) {
	m := newTestJWTManager()

	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, 0)
	require.NoError(t, err)

	neverRevoked := func(jti string) (bool, error) { return false, nil }

	_, err = m.ValidateRefreshToken(pair.AccessToken, neverRevoked)
	assert.Error(t, err)
}

func TestValidateRefreshToken_NilCallback(t *testing.T) {
	m := newTestJWTManager()

	pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, 0)
	require.NoError(t, err)

	result, err := m.ValidateRefreshToken(pair.RefreshToken, nil)
	require.NoError(t, err)
	assert.Equal(t, "user-1", result.Claims.UserID)
}

func TestGenerateTokens_UniqueJTIs(t *testing.T) {
	m := newTestJWTManager()

	jtis := make(map[string]bool)
	for i := 0; i < 10; i++ {
		pair, err := m.GenerateTokens("user-1", "a@b.com", []string{"ListDevices"}, 0)
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
