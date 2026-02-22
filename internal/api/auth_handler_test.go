package api_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestLogin_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewAuthHandler(st, jwtMgr)

	email := testutil.NewID() + "@test.com"
	testutil.CreateTestUser(t, st, email, "correct-password", "admin")

	resp, err := h.Login(context.Background(), connect.NewRequest(&pm.LoginRequest{
		Email:    email,
		Password: "correct-password",
	}))
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Msg.AccessToken)
	assert.NotEmpty(t, resp.Msg.RefreshToken)
	assert.NotNil(t, resp.Msg.ExpiresAt)
	assert.NotNil(t, resp.Msg.User)
	assert.Equal(t, email, resp.Msg.User.Email)
}

func TestLogin_WrongPassword(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewAuthHandler(st, jwtMgr)

	email := testutil.NewID() + "@test.com"
	testutil.CreateTestUser(t, st, email, "correct-password", "user")

	_, err := h.Login(context.Background(), connect.NewRequest(&pm.LoginRequest{
		Email:    email,
		Password: "wrong-password",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestLogin_NonexistentUser(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewAuthHandler(st, jwtMgr)

	_, err := h.Login(context.Background(), connect.NewRequest(&pm.LoginRequest{
		Email:    "nonexistent@test.com",
		Password: "whatever",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestLogin_DisabledUser(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewAuthHandler(st, jwtMgr)

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")

	// Disable the user
	err := st.AppendEvent(context.Background(), testutil.DisableEvent(userID))
	require.NoError(t, err)

	_, err = h.Login(context.Background(), connect.NewRequest(&pm.LoginRequest{
		Email:    email,
		Password: "password",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestLogin_NoCookiesSet(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewAuthHandler(st, jwtMgr)

	email := testutil.NewID() + "@test.com"
	testutil.CreateTestUser(t, st, email, "password", "user")

	req := connect.NewRequest(&pm.LoginRequest{
		Email:    email,
		Password: "password",
	})
	req.Header().Set("Origin", "https://localhost:5173")

	resp, err := h.Login(context.Background(), req)
	require.NoError(t, err)

	// Verify tokens are returned in the response body
	assert.NotEmpty(t, resp.Msg.AccessToken)
	assert.NotEmpty(t, resp.Msg.RefreshToken)

	// Verify NO Set-Cookie headers are set (Bearer-only auth)
	cookies := resp.Header().Values("Set-Cookie")
	assert.Empty(t, cookies, "Login should not set any cookies")
}

func TestRefreshToken_RequiresBodyToken(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewAuthHandler(st, jwtMgr)

	// RefreshToken with empty body should fail.
	// Proto validation catches the empty refresh_token field.
	_, err := h.RefreshToken(context.Background(), connect.NewRequest(&pm.RefreshTokenRequest{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh_token")
}

func TestRefreshToken_NoCookieFallback(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewAuthHandler(st, jwtMgr)

	email := testutil.NewID() + "@test.com"
	testutil.CreateTestUser(t, st, email, "password", "user")

	// Login to get a valid refresh token
	loginResp, err := h.Login(context.Background(), connect.NewRequest(&pm.LoginRequest{
		Email:    email,
		Password: "password",
	}))
	require.NoError(t, err)

	// Send refresh token via cookie only (no body) — should fail.
	// Proto validation catches the empty refresh_token field first.
	req := connect.NewRequest(&pm.RefreshTokenRequest{})
	req.Header().Set("Cookie", "pm_refresh="+loginResp.Msg.RefreshToken)

	_, err = h.RefreshToken(context.Background(), req)
	require.Error(t, err)
	// Proto validation rejects the empty body before our handler runs
	assert.Contains(t, err.Error(), "refresh_token")
}

func TestRefreshToken_BodyToken(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewAuthHandler(st, jwtMgr)

	email := testutil.NewID() + "@test.com"
	testutil.CreateTestUser(t, st, email, "password", "user")

	// Login to get a valid refresh token
	loginResp, err := h.Login(context.Background(), connect.NewRequest(&pm.LoginRequest{
		Email:    email,
		Password: "password",
	}))
	require.NoError(t, err)

	// Send refresh token in body — should succeed
	refreshResp, err := h.RefreshToken(context.Background(), connect.NewRequest(&pm.RefreshTokenRequest{
		RefreshToken: loginResp.Msg.RefreshToken,
	}))
	require.NoError(t, err)

	assert.NotEmpty(t, refreshResp.Msg.AccessToken)
	assert.NotEmpty(t, refreshResp.Msg.RefreshToken)
	assert.NotNil(t, refreshResp.Msg.ExpiresAt)

	// Verify NO Set-Cookie headers
	cookies := refreshResp.Header().Values("Set-Cookie")
	assert.Empty(t, cookies, "RefreshToken should not set any cookies")
}

func TestLogout_NoCookiesCleared(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewAuthHandler(st, jwtMgr)

	email := testutil.NewID() + "@test.com"
	testutil.CreateTestUser(t, st, email, "password", "user")

	// Login to get a valid refresh token
	loginResp, err := h.Login(context.Background(), connect.NewRequest(&pm.LoginRequest{
		Email:    email,
		Password: "password",
	}))
	require.NoError(t, err)

	// Logout with refresh token in body
	logoutResp, err := h.Logout(context.Background(), connect.NewRequest(&pm.LogoutRequest{
		RefreshToken: loginResp.Msg.RefreshToken,
	}))
	require.NoError(t, err)

	// Verify NO Set-Cookie headers (no cookie clearing)
	cookies := logoutResp.Header().Values("Set-Cookie")
	assert.Empty(t, cookies, "Logout should not set any cookies")
}

func TestGetCurrentUser(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewAuthHandler(st, jwtMgr)

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "admin")
	ctx := auth.WithUser(context.Background(), &auth.UserContext{ID: userID, Email: email, Permissions: auth.AdminPermissions()})

	resp, err := h.GetCurrentUser(ctx, connect.NewRequest(&pm.GetCurrentUserRequest{}))
	require.NoError(t, err)

	assert.Equal(t, userID, resp.Msg.User.Id)
	assert.Equal(t, email, resp.Msg.User.Email)
}

func TestLogin_TOTPRequired(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	enc := testutil.NewEncryptor(t)
	h := api.NewAuthHandler(st, jwtMgr)

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")

	// Enable TOTP for the user
	testutil.SetupTOTP(t, st, enc, userID, email)

	// Login should return totp_required instead of tokens
	resp, err := h.Login(context.Background(), connect.NewRequest(&pm.LoginRequest{
		Email:    email,
		Password: "password",
	}))
	require.NoError(t, err)

	assert.True(t, resp.Msg.TotpRequired)
	assert.NotEmpty(t, resp.Msg.TotpChallenge)
	assert.Empty(t, resp.Msg.AccessToken, "should not return access token when TOTP is required")
	assert.Empty(t, resp.Msg.RefreshToken, "should not return refresh token when TOTP is required")
	assert.Nil(t, resp.Msg.User, "should not return user when TOTP is required")
}

func TestLogin_TOTPNotRequired(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewAuthHandler(st, jwtMgr)

	email := testutil.NewID() + "@test.com"
	testutil.CreateTestUser(t, st, email, "password", "user")

	// Login without TOTP should return tokens directly
	resp, err := h.Login(context.Background(), connect.NewRequest(&pm.LoginRequest{
		Email:    email,
		Password: "password",
	}))
	require.NoError(t, err)

	assert.False(t, resp.Msg.TotpRequired)
	assert.Empty(t, resp.Msg.TotpChallenge)
	assert.NotEmpty(t, resp.Msg.AccessToken)
	assert.NotEmpty(t, resp.Msg.RefreshToken)
	assert.NotNil(t, resp.Msg.User)
}

func TestLogin_PasswordDisabledByProvider(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewAuthHandler(st, jwtMgr)

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password", "user")

	// Create a provider with disable_password_for_linked=true
	providerID := testutil.NewID()
	err := st.AppendEvent(context.Background(), store.Event{
		StreamType: "identity_provider",
		StreamID:   providerID,
		EventType:  "IdentityProviderCreated",
		Data: map[string]any{
			"name":                        "Corporate SSO",
			"slug":                        "corporate",
			"provider_type":               "oidc",
			"client_id":                   "client-corp",
			"client_secret_encrypted":     "encrypted",
			"issuer_url":                  "https://corp.example.com",
			"enabled":                     true,
			"disable_password_for_linked": true,
		},
		ActorType: "system",
		ActorID:   "test",
	})
	require.NoError(t, err)

	// Link the user to this provider
	testutil.CreateTestIdentityLink(t, st, userID, providerID, "corp-ext-123", email)

	// Login with correct password should still be rejected
	_, err = h.Login(context.Background(), connect.NewRequest(&pm.LoginRequest{
		Email:    email,
		Password: "password",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "password login is disabled")
}

func TestLogin_SSOOnlyUserNoPassword(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewAuthHandler(st, jwtMgr)

	email := testutil.NewID() + "@test.com"
	userID := testutil.NewID()
	err := st.AppendEvent(context.Background(), testutil.SSOOnlyUserEvent(userID, email))
	require.NoError(t, err)

	// Login attempt should fail because user has no password
	_, err = h.Login(context.Background(), connect.NewRequest(&pm.LoginRequest{
		Email:    email,
		Password: "anything",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "password login is not available")
}

func TestLogin_UserHasPassword(t *testing.T) {
	st := testutil.SetupPostgres(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewAuthHandler(st, jwtMgr)

	email := testutil.NewID() + "@test.com"
	testutil.CreateTestUser(t, st, email, "password", "user")

	resp, err := h.Login(context.Background(), connect.NewRequest(&pm.LoginRequest{
		Email:    email,
		Password: "password",
	}))
	require.NoError(t, err)

	assert.True(t, resp.Msg.User.HasPassword)
}
