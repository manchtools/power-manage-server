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

func TestLogin_SetsCookies(t *testing.T) {
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

	cookies := resp.Header().Values("Set-Cookie")
	assert.Len(t, cookies, 2)
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
