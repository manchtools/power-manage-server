package api_test

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// loginForRefresh logs a fresh user in and returns the auth handler, the user's
// id, and a valid refresh token to exercise the RefreshToken revocation paths.
func loginForRefresh(t *testing.T, st *store.Store) (*api.AuthHandler, string, string) {
	t.Helper()
	h := api.NewAuthHandler(st, slog.Default(), testutil.NewJWTManager(), true)
	// A separate enabled admin so disabling/deleting the test user can't trip the
	// last-admin guard (which requires >=1 enabled admin to remain).
	testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	// The user under test is a non-admin.
	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "correct-password", "user")
	resp, err := h.Login(context.Background(), connect.NewRequest(&pm.LoginRequest{Email: email, Password: "correct-password"}))
	require.NoError(t, err)
	require.NotEmpty(t, resp.Msg.RefreshToken)
	return h, userID, resp.Msg.RefreshToken
}

// TestRefreshToken_SessionVersionMismatch_Rejected pins finding #4/#6: once a
// user's session_version is bumped (a role/permission change), a refresh token
// minted at the old version is rejected — the enforcement point for revocation.
func TestRefreshToken_SessionVersionMismatch_Rejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, userID, refresh := loginForRefresh(t, st)

	// Bump session_version out from under the issued token.
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  string(eventtypes.UserSessionInvalidated),
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userID,
	}))

	_, err := h.RefreshToken(context.Background(), connect.NewRequest(&pm.RefreshTokenRequest{RefreshToken: refresh}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

// TestRefreshToken_DisabledUser_Rejected: a disabled account can't refresh.
func TestRefreshToken_DisabledUser_Rejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, userID, refresh := loginForRefresh(t, st)

	userH := api.NewUserHandler(st, slog.Default(), nil)
	_, err := userH.SetUserDisabled(testutil.AdminContext(testutil.NewID()),
		connect.NewRequest(&pm.SetUserDisabledRequest{Id: userID, Disabled: true}))
	require.NoError(t, err)

	_, err = h.RefreshToken(context.Background(), connect.NewRequest(&pm.RefreshTokenRequest{RefreshToken: refresh}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

// TestRefreshToken_DeletedUser_Rejected: a deleted account can't refresh.
func TestRefreshToken_DeletedUser_Rejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, userID, refresh := loginForRefresh(t, st)

	userH := api.NewUserHandler(st, slog.Default(), nil)
	_, err := userH.DeleteUser(testutil.AdminContext(testutil.NewID()),
		connect.NewRequest(&pm.DeleteUserRequest{Id: userID}))
	require.NoError(t, err)

	_, err = h.RefreshToken(context.Background(), connect.NewRequest(&pm.RefreshTokenRequest{RefreshToken: refresh}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

// TestRefreshToken_SingleUse_SecondCallRejected pins that a refresh token is
// single-use: the first refresh revokes the old JTI, so replaying it fails.
func TestRefreshToken_SingleUse_SecondCallRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, _, refresh := loginForRefresh(t, st)

	first, err := h.RefreshToken(context.Background(), connect.NewRequest(&pm.RefreshTokenRequest{RefreshToken: refresh}))
	require.NoError(t, err, "first refresh must succeed")
	require.NotEmpty(t, first.Msg.RefreshToken)

	// Replaying the SAME (now-spent) token must be rejected.
	_, err = h.RefreshToken(context.Background(), connect.NewRequest(&pm.RefreshTokenRequest{RefreshToken: refresh}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}
