package api_test

import (
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestCreateToken_Admin(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewTokenHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateToken(ctx, connect.NewRequest(&pm.CreateTokenRequest{
		Name: "Test Token",
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.Token.Id)
	assert.Equal(t, "Test Token", resp.Msg.Token.Name)
	assert.NotEmpty(t, resp.Msg.Token.Value) // Value only returned on creation
	// Admin omitted owner_id → ownerless token. Devices enrolled via
	// this token won't be auto-assigned to the admin who created it.
	assert.Empty(t, resp.Msg.Token.OwnerId)
}

func TestCreateToken_Admin_OwnerSelf(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewTokenHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateToken(ctx, connect.NewRequest(&pm.CreateTokenRequest{
		Name:    "Self-owned",
		OwnerId: adminID,
	}))
	require.NoError(t, err)
	assert.Equal(t, adminID, resp.Msg.Token.OwnerId)
}

func TestCreateToken_Admin_OwnerOtherUser(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewTokenHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	otherID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateToken(ctx, connect.NewRequest(&pm.CreateTokenRequest{
		Name:    "Owned by other",
		OwnerId: otherID,
	}))
	require.NoError(t, err)
	assert.Equal(t, otherID, resp.Msg.Token.OwnerId)
}

func TestCreateToken_Admin_OwnerNotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewTokenHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.CreateToken(ctx, connect.NewRequest(&pm.CreateTokenRequest{
		Name:    "Bad Owner",
		OwnerId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", // valid ULID, no such user
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestCreateToken_User(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewTokenHandler(st, slog.Default())

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	otherID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	ctx := testutil.UserContext(userID)

	// :self scope ignores any owner_id the caller passes — the token
	// is always owned by the creator. Pass another user's ID to prove
	// the server-side override holds.
	resp, err := h.CreateToken(ctx, connect.NewRequest(&pm.CreateTokenRequest{
		Name:    "User Token",
		OwnerId: otherID,
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Token.OneTime) // Non-admin tokens are always one-time
	assert.Equal(t, userID, resp.Msg.Token.OwnerId)
}

func TestGetToken(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewTokenHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	createResp, err := h.CreateToken(ctx, connect.NewRequest(&pm.CreateTokenRequest{
		Name: "Get Test",
	}))
	require.NoError(t, err)

	resp, err := h.GetToken(ctx, connect.NewRequest(&pm.GetTokenRequest{Id: createResp.Msg.Token.Id}))
	require.NoError(t, err)
	assert.Equal(t, createResp.Msg.Token.Id, resp.Msg.Token.Id)
	assert.Equal(t, "Get Test", resp.Msg.Token.Name)
	assert.Empty(t, resp.Msg.Token.Value) // Value not returned on get
}

func TestListTokens(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewTokenHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	for i := 0; i < 3; i++ {
		_, err := h.CreateToken(ctx, connect.NewRequest(&pm.CreateTokenRequest{
			Name: testutil.NewID(),
		}))
		require.NoError(t, err)
	}

	resp, err := h.ListTokens(ctx, connect.NewRequest(&pm.ListTokensRequest{}))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.Msg.Tokens), 3)
}

func TestRenameToken(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewTokenHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	createResp, err := h.CreateToken(ctx, connect.NewRequest(&pm.CreateTokenRequest{
		Name: "Old Name",
	}))
	require.NoError(t, err)

	resp, err := h.RenameToken(ctx, connect.NewRequest(&pm.RenameTokenRequest{
		Id:   createResp.Msg.Token.Id,
		Name: "New Name",
	}))
	require.NoError(t, err)
	assert.Equal(t, "New Name", resp.Msg.Token.Name)
}

func TestSetTokenDisabled(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewTokenHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	createResp, err := h.CreateToken(ctx, connect.NewRequest(&pm.CreateTokenRequest{
		Name: "Disable Test",
	}))
	require.NoError(t, err)

	resp, err := h.SetTokenDisabled(ctx, connect.NewRequest(&pm.SetTokenDisabledRequest{
		Id:       createResp.Msg.Token.Id,
		Disabled: true,
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Token.Disabled)

	resp, err = h.SetTokenDisabled(ctx, connect.NewRequest(&pm.SetTokenDisabledRequest{
		Id:       createResp.Msg.Token.Id,
		Disabled: false,
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Token.Disabled)
}

func TestDeleteToken(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewTokenHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	createResp, err := h.CreateToken(ctx, connect.NewRequest(&pm.CreateTokenRequest{
		Name: "Delete Test",
	}))
	require.NoError(t, err)

	_, err = h.DeleteToken(ctx, connect.NewRequest(&pm.DeleteTokenRequest{Id: createResp.Msg.Token.Id}))
	require.NoError(t, err)

	_, err = h.GetToken(ctx, connect.NewRequest(&pm.GetTokenRequest{Id: createResp.Msg.Token.Id}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}
