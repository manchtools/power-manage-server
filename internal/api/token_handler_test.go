package api_test

import (
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
	h := api.NewTokenHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateToken(ctx, connect.NewRequest(&pm.CreateTokenRequest{
		Name: "Test Token",
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.Token.Id)
	assert.Equal(t, "Test Token", resp.Msg.Token.Name)
	assert.NotEmpty(t, resp.Msg.Token.Value) // Value only returned on creation
}

func TestCreateToken_User(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewTokenHandler(st)

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	ctx := testutil.UserContext(userID)

	resp, err := h.CreateToken(ctx, connect.NewRequest(&pm.CreateTokenRequest{
		Name: "User Token",
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Token.OneTime) // Non-admin tokens are always one-time
}

func TestGetToken(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewTokenHandler(st)

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
	h := api.NewTokenHandler(st)

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
	h := api.NewTokenHandler(st)

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
	h := api.NewTokenHandler(st)

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
	h := api.NewTokenHandler(st)

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
