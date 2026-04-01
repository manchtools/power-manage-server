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

func TestGetServerSettings_Defaults(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewSettingsHandler(st, slog.Default(), nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.GetServerSettings(ctx, connect.NewRequest(&pm.GetServerSettingsRequest{}))
	require.NoError(t, err)

	// Defaults should be false
	assert.False(t, resp.Msg.Settings.UserProvisioningEnabled)
	assert.False(t, resp.Msg.Settings.SshAccessForAll)
	assert.False(t, resp.Msg.Settings.AutoUpdateAgents)
}

func TestUpdateServerSettings_PersistsAndReturnsNewValues(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewSettingsHandler(st, slog.Default(), nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	// Update settings
	updateResp, err := h.UpdateServerSettings(ctx, connect.NewRequest(&pm.UpdateServerSettingsRequest{
		UserProvisioningEnabled: true,
		SshAccessForAll:         false,
		AutoUpdateAgents:        true,
	}))
	require.NoError(t, err)
	assert.True(t, updateResp.Msg.Settings.UserProvisioningEnabled)
	assert.False(t, updateResp.Msg.Settings.SshAccessForAll)
	assert.True(t, updateResp.Msg.Settings.AutoUpdateAgents)

	// Read back and verify persistence
	getResp, err := h.GetServerSettings(ctx, connect.NewRequest(&pm.GetServerSettingsRequest{}))
	require.NoError(t, err)
	assert.True(t, getResp.Msg.Settings.UserProvisioningEnabled)
	assert.False(t, getResp.Msg.Settings.SshAccessForAll)
	assert.True(t, getResp.Msg.Settings.AutoUpdateAgents)
}

func TestUpdateServerSettings_ToggleBackAndForth(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewSettingsHandler(st, slog.Default(), nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	// Enable SSH access
	_, err := h.UpdateServerSettings(ctx, connect.NewRequest(&pm.UpdateServerSettingsRequest{
		SshAccessForAll: true,
	}))
	require.NoError(t, err)

	resp, err := h.GetServerSettings(ctx, connect.NewRequest(&pm.GetServerSettingsRequest{}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Settings.SshAccessForAll)

	// Disable SSH access
	_, err = h.UpdateServerSettings(ctx, connect.NewRequest(&pm.UpdateServerSettingsRequest{
		SshAccessForAll: false,
	}))
	require.NoError(t, err)

	resp, err = h.GetServerSettings(ctx, connect.NewRequest(&pm.GetServerSettingsRequest{}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Settings.SshAccessForAll)
}
