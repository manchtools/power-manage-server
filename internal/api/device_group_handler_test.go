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

func TestCreateDeviceGroup_Static(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateDeviceGroup(ctx, connect.NewRequest(&pm.CreateDeviceGroupRequest{
		Name: "Web Servers",
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.Group.Id)
	assert.Equal(t, "Web Servers", resp.Msg.Group.Name)
	assert.False(t, resp.Msg.Group.IsDynamic)
}

func TestGetDeviceGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Test Group")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.GetDeviceGroup(ctx, connect.NewRequest(&pm.GetDeviceGroupRequest{Id: groupID}))
	require.NoError(t, err)
	assert.Equal(t, groupID, resp.Msg.Group.Id)
	assert.Equal(t, "Test Group", resp.Msg.Group.Name)
}

func TestGetDeviceGroup_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.GetDeviceGroup(ctx, connect.NewRequest(&pm.GetDeviceGroupRequest{Id: testutil.NewID()}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestListDeviceGroups(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	for i := 0; i < 3; i++ {
		testutil.CreateTestDeviceGroup(t, st, adminID, testutil.NewID())
	}

	resp, err := h.ListDeviceGroups(ctx, connect.NewRequest(&pm.ListDeviceGroupsRequest{}))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.Msg.Groups), 3)
}

func TestRenameDeviceGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Old")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.RenameDeviceGroup(ctx, connect.NewRequest(&pm.RenameDeviceGroupRequest{
		Id:   groupID,
		Name: "New",
	}))
	require.NoError(t, err)
	assert.Equal(t, "New", resp.Msg.Group.Name)
}

func TestDeleteDeviceGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "To Delete")
	ctx := testutil.AdminContext(adminID)

	_, err := h.DeleteDeviceGroup(ctx, connect.NewRequest(&pm.DeleteDeviceGroupRequest{Id: groupID}))
	require.NoError(t, err)

	_, err = h.GetDeviceGroup(ctx, connect.NewRequest(&pm.GetDeviceGroupRequest{Id: groupID}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestAddDeviceToGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Members Group")
	deviceID := testutil.CreateTestDevice(t, st, "member-host")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.AddDeviceToGroup(ctx, connect.NewRequest(&pm.AddDeviceToGroupRequest{
		GroupId:  groupID,
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(1), resp.Msg.Group.MemberCount)
}

func TestRemoveDeviceFromGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Remove Group")
	deviceID := testutil.CreateTestDevice(t, st, "remove-host")
	ctx := testutil.AdminContext(adminID)

	// Add first
	_, err := h.AddDeviceToGroup(ctx, connect.NewRequest(&pm.AddDeviceToGroupRequest{
		GroupId:  groupID,
		DeviceId: deviceID,
	}))
	require.NoError(t, err)

	// Remove
	resp, err := h.RemoveDeviceFromGroup(ctx, connect.NewRequest(&pm.RemoveDeviceFromGroupRequest{
		GroupId:  groupID,
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(0), resp.Msg.Group.MemberCount)
}

func TestSetDeviceGroupSyncInterval(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Sync Group")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.SetDeviceGroupSyncInterval(ctx, connect.NewRequest(&pm.SetDeviceGroupSyncIntervalRequest{
		Id:                  groupID,
		SyncIntervalMinutes: 60,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(60), resp.Msg.Group.SyncIntervalMinutes)
}

func TestSetDeviceGroupMaintenanceWindow(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Window Group")
	ctx := testutil.AdminContext(adminID)

	// Set a window with two entries; the response carries the
	// projected schedule as proto so we can assert round-trip
	// fidelity end-to-end (handler → event → projector → query).
	resp, err := h.SetDeviceGroupMaintenanceWindow(ctx, connect.NewRequest(&pm.SetDeviceGroupMaintenanceWindowRequest{
		Id: groupID,
		MaintenanceWindow: &pm.MaintenanceWindow{Schedule: []*pm.MaintenanceWindowEntry{
			{Days: []string{"mon", "tue", "wed", "thu", "fri"}, Allow: "22:00-06:00"},
			{Days: []string{"sat", "sun"}, Allow: "00:00-23:59"},
		}},
	}))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg.Group.MaintenanceWindow)
	assert.Len(t, resp.Msg.Group.MaintenanceWindow.Schedule, 2)
	assert.Equal(t, "22:00-06:00", resp.Msg.Group.MaintenanceWindow.Schedule[0].Allow)

	// Clear the window — passing nil drops the schedule and the
	// projection's COALESCE should restore the empty default.
	clearResp, err := h.SetDeviceGroupMaintenanceWindow(ctx, connect.NewRequest(&pm.SetDeviceGroupMaintenanceWindowRequest{
		Id:                groupID,
		MaintenanceWindow: nil,
	}))
	require.NoError(t, err)
	assert.Nil(t, clearResp.Msg.Group.MaintenanceWindow,
		"cleared window must surface as nil (no constraint)")
}

func TestSetDeviceGroupMaintenanceWindow_InvalidEntryRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Window Group Bad")
	ctx := testutil.AdminContext(adminID)

	_, err := h.SetDeviceGroupMaintenanceWindow(ctx, connect.NewRequest(&pm.SetDeviceGroupMaintenanceWindowRequest{
		Id: groupID,
		MaintenanceWindow: &pm.MaintenanceWindow{Schedule: []*pm.MaintenanceWindowEntry{
			{Days: []string{"funday"}, Allow: "09:00-17:00"},
		}},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err),
		"validator should reject non-canonical weekday tokens at the boundary")
}

func TestValidateDynamicQuery(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.ValidateDynamicQuery(ctx, connect.NewRequest(&pm.ValidateDynamicQueryRequest{
		Query: `(device.labels.environment equals "production")`,
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Valid)
}
