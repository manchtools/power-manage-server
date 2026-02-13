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

func TestCreateDeviceGroup_Static(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st)

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
	h := api.NewDeviceGroupHandler(st)

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
	h := api.NewDeviceGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.GetDeviceGroup(ctx, connect.NewRequest(&pm.GetDeviceGroupRequest{Id: testutil.NewID()}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestListDeviceGroups(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st)

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
	h := api.NewDeviceGroupHandler(st)

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
	h := api.NewDeviceGroupHandler(st)

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
	h := api.NewDeviceGroupHandler(st)

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
	h := api.NewDeviceGroupHandler(st)

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
	h := api.NewDeviceGroupHandler(st)

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

func TestValidateDynamicQuery(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.ValidateDynamicQuery(ctx, connect.NewRequest(&pm.ValidateDynamicQueryRequest{
		Query: `(device.labels.environment equals "production")`,
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Valid)
}
