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

func TestListDevices_Empty(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.ListDevices(ctx, connect.NewRequest(&pm.ListDevicesRequest{}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.Devices)
	assert.Equal(t, int32(0), resp.Msg.TotalCount)
}

func TestListDevices_WithDevices(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	for i := 0; i < 3; i++ {
		testutil.CreateTestDevice(t, st, testutil.NewID()+"-host")
	}

	resp, err := h.ListDevices(ctx, connect.NewRequest(&pm.ListDevicesRequest{}))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.Msg.Devices), 3)
}

func TestGetDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	resp, err := h.GetDevice(ctx, connect.NewRequest(&pm.GetDeviceRequest{Id: deviceID}))
	require.NoError(t, err)
	assert.Equal(t, deviceID, resp.Msg.Device.Id)
	assert.Equal(t, "test-host", resp.Msg.Device.Hostname)
}

func TestGetDevice_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.GetDevice(ctx, connect.NewRequest(&pm.GetDeviceRequest{Id: testutil.NewID()}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestSetDeviceLabel(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	resp, err := h.SetDeviceLabel(ctx, connect.NewRequest(&pm.SetDeviceLabelRequest{
		Id:    deviceID,
		Key:   "env",
		Value: "production",
	}))
	require.NoError(t, err)
	assert.Equal(t, "production", resp.Msg.Device.Labels["env"])
}

func TestRemoveDeviceLabel(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	// Set label first
	_, err := h.SetDeviceLabel(ctx, connect.NewRequest(&pm.SetDeviceLabelRequest{
		Id:    deviceID,
		Key:   "env",
		Value: "staging",
	}))
	require.NoError(t, err)

	// Remove it
	resp, err := h.RemoveDeviceLabel(ctx, connect.NewRequest(&pm.RemoveDeviceLabelRequest{
		Id:  deviceID,
		Key: "env",
	}))
	require.NoError(t, err)
	assert.NotContains(t, resp.Msg.Device.Labels, "env")
}

func TestDeleteDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	deviceID := testutil.CreateTestDevice(t, st, "to-delete")

	_, err := h.DeleteDevice(ctx, connect.NewRequest(&pm.DeleteDeviceRequest{Id: deviceID}))
	require.NoError(t, err)

	_, err = h.GetDevice(ctx, connect.NewRequest(&pm.GetDeviceRequest{Id: deviceID}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestAssignDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	ctx := testutil.AdminContext(adminID)

	deviceID := testutil.CreateTestDevice(t, st, "assign-host")

	resp, err := h.AssignDevice(ctx, connect.NewRequest(&pm.AssignDeviceRequest{
		DeviceId: deviceID,
		UserId:   userID,
	}))
	require.NoError(t, err)
	assert.Equal(t, userID, resp.Msg.Device.AssignedUserId)
}

func TestUnassignDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	ctx := testutil.AdminContext(adminID)

	deviceID := testutil.CreateTestDevice(t, st, "unassign-host")

	// Assign first
	_, err := h.AssignDevice(ctx, connect.NewRequest(&pm.AssignDeviceRequest{
		DeviceId: deviceID,
		UserId:   userID,
	}))
	require.NoError(t, err)

	// Unassign
	resp, err := h.UnassignDevice(ctx, connect.NewRequest(&pm.UnassignDeviceRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.Device.AssignedUserId)
}

func TestSetDeviceSyncInterval(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	deviceID := testutil.CreateTestDevice(t, st, "sync-host")

	resp, err := h.SetDeviceSyncInterval(ctx, connect.NewRequest(&pm.SetDeviceSyncIntervalRequest{
		Id:                  deviceID,
		SyncIntervalMinutes: 30,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(30), resp.Msg.Device.SyncIntervalMinutes)
}
