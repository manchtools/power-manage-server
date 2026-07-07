package api_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// Spec 22 AC 7 — Device RPC freshness fields: last_inventory_at and
// inventory_overdue at the interval+grace boundary (default 1440 min +
// max(1h, 25%) grace = 30 h), computable while the device is offline,
// carried by the list path via one batched query.

func freshnessInsertInventory(t *testing.T, st *store.Store, deviceID string, collectedAt time.Time) {
	t.Helper()
	_, err := st.TestingPool().Exec(context.Background(),
		`INSERT INTO device_inventory (device_id, table_name, rows, collected_at)
		 VALUES ($1, 'system_info', '[]'::jsonb, $2)
		 ON CONFLICT (device_id, table_name) DO UPDATE SET collected_at = EXCLUDED.collected_at`,
		deviceID, collectedAt)
	require.NoError(t, err)
}

func TestGetDevice_InventoryFreshness_Boundary(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil, discardLogger(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "fresh-host")

	collected := time.Now().Truncate(time.Millisecond)
	freshnessInsertInventory(t, st, deviceID, collected)

	// Age just below interval+grace (30 h for the 1440-minute default).
	h.SetNowForTest(func() time.Time { return collected.Add(29 * time.Hour) })
	resp, err := h.GetDevice(ctx, connect.NewRequest(&pm.GetDeviceRequest{Id: deviceID}))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg.Device.LastInventoryAt, "last_inventory_at must be reported")
	assert.WithinDuration(t, collected, resp.Msg.Device.LastInventoryAt.AsTime(), time.Second)
	assert.False(t, resp.Msg.Device.InventoryOverdue, "age below interval+grace is not overdue")

	// Age just above interval+grace.
	h.SetNowForTest(func() time.Time { return collected.Add(31 * time.Hour) })
	resp, err = h.GetDevice(ctx, connect.NewRequest(&pm.GetDeviceRequest{Id: deviceID}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Device.InventoryOverdue, "age above interval+grace is overdue")
}

func TestGetDevice_InventoryOverdue_WhileOffline(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil, discardLogger(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "offline-host")

	now := time.Now()
	// Device far offline; inventory far past the threshold. Overdue is
	// computed from server-held policy, so it must trip regardless.
	_, err := st.TestingPool().Exec(context.Background(),
		"UPDATE devices_projection SET last_seen_at = $2 WHERE id = $1", deviceID, now.Add(-72*time.Hour))
	require.NoError(t, err)
	freshnessInsertInventory(t, st, deviceID, now.Add(-40*time.Hour))
	h.SetNowForTest(func() time.Time { return now })

	resp, err := h.GetDevice(ctx, connect.NewRequest(&pm.GetDeviceRequest{Id: deviceID}))
	require.NoError(t, err)
	assert.Equal(t, pm.DeviceStatus_DEVICE_STATUS_OFFLINE, resp.Msg.Device.Status)
	assert.True(t, resp.Msg.Device.InventoryOverdue, "overdue must be valid while the device is offline")
}

func TestGetDevice_NeverCollected_FreshEnrollmentNotOverdue(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil, discardLogger(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "new-host") // registered now, no inventory

	resp, err := h.GetDevice(ctx, connect.NewRequest(&pm.GetDeviceRequest{Id: deviceID}))
	require.NoError(t, err)
	assert.Nil(t, resp.Msg.Device.LastInventoryAt, "never-collected device has no last_inventory_at")
	assert.False(t, resp.Msg.Device.InventoryOverdue, "a fresh enrollment gets a full interval+grace window")

	// The same device far past the window without any collection IS overdue.
	h.SetNowForTest(func() time.Time { return time.Now().Add(31 * time.Hour) })
	resp, err = h.GetDevice(ctx, connect.NewRequest(&pm.GetDeviceRequest{Id: deviceID}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Device.InventoryOverdue, "an old never-collected device reads as collection-failing")
}

func TestListDevices_CarriesFreshnessFields(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil, discardLogger(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	now := time.Now()
	overdue := testutil.CreateTestDevice(t, st, "list-overdue")
	freshnessInsertInventory(t, st, overdue, now.Add(-40*time.Hour))
	fresh := testutil.CreateTestDevice(t, st, "list-fresh")
	freshnessInsertInventory(t, st, fresh, now.Add(-time.Hour))
	h.SetNowForTest(func() time.Time { return now })

	resp, err := h.ListDevices(ctx, connect.NewRequest(&pm.ListDevicesRequest{}))
	require.NoError(t, err)

	byID := make(map[string]*pm.Device)
	for _, d := range resp.Msg.Devices {
		byID[d.Id] = d
	}
	require.Contains(t, byID, overdue)
	require.Contains(t, byID, fresh)

	assert.True(t, byID[overdue].InventoryOverdue)
	require.NotNil(t, byID[overdue].LastInventoryAt)
	assert.False(t, byID[fresh].InventoryOverdue)
	require.NotNil(t, byID[fresh].LastInventoryAt)
	assert.WithinDuration(t, now.Add(-time.Hour), byID[fresh].LastInventoryAt.AsTime(), time.Second)
}
