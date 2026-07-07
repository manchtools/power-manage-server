package api_test

import (
	"context"
	"fmt"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// Spec 22 AC 1/4 — SetDeviceInventoryInterval handler coverage:
// correct / absent / malformed / out-of-range value, 0-as-inherit,
// unauthenticated, out-of-scope → PermissionDenied (WS3 mutation
// semantics), absent target → NotFound, event appended (audit).

func inventoryIntervalEventCount(t *testing.T, st *store.Store, streamType, streamID, eventType string) int {
	t.Helper()
	var n int
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		"SELECT count(*) FROM events WHERE stream_type=$1 AND stream_id=$2 AND event_type=$3",
		streamType, streamID, eventType).Scan(&n))
	return n
}

func TestSetDeviceInventoryInterval(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil, discardLogger(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "inv-host")

	resp, err := h.SetDeviceInventoryInterval(ctx, connect.NewRequest(&pm.SetDeviceInventoryIntervalRequest{
		Id:                       deviceID,
		InventoryIntervalMinutes: 240,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(240), resp.Msg.Device.InventoryIntervalMinutes)

	// AC 1: persisted as an event (audit-visible), projected onto the device projection.
	assert.Equal(t, 1, inventoryIntervalEventCount(t, st, "device", deviceID, "DeviceInventoryIntervalSet"))
	var projected int32
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		"SELECT inventory_interval_minutes FROM devices_projection WHERE id=$1", deviceID).Scan(&projected))
	assert.Equal(t, int32(240), projected)
}

func TestSetDeviceInventoryInterval_ZeroInherits(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil, discardLogger(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "inv-host")

	// Set an override first so 0 provably resets rather than "was already 0".
	_, err := h.SetDeviceInventoryInterval(ctx, connect.NewRequest(&pm.SetDeviceInventoryIntervalRequest{
		Id: deviceID, InventoryIntervalMinutes: 240,
	}))
	require.NoError(t, err)

	resp, err := h.SetDeviceInventoryInterval(ctx, connect.NewRequest(&pm.SetDeviceInventoryIntervalRequest{
		Id: deviceID, InventoryIntervalMinutes: 0,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(0), resp.Msg.Device.InventoryIntervalMinutes)
}

func TestSetDeviceInventoryInterval_OutOfRange(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil, discardLogger(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "inv-host")

	for _, minutes := range []int32{119, 10081, -5} {
		t.Run(fmt.Sprintf("minutes=%d", minutes), func(t *testing.T) {
			_, err := h.SetDeviceInventoryInterval(ctx, connect.NewRequest(&pm.SetDeviceInventoryIntervalRequest{
				Id: deviceID, InventoryIntervalMinutes: minutes,
			}))
			require.Error(t, err)
			assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
		})
	}
	// No event may leak from rejected requests.
	assert.Equal(t, 0, inventoryIntervalEventCount(t, st, "device", deviceID, "DeviceInventoryIntervalSet"))
}

func TestSetDeviceInventoryInterval_BadID(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil, discardLogger(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	for name, id := range map[string]string{"absent": "", "malformed": "not-a-ulid"} {
		t.Run(name, func(t *testing.T) {
			_, err := h.SetDeviceInventoryInterval(ctx, connect.NewRequest(&pm.SetDeviceInventoryIntervalRequest{
				Id: id, InventoryIntervalMinutes: 240,
			}))
			require.Error(t, err)
			assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
		})
	}
}

func TestSetDeviceInventoryInterval_DeviceNotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil, discardLogger(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.SetDeviceInventoryInterval(ctx, connect.NewRequest(&pm.SetDeviceInventoryIntervalRequest{
		Id: testutil.NewID(), InventoryIntervalMinutes: 240,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestSetDeviceInventoryInterval_Unauthenticated(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil, discardLogger(), api.NoOpSigner{})

	deviceID := testutil.CreateTestDevice(t, st, "inv-host")

	_, err := h.SetDeviceInventoryInterval(context.Background(), connect.NewRequest(&pm.SetDeviceInventoryIntervalRequest{
		Id: deviceID, InventoryIntervalMinutes: 240,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestSetDeviceInventoryInterval_OutOfScope_Denied(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil, discardLogger(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	dgA := testutil.CreateTestDeviceGroup(t, st, adminID, "Fleet A")
	dgB := testutil.CreateTestDeviceGroup(t, st, adminID, "Fleet B")
	deviceID := testutil.CreateTestDevice(t, st, "inv-host")
	testutil.AddDeviceToTestGroup(t, st, adminID, dgA, deviceID)

	// Caller scoped to a DIFFERENT group than the device belongs to.
	id, grants := scopedToGroup("scoped-admin", dgB, "SetDeviceInventoryInterval")
	ctx := testutil.AuthContextScoped(id, "s@test.com", []string{"SetDeviceInventoryInterval"}, grants)

	_, err := h.SetDeviceInventoryInterval(ctx, connect.NewRequest(&pm.SetDeviceInventoryIntervalRequest{
		Id: deviceID, InventoryIntervalMinutes: 240,
	}))
	require.Error(t, err)
	// Mutations on an out-of-scope device deny with PermissionDenied —
	// the WS3 behavior of the sync-interval template this RPC clones
	// (NotFound is the read-visibility code; see EnforceDeviceScope).
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

// --- SetDeviceGroupInventoryInterval (spec 22 AC 2/4) ---

func TestSetDeviceGroupInventoryInterval(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, discardLogger())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Inv Group")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.SetDeviceGroupInventoryInterval(ctx, connect.NewRequest(&pm.SetDeviceGroupInventoryIntervalRequest{
		Id:                       groupID,
		InventoryIntervalMinutes: 720,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(720), resp.Msg.Group.InventoryIntervalMinutes)

	// AC 2: persisted as an event, projected onto the group projection.
	assert.Equal(t, 1, inventoryIntervalEventCount(t, st, "device_group", groupID, "DeviceGroupInventoryIntervalSet"))
	var projected int32
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		"SELECT inventory_interval_minutes FROM device_groups_projection WHERE id=$1", groupID).Scan(&projected))
	assert.Equal(t, int32(720), projected)
}

func TestSetDeviceGroupInventoryInterval_ZeroInherits(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, discardLogger())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Inv Group")
	ctx := testutil.AdminContext(adminID)

	_, err := h.SetDeviceGroupInventoryInterval(ctx, connect.NewRequest(&pm.SetDeviceGroupInventoryIntervalRequest{
		Id: groupID, InventoryIntervalMinutes: 720,
	}))
	require.NoError(t, err)

	resp, err := h.SetDeviceGroupInventoryInterval(ctx, connect.NewRequest(&pm.SetDeviceGroupInventoryIntervalRequest{
		Id: groupID, InventoryIntervalMinutes: 0,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(0), resp.Msg.Group.InventoryIntervalMinutes)
}

func TestSetDeviceGroupInventoryInterval_OutOfRange(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, discardLogger())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Inv Group")
	ctx := testutil.AdminContext(adminID)

	for _, minutes := range []int32{119, 10081, -5} {
		t.Run(fmt.Sprintf("minutes=%d", minutes), func(t *testing.T) {
			_, err := h.SetDeviceGroupInventoryInterval(ctx, connect.NewRequest(&pm.SetDeviceGroupInventoryIntervalRequest{
				Id: groupID, InventoryIntervalMinutes: minutes,
			}))
			require.Error(t, err)
			assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
		})
	}
	assert.Equal(t, 0, inventoryIntervalEventCount(t, st, "device_group", groupID, "DeviceGroupInventoryIntervalSet"))
}

func TestSetDeviceGroupInventoryInterval_GroupNotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, discardLogger())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.SetDeviceGroupInventoryInterval(ctx, connect.NewRequest(&pm.SetDeviceGroupInventoryIntervalRequest{
		Id: testutil.NewID(), InventoryIntervalMinutes: 720,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestSetDeviceGroupInventoryInterval_Unauthenticated(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, discardLogger())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Inv Group")

	_, err := h.SetDeviceGroupInventoryInterval(context.Background(), connect.NewRequest(&pm.SetDeviceGroupInventoryIntervalRequest{
		Id: groupID, InventoryIntervalMinutes: 720,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestSetDeviceGroupInventoryInterval_OutOfScope_Denied(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, discardLogger())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	target := testutil.CreateTestDeviceGroup(t, st, adminID, "Target Group")
	other := testutil.CreateTestDeviceGroup(t, st, adminID, "Other Group")

	// Caller's grant covers a different group than the one being mutated.
	id, grants := scopedToGroup("scoped-admin", other, "SetDeviceGroupInventoryInterval")
	ctx := testutil.AuthContextScoped(id, "s@test.com", []string{"SetDeviceGroupInventoryInterval"}, grants)

	_, err := h.SetDeviceGroupInventoryInterval(ctx, connect.NewRequest(&pm.SetDeviceGroupInventoryIntervalRequest{
		Id: target, InventoryIntervalMinutes: 720,
	}))
	require.Error(t, err)
	// Mutations on an out-of-scope group deny with PermissionDenied —
	// the WS3 behavior of the sync-interval template this RPC clones.
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}
