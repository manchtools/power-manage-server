package projectors_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// Spec 22 — projector coverage for DeviceInventoryIntervalSet /
// DeviceGroupInventoryIntervalSet: pure decode (explicit / missing key /
// wrong stream) and end-to-end projection against real Postgres.

func TestDeviceInventoryIntervalSetFromEvent_Pure(t *testing.T) {
	t.Run("explicit value", func(t *testing.T) {
		got, err := projectors.DeviceInventoryIntervalSetFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceInventoryIntervalSet",
			Data: jsonOrFail(t, map[string]any{"inventory_interval_minutes": 240}),
		})
		require.NoError(t, err)
		assert.Equal(t, int32(240), got.InventoryIntervalMinutes)
	})

	t.Run("missing key → 0", func(t *testing.T) {
		got, err := projectors.DeviceInventoryIntervalSetFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceInventoryIntervalSet",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Equal(t, int32(0), got.InventoryIntervalMinutes)
	})

	t.Run("wrong stream type → ignored", func(t *testing.T) {
		_, err := projectors.DeviceInventoryIntervalSetFromEvent(store.PersistedEvent{
			StreamType: "device_group", EventType: "DeviceInventoryIntervalSet",
		})
		assert.ErrorIs(t, err, projectors.ErrIgnoredEvent)
	})

	t.Run("invalid payload → error", func(t *testing.T) {
		_, err := projectors.DeviceInventoryIntervalSetFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceInventoryIntervalSet",
			Data: []byte("{not-json"),
		})
		assert.Error(t, err)
	})
}

func TestDeviceGroupInventoryIntervalSetFromEvent_Pure(t *testing.T) {
	t.Run("explicit value", func(t *testing.T) {
		got, err := projectors.DeviceGroupInventoryIntervalSetFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupInventoryIntervalSet",
			Data: jsonOrFail(t, map[string]any{"inventory_interval_minutes": 720}),
		})
		require.NoError(t, err)
		assert.Equal(t, int32(720), got.InventoryIntervalMinutes)
	})

	t.Run("missing key → 0", func(t *testing.T) {
		got, err := projectors.DeviceGroupInventoryIntervalSetFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupInventoryIntervalSet",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Equal(t, int32(0), got.InventoryIntervalMinutes)
	})

	t.Run("wrong stream type → ignored", func(t *testing.T) {
		_, err := projectors.DeviceGroupInventoryIntervalSetFromEvent(store.PersistedEvent{
			StreamType: "device", EventType: "DeviceGroupInventoryIntervalSet",
		})
		assert.ErrorIs(t, err, projectors.ErrIgnoredEvent)
	})
}

// TestDeviceListener_InventoryIntervalSet drives the event through the
// real listener into devices_projection, including the reset-to-0 path.
func TestDeviceListener_InventoryIntervalSet(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	deviceID := testutil.NewID()
	registerDeviceForTest(t, st, ctx, deviceID, "inv-lifecycle")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceInventoryIntervalSet",
		Data:      map[string]any{"inventory_interval_minutes": 240},
		ActorType: "user", ActorID: "u",
	}))
	got, err := st.Queries().GetDeviceByID(ctx, deviceLookup(deviceID))
	require.NoError(t, err)
	assert.Equal(t, int32(240), got.InventoryIntervalMinutes)

	// Reset to inherit.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceInventoryIntervalSet",
		Data:      map[string]any{"inventory_interval_minutes": 0},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetDeviceByID(ctx, deviceLookup(deviceID))
	require.NoError(t, err)
	assert.Equal(t, int32(0), got.InventoryIntervalMinutes)
}

// TestDeviceGroupListener_InventoryIntervalSet mirrors the device test
// for device_groups_projection.
func TestDeviceGroupListener_InventoryIntervalSet(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupCreated",
		Data:      map[string]any{"name": "inv-group", "description": ""},
		ActorType: "user", ActorID: "u-1",
	}))

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupInventoryIntervalSet",
		Data:      map[string]any{"inventory_interval_minutes": 720},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err := st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(720), got.InventoryIntervalMinutes)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupInventoryIntervalSet",
		Data:      map[string]any{"inventory_interval_minutes": 0},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err = st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), got.InventoryIntervalMinutes)
}
