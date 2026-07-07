package store_test

// Spec 22 AC 3 / 5 / 6 — SQL-level coverage for the inventory-interval
// resolution (device override > group MIN > default, 0 inherits at each
// level) and the scheduler's stale-device feed. The resolution
// expression is embedded in BOTH ListDeviceInventoryFreshnessBatch and
// ListStaleInventoryDevices; the resolution subtests run against both
// so the two copies cannot drift apart.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

const testDefaultInventoryInterval = int32(1440)

// setDeviceInventoryInterval / setGroupInventoryInterval drive the
// policy through the real event pipeline (projector included).
func setDeviceInventoryInterval(t *testing.T, st *store.Store, deviceID string, minutes int32) {
	t.Helper()
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceInventoryIntervalSet",
		Data:      map[string]any{"inventory_interval_minutes": minutes},
		ActorType: "user", ActorID: "u",
	}))
}

func setGroupInventoryInterval(t *testing.T, st *store.Store, groupID string, minutes int32) {
	t.Helper()
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupInventoryIntervalSet",
		Data:      map[string]any{"inventory_interval_minutes": minutes},
		ActorType: "user", ActorID: "u",
	}))
}

// resolvedInterval reads the effective interval for one device via the
// freshness batch query.
func resolvedInterval(t *testing.T, st *store.Store, deviceID string) int32 {
	t.Helper()
	rows, err := st.Queries().ListDeviceInventoryFreshnessBatch(context.Background(),
		db.ListDeviceInventoryFreshnessBatchParams{
			DefaultIntervalMinutes: testDefaultInventoryInterval,
			DeviceIds:              []string{deviceID},
		})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	return rows[0].ResolvedIntervalMinutes
}

// insertInventory writes a device_inventory row with a pinned
// collected_at (the table is operational, not event-sourced).
func insertInventory(t *testing.T, st *store.Store, deviceID string, collectedAt time.Time) {
	t.Helper()
	_, err := st.TestingPool().Exec(context.Background(),
		`INSERT INTO device_inventory (device_id, table_name, rows, collected_at)
		 VALUES ($1, 'system_info', '[]'::jsonb, $2)
		 ON CONFLICT (device_id, table_name) DO UPDATE SET collected_at = EXCLUDED.collected_at`,
		deviceID, collectedAt)
	require.NoError(t, err)
}

// markSeen pins last_seen_at directly (heartbeats do this in prod).
func markSeen(t *testing.T, st *store.Store, deviceID string, at time.Time) {
	t.Helper()
	_, err := st.TestingPool().Exec(context.Background(),
		"UPDATE devices_projection SET last_seen_at = $2 WHERE id = $1", deviceID, at)
	require.NoError(t, err)
}

func staleDevices(t *testing.T, st *store.Store, now time.Time) []string {
	t.Helper()
	ids, err := st.Queries().ListStaleInventoryDevices(context.Background(),
		db.ListStaleInventoryDevicesParams{
			SeenSince:              pgtype.Timestamptz{Time: now.Add(-15 * time.Minute), Valid: true},
			DefaultIntervalMinutes: testDefaultInventoryInterval,
			Now:                    pgtype.Timestamptz{Time: now, Valid: true},
		})
	require.NoError(t, err)
	return ids
}

func TestInventoryIntervalResolution(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")

	t.Run("default when nothing set", func(t *testing.T) {
		d := testutil.CreateTestDevice(t, st, "res-default")
		assert.Equal(t, testDefaultInventoryInterval, resolvedInterval(t, st, d))
	})

	t.Run("device override wins over group", func(t *testing.T) {
		d := testutil.CreateTestDevice(t, st, "res-override")
		g := testutil.CreateTestDeviceGroup(t, st, adminID, "res-g1-"+testutil.NewID()[:8])
		testutil.AddDeviceToTestGroup(t, st, adminID, g, d)
		setGroupInventoryInterval(t, st, g, 480)
		setDeviceInventoryInterval(t, st, d, 240)
		assert.Equal(t, int32(240), resolvedInterval(t, st, d))
	})

	t.Run("group MIN across multiple groups", func(t *testing.T) {
		d := testutil.CreateTestDevice(t, st, "res-min")
		g1 := testutil.CreateTestDeviceGroup(t, st, adminID, "res-g2-"+testutil.NewID()[:8])
		g2 := testutil.CreateTestDeviceGroup(t, st, adminID, "res-g3-"+testutil.NewID()[:8])
		testutil.AddDeviceToTestGroup(t, st, adminID, g1, d)
		testutil.AddDeviceToTestGroup(t, st, adminID, g2, d)
		setGroupInventoryInterval(t, st, g1, 720)
		setGroupInventoryInterval(t, st, g2, 360)
		assert.Equal(t, int32(360), resolvedInterval(t, st, d))
	})

	t.Run("zero inherits at each level", func(t *testing.T) {
		d := testutil.CreateTestDevice(t, st, "res-zero")
		g := testutil.CreateTestDeviceGroup(t, st, adminID, "res-g4-"+testutil.NewID()[:8])
		testutil.AddDeviceToTestGroup(t, st, adminID, g, d)
		// Device 0 + group 0 → default.
		setDeviceInventoryInterval(t, st, d, 0)
		setGroupInventoryInterval(t, st, g, 0)
		assert.Equal(t, testDefaultInventoryInterval, resolvedInterval(t, st, d))
		// Device 0 + group set → group.
		setGroupInventoryInterval(t, st, g, 600)
		assert.Equal(t, int32(600), resolvedInterval(t, st, d))
	})
}

// TestInventoryIntervalResolution_StaleQueryAgrees pins the second copy
// of the resolution expression (ListStaleInventoryDevices) to the same
// semantics: a device with a 240-minute override and 300-minute-old
// inventory is stale; with a 480-minute group interval it is not.
func TestInventoryIntervalResolution_StaleQueryAgrees(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	now := time.Now()

	d := testutil.CreateTestDevice(t, st, "agree-host")
	g := testutil.CreateTestDeviceGroup(t, st, adminID, "agree-g-"+testutil.NewID()[:8])
	testutil.AddDeviceToTestGroup(t, st, adminID, g, d)
	markSeen(t, st, d, now)
	insertInventory(t, st, d, now.Add(-300*time.Minute))

	// Group interval 480 → 300-minute-old inventory is fresh.
	setGroupInventoryInterval(t, st, g, 480)
	assert.NotContains(t, staleDevices(t, st, now), d)

	// Device override 240 wins → the same inventory is now stale.
	setDeviceInventoryInterval(t, st, d, 240)
	assert.Contains(t, staleDevices(t, st, now), d)
}

func TestListStaleInventoryDevices(t *testing.T) {
	st := testutil.SetupPostgres(t)
	now := time.Now()

	t.Run("never-collected device is stale (AC 6)", func(t *testing.T) {
		d := testutil.CreateTestDevice(t, st, "stale-never")
		markSeen(t, st, d, now)
		assert.Contains(t, staleDevices(t, st, now), d)
	})

	t.Run("fresh device is not stale", func(t *testing.T) {
		d := testutil.CreateTestDevice(t, st, "stale-fresh")
		markSeen(t, st, d, now)
		insertInventory(t, st, d, now.Add(-time.Hour)) // well inside the 1440-minute default
		assert.NotContains(t, staleDevices(t, st, now), d)
	})

	t.Run("stale device past the default interval", func(t *testing.T) {
		d := testutil.CreateTestDevice(t, st, "stale-old")
		markSeen(t, st, d, now)
		insertInventory(t, st, d, now.Add(-25*time.Hour))
		assert.Contains(t, staleDevices(t, st, now), d)
	})

	t.Run("device with old last_seen_at is skipped (AC 5)", func(t *testing.T) {
		d := testutil.CreateTestDevice(t, st, "stale-gone")
		markSeen(t, st, d, now.Add(-2*time.Hour)) // outside the one-tick seen window
		assert.NotContains(t, staleDevices(t, st, now), d)
	})

	t.Run("deleted device is skipped", func(t *testing.T) {
		d := testutil.CreateTestDevice(t, st, "stale-deleted")
		markSeen(t, st, d, now)
		require.NoError(t, st.AppendEvent(context.Background(), store.Event{
			StreamType: "device", StreamID: d, EventType: "DeviceDeleted",
			Data: map[string]any{}, ActorType: "user", ActorID: "u",
		}))
		assert.NotContains(t, staleDevices(t, st, now), d)
	})
}
