package main

// Boot-time seed tests for bootstrapAllDevicesGroup. The migration
// 008 PL/pgSQL DO block was retired in #242 Wave H (PR #308); these
// tests guard the Go replacement against the latent regression the
// PL/pgSQL version carried — the seed event was written into the
// events table but no listener was registered, so once Wave F retired
// the reactive triggers, fresh deployments silently had no "All
// Devices" projection row.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestBootstrapAllDevicesGroup_FreshDB asserts the seed contract:
// on a fresh database (no prior "All Devices" group), the bootstrap
// function emits a DeviceGroupCreated event that the registered
// projector listener materialises into a projection row visible via
// the standard repo lookup. This is the regression that the prior
// PL/pgSQL DO block silently failed.
func TestBootstrapAllDevicesGroup_FreshDB(t *testing.T) {
	// SetupPostgres wires projectors.WireAll, matching production
	// boot order — bootstrapAllDevicesGroup runs after WireAll so
	// the emitted event flows through the registered listener.
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	// Pre-condition: no "All Devices" group exists on a fresh DB.
	_, err := st.Repos().DeviceGroup.GetByName(ctx, "All Devices")
	require.True(t, store.IsNotFound(err),
		"fresh DB must not have the All Devices group seeded by migration")

	bootstrapAllDevicesGroup(ctx, st, quietLogger())

	group, err := st.Repos().DeviceGroup.GetByName(ctx, "All Devices")
	require.NoError(t, err, "bootstrap must materialise the projection row")
	assert.Equal(t, "All Devices", group.Name)
	assert.True(t, group.IsDynamic,
		"All Devices is the canonical dynamic group — the empty query matches every device")
	assert.Equal(t, "Dynamic group that matches all registered devices", group.Description)
}

// TestBootstrapAllDevicesGroup_Idempotent asserts the re-run contract:
// calling bootstrapAllDevicesGroup against a DB that already carries
// the seed is a no-op. A regression that emitted a second
// DeviceGroupCreated event would either (a) create a duplicate row
// with a different ULID or (b) collide on the unique-name constraint
// and crash the listener. Both are operator-visible breakages.
func TestBootstrapAllDevicesGroup_Idempotent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	bootstrapAllDevicesGroup(ctx, st, quietLogger())
	firstGroup, err := st.Repos().DeviceGroup.GetByName(ctx, "All Devices")
	require.NoError(t, err)

	// Second invocation must be a no-op — same row id, no new event.
	bootstrapAllDevicesGroup(ctx, st, quietLogger())
	secondGroup, err := st.Repos().DeviceGroup.GetByName(ctx, "All Devices")
	require.NoError(t, err)
	assert.Equal(t, firstGroup.ID, secondGroup.ID,
		"second bootstrap invocation must not produce a new group — same row, same id")
}
