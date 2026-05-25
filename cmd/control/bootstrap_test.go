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

	"github.com/manchtools/power-manage/server/internal/projectors"
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

// TestEnsureAdminUser_RequiresWireAllFirst guards against the #317
// regression: ensureAdminUser emits a UserCreatedWithRoles event which
// only materialises into users_projection when UserListener is already
// registered. Production startup wires WireAll inside wireSystemActions
// (cmd/control/main.go); ensureAdminUser must run AFTER that.
//
// The test uses SetupPostgresWithoutProjectors so the test fixture
// doesn't paper over the production ordering — SetupPostgres's
// auto-wire is what masked the original bug from CI for rc1.
func TestEnsureAdminUser_RequiresWireAllFirst(t *testing.T) {
	ctx := context.Background()
	logger := quietLogger()

	t.Run("CorrectOrder_WireAllThenEnsureAdmin", func(t *testing.T) {
		st := testutil.SetupPostgresWithoutProjectors(t)
		// Production order as of #317: listeners registered first.
		projectors.WireAll(st, logger)

		err := ensureAdminUser(ctx, st, "admin@example.com", "test-password", logger)
		require.NoError(t, err, "ensureAdminUser succeeds")

		user, err := st.Repos().User.GetByEmail(ctx, "admin@example.com")
		require.NoError(t, err,
			"with WireAll wired first, UserListener writes users_projection during AppendEvent")
		assert.Equal(t, "admin@example.com", user.Email)
		require.NotNil(t, user.PasswordHash)
		assert.NotEmpty(t, *user.PasswordHash,
			"projector must persist the bcrypt hash so Login can verify against it")
	})

	t.Run("BrokenOrder_EnsureAdminBeforeWireAll", func(t *testing.T) {
		// Documents the rc1 broken order: with no listener registered
		// at AppendEvent time, the event lands in `events` but the
		// projection write is silently skipped — GetByEmail then misses.
		// If main.go regresses to the pre-#317 ordering, this branch
		// would pass and the production-correct branch above would fail.
		st := testutil.SetupPostgresWithoutProjectors(t)

		err := ensureAdminUser(ctx, st, "admin@example.com", "test-password", logger)
		require.NoError(t, err,
			"AppendEvent succeeds — the bug is the silent projection skip, not the emit")

		_, err = st.Repos().User.GetByEmail(ctx, "admin@example.com")
		require.True(t, store.IsNotFound(err),
			"without WireAll first, the projection row never materialises; "+
				"this is the rc1 race that left users_projection empty for the bootstrap admin")
	})
}
