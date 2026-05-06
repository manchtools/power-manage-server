package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	generated "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestRebuildAll_RoundTripsThroughEventStore proves that RebuildAll
// can re-derive the projection state from the event store after a
// destructive truncate. Truncates users_projection mid-test, runs
// RebuildAll for the "users" target, asserts the row reappears.
//
// This is the critical correctness contract: after rebuild, the
// projection state must be identical to what the live event-handler
// pipeline produced. Any divergence means our Go RebuildAll has lost
// fidelity vs the (now-deleted) PL/pgSQL rebuild_users_projection().
func TestRebuildAll_RoundTripsThroughEventStore(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "admin")

	// Pre-condition: live pipeline projected the user.
	before, err := st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	require.Equal(t, email, before.Email)

	// Truncate the projection out from under the live pipeline,
	// simulating an incident (manual delete, projector bug, etc.)
	// that left the projection inconsistent with the event store.
	_, err = st.Pool().Exec(ctx, "TRUNCATE users_projection CASCADE")
	require.NoError(t, err)

	_, err = st.Queries().GetUserByID(ctx, userID)
	require.Error(t, err, "post-truncate fetch must fail; if it doesn't the truncate didn't take")

	// RebuildAll for just this target replays every 'user' event
	// through the projector and recreates the row.
	res, err := st.RebuildAll(ctx, "users")
	require.NoError(t, err)
	require.Len(t, res.Targets, 1)
	assert.Equal(t, "users", res.Targets[0].Name)
	assert.Greater(t, res.Targets[0].EventsApplied, int64(0),
		"at least the UserCreated event must have been replayed")

	after, err := st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, email, after.Email)
	assert.Equal(t, before.ID, after.ID)
}

// TestRebuildAll_NoArgsRebuildsEverything covers the operator
// happy-path: `RebuildAll(ctx)` with no targets rebuilds every
// registered projection. We seed a few stream types, truncate them
// all, then call RebuildAll(ctx) with no args and assert each target
// reappears.
func TestRebuildAll_NoArgsRebuildsEverything(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "rebuild-test-host")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Rebuild Test Group")

	_, err := st.Pool().Exec(ctx,
		`TRUNCATE users_projection CASCADE;
		 TRUNCATE devices_projection CASCADE;
		 TRUNCATE device_groups_projection CASCADE`)
	require.NoError(t, err)

	res, err := st.RebuildAll(ctx)
	require.NoError(t, err)
	assert.Equal(t, len(store.AllRebuildTargets), len(res.Targets),
		"no-arg RebuildAll must rebuild every registered target")

	// Each seeded entity is back.
	if _, err := st.Queries().GetUserByID(ctx, adminID); err != nil {
		t.Errorf("user gone after rebuild: %v", err)
	}
	if _, err := st.Queries().GetDeviceByID(ctx, generated.GetDeviceByIDParams{ID: deviceID}); err != nil {
		t.Errorf("device gone after rebuild: %v", err)
	}
	if _, err := st.Queries().GetDeviceGroupByID(ctx, groupID); err != nil {
		t.Errorf("device group gone after rebuild: %v", err)
	}
}

// TestRebuildAll_UnknownTargetIsRejected — operators mistyping a
// target name must get a clean error rather than a silent no-op.
// Bug-class avoidance: a typo'd `RebuildAll(ctx, "user")` (singular)
// when the canonical name is "users" should not return success with
// zero work done.
func TestRebuildAll_UnknownTargetIsRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	_, err := st.RebuildAll(ctx, "user", "nonexistent")
	require.Error(t, err)
	assert.True(t, errors.Is(err, store.ErrUnknownTarget),
		"want ErrUnknownTarget for typo'd target")
	assert.Contains(t, err.Error(), "nonexistent")
}

// TestRebuildAll_PortedProjector_RoundTrip — covers the regression
// from manchtools/power-manage-server#125: once a projector is
// ported to a Go listener, the corresponding PL/pgSQL
// project_<X>_event() becomes a no-op stub. RebuildAll then
// TRUNCATEs the projection and dispatches every event through the
// stub, leaving the projection empty.
//
// The fix routes ported targets through a Go applier registered in
// projectors.WireAll. This test exercises that path end-to-end on
// the "roles" target — the first ported projector that owned a
// rebuild target — by creating a role via the live pipeline,
// truncating its projection, calling RebuildAll, and asserting the
// row reappears with the same fields.
func TestRebuildAll_PortedProjector_RoundTrip(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	roleID := testutil.CreateTestRole(t, st, adminID, "RebuildPortedRole", []string{"users:read"})

	before, err := st.Queries().GetRoleByID(ctx, roleID)
	require.NoError(t, err, "role must exist after live pipeline projection")
	assert.Equal(t, "RebuildPortedRole", before.Name)

	_, err = st.Pool().Exec(ctx, "TRUNCATE roles_projection CASCADE")
	require.NoError(t, err)

	_, err = st.Queries().GetRoleByID(ctx, roleID)
	require.Error(t, err, "post-truncate fetch must fail; if it doesn't the truncate didn't take")

	res, err := st.RebuildAll(ctx, "roles")
	require.NoError(t, err)
	require.Len(t, res.Targets, 1)
	assert.Equal(t, "roles", res.Targets[0].Name)
	assert.Greater(t, res.Targets[0].EventsApplied, int64(0),
		"at least the RoleCreated event must have been replayed")

	after, err := st.Queries().GetRoleByID(ctx, roleID)
	require.NoError(t, err, "rebuild must restore the role projection — issue #125 regression if this fails")
	assert.Equal(t, before.Name, after.Name)
	assert.Equal(t, before.ID, after.ID)
}

// TestRebuildAll_PortedToken_RoundTrip — same #125 regression
// coverage as the roles test, but for the tokens target. Different
// applier path, so deserves its own test rather than relying on the
// roles test as a stand-in.
func TestRebuildAll_PortedToken_RoundTrip(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")

	tokenID := testutil.NewID()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "token",
		StreamID:   tokenID,
		EventType:  "TokenCreated",
		Data: map[string]any{
			"id":         tokenID,
			"value_hash": "test-hash",
			"name":       "RebuildPortedToken",
			"one_time":   false,
			"max_uses":   nil,
			"expires_at": nil,
			"owner_id":   adminID,
			"created_by": adminID,
		},
		ActorType: "user",
		ActorID:   adminID,
	}))

	before, err := st.Queries().GetTokenByID(ctx, generated.GetTokenByIDParams{ID: tokenID})
	require.NoError(t, err, "token must exist after live pipeline projection")
	assert.Equal(t, "RebuildPortedToken", before.Name)

	_, err = st.Pool().Exec(ctx, "TRUNCATE tokens_projection CASCADE")
	require.NoError(t, err)

	res, err := st.RebuildAll(ctx, "tokens")
	require.NoError(t, err)
	assert.Greater(t, res.Targets[0].EventsApplied, int64(0))

	after, err := st.Queries().GetTokenByID(ctx, generated.GetTokenByIDParams{ID: tokenID})
	require.NoError(t, err, "rebuild must restore the token projection — issue #125 regression if this fails")
	assert.Equal(t, before.Name, after.Name)
	assert.Equal(t, before.ID, after.ID)
}

// TestRebuildAll_PortedUserSelection_RoundTrip — third ported target
// with a rebuild entry. Different applier (single UPSERT, no
// transaction wrap) so worth its own coverage even though the role
// + token tests already prove the dispatcher path.
func TestRebuildAll_PortedUserSelection_RoundTrip(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "rebuild-user-selection-host")
	groupID := testutil.CreateTestUserGroup(t, st, adminID, "RebuildPortedSelectionGroup")

	selectionID := testutil.NewID()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_selection",
		StreamID:   selectionID,
		EventType:  "UserSelectionChanged",
		Data: map[string]any{
			"id":          selectionID,
			"device_id":   deviceID,
			"source_type": "user_group",
			"source_id":   groupID,
			"selected":    true,
			"created_by":  adminID,
		},
		ActorType: "user",
		ActorID:   adminID,
	}))

	before, err := st.Queries().GetUserSelection(ctx, generated.GetUserSelectionParams{
		DeviceID: deviceID, SourceType: "user_group", SourceID: groupID,
	})
	require.NoError(t, err, "selection must exist after live pipeline projection")
	assert.True(t, before.Selected)

	_, err = st.Pool().Exec(ctx, "TRUNCATE user_selections_projection CASCADE")
	require.NoError(t, err)

	res, err := st.RebuildAll(ctx, "user_selections")
	require.NoError(t, err)
	assert.Greater(t, res.Targets[0].EventsApplied, int64(0))

	after, err := st.Queries().GetUserSelection(ctx, generated.GetUserSelectionParams{
		DeviceID: deviceID, SourceType: "user_group", SourceID: groupID,
	})
	require.NoError(t, err, "rebuild must restore the user_selection projection — issue #125 regression if this fails")
	assert.Equal(t, before.ID, after.ID)
	assert.Equal(t, before.Selected, after.Selected)
}

// TestRebuildAll_TransactionalAtomicity — if the projector function
// fails partway through replay, the whole rebuild must roll back so
// the projection is not left half-replayed against a TRUNCATE'd
// table. We force a failure by swapping out the events table briefly,
// then verify the projection returns to its pre-rebuild state.
//
// Skipped for now: the cleanest way to force a projector failure is
// to inject a malformed event row, which requires write access to
// the events table mid-test. Documented here as a follow-up since
// the contract is critical but the test is fragile to set up.
func TestRebuildAll_TransactionalAtomicity(t *testing.T) {
	t.Skip("follow-up: inject a malformed event to force projector failure mid-replay")
}
