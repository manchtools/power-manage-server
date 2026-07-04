package store_test

import (
	"context"
	"errors"
	"fmt"
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
	_, err = st.TestingPool().Exec(ctx, "TRUNCATE users_projection CASCADE")
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

// TestRebuildAll_StreamsAcrossBatchBoundary pins WS13 #14: with the batch size
// lowered below the event count, the keyset-paginated replay still applies every
// event across batch boundaries in order (no events dropped or double-applied,
// no full pre-buffer). Seeds several users, lowers the batch size to 2, truncates
// the projection, and asserts every user reappears and the count matches.
func TestRebuildAll_StreamsAcrossBatchBoundary(t *testing.T) {
	restore := store.SetRebuildBatchSizeForTest(2)
	defer restore()

	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	ids := make([]string, 0, 5)
	for i := 0; i < 5; i++ { // 5 users > batch size 2 → at least 3 batches
		ids = append(ids, testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin"))
	}

	_, err := st.TestingPool().Exec(ctx, "TRUNCATE users_projection CASCADE")
	require.NoError(t, err)

	res, err := st.RebuildAll(ctx, "users")
	require.NoError(t, err)
	require.Len(t, res.Targets, 1)
	assert.GreaterOrEqual(t, res.Targets[0].EventsApplied, int64(len(ids)),
		"every seeded user's events must replay across the batch boundary")

	for _, id := range ids {
		_, err := st.Queries().GetUserByID(ctx, id)
		assert.NoErrorf(t, err, "user %s must reappear after a multi-batch rebuild", id)
	}
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

	_, err := st.TestingPool().Exec(ctx,
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

// TestAllRebuildTargetsHaveRegisteredApplier is the self-discovering parity
// guard for #125's silent-no-op failure mode: every entry in AllRebuildTargets
// MUST have a Go applier wired by projectors.WireAll. A target without one makes
// RebuildAll TRUNCATE the projection and then "succeed" without re-applying any
// event — a destructive no-op during emergency replay. Adding a target here
// without the matching WireAll registration trips this test. (Matches-zero
// guarded so an empty target list can't pass vacuously.)
func TestAllRebuildTargetsHaveRegisteredApplier(t *testing.T) {
	require.NotEmpty(t, store.AllRebuildTargets, "AllRebuildTargets is empty — the parity guard would pass vacuously")

	st := testutil.SetupPostgres(t) // SetupPostgres runs projectors.WireAll
	for _, target := range store.AllRebuildTargets {
		assert.Truef(t, st.HasRebuildApply(target.Name),
			"rebuild target %q has no Go applier registered — projectors.WireAll must RegisterRebuildApply it, or RebuildAll silently no-ops the projection", target.Name)
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

	_, err = st.TestingPool().Exec(ctx, "TRUNCATE roles_projection CASCADE")
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

	_, err = st.TestingPool().Exec(ctx, "TRUNCATE tokens_projection CASCADE")
	require.NoError(t, err)

	_, err = st.Queries().GetTokenByID(ctx, generated.GetTokenByIDParams{ID: tokenID})
	require.Error(t, err, "post-truncate fetch must fail; if it doesn't the truncate didn't take")

	res, err := st.RebuildAll(ctx, "tokens")
	require.NoError(t, err)
	require.Len(t, res.Targets, 1)
	assert.Equal(t, "tokens", res.Targets[0].Name)
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

	_, err = st.TestingPool().Exec(ctx, "TRUNCATE user_selections_projection CASCADE")
	require.NoError(t, err)

	_, err = st.Queries().GetUserSelection(ctx, generated.GetUserSelectionParams{
		DeviceID: deviceID, SourceType: "user_group", SourceID: groupID,
	})
	require.Error(t, err, "post-truncate fetch must fail; if it doesn't the truncate didn't take")

	res, err := st.RebuildAll(ctx, "user_selections")
	require.NoError(t, err)
	require.Len(t, res.Targets, 1)
	assert.Equal(t, "user_selections", res.Targets[0].Name)
	assert.Greater(t, res.Targets[0].EventsApplied, int64(0))

	after, err := st.Queries().GetUserSelection(ctx, generated.GetUserSelectionParams{
		DeviceID: deviceID, SourceType: "user_group", SourceID: groupID,
	})
	require.NoError(t, err, "rebuild must restore the user_selection projection — issue #125 regression if this fails")
	assert.Equal(t, before.ID, after.ID)
	assert.Equal(t, before.Selected, after.Selected)
}

// TestRebuildAll_GoApplierMissingFailsLoudly — defensive guard for
// the silent-no-op rebuild that motivated #125. After migration 028
// the three ported targets carry an empty Function; if the Go
// applier registration ever drifts (a WireAll entry is removed, a
// refactor renames the target, a code path constructs a Store
// without wiring), runOneTarget must fail loudly instead of falling
// through to dispatchViaPlpgsql with an empty function name —
// which builds valid SQL that returns rows without invoking any
// projector and reports "rebuild succeeded" against the freshly
// truncated projection.
func TestRebuildAll_GoApplierMissingFailsLoudly(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()

	// Seed a row directly into the projection. The post-rebuild
	// invariant we assert is that the projection is untouched as
	// observed from an external connection — strictly, this only
	// catches the user-visible failure mode. The whole RebuildAll
	// runs inside pgx.BeginFunc, so a hypothetical "TRUNCATE then
	// error" would also roll back and look identical from the
	// outside. The guarantee that the guard fires *before* TRUNCATE
	// (and therefore avoids briefly holding ACCESS EXCLUSIVE on a
	// production projection) is verified by reading runOneTarget,
	// not by this test alone.
	roleID := testutil.NewID()
	_, err := st.TestingPool().Exec(ctx,
		`INSERT INTO roles_projection (id, name, description, permissions, is_system, created_at, projection_version)
		 VALUES ($1, 'guard-canary', '', ARRAY[]::TEXT[], false, NOW(), 0)`,
		roleID,
	)
	require.NoError(t, err)

	_, err = st.RebuildAll(ctx, "roles")
	require.Error(t, err, "rebuild must fail when the Go applier is unwired and Function is empty")
	assert.Contains(t, err.Error(), "no Go applier registered",
		"error must name the missing-applier failure mode so operators can wire WireAll")
	assert.Contains(t, err.Error(), "roles",
		"error must name the offending target")

	// The canary row must still be there. As called out above,
	// this only proves the user-visible invariant (failed rebuild
	// leaves the projection intact); strict pre-TRUNCATE ordering
	// is verified by reading runOneTarget.
	var count int
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM roles_projection WHERE id = $1`, roleID,
	).Scan(&count))
	assert.Equal(t, 1, count,
		"projection must survive the failed rebuild; finding zero rows means either the guard ran too late or the outer transaction failed to roll back a destructive op")
}

// TestRebuildAll_SkipEventIsNonFatal pins the ErrSkipEvent contract: an
// applier that reports an unprojectable historical event (e.g. a
// malformed payload) via store.ErrSkipEvent must NOT abort the rebuild —
// the event is skipped and the target completes, unlike a plain error
// which rolls the whole target back (TestRebuildAll_TransactionalAtomicity).
func TestRebuildAll_SkipEventIsNonFatal(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	roleID := testutil.CreateTestRole(t, st, actorID, "skip-role-"+testutil.NewID(), []string{"GetDevice"})

	// Every replayed event reports itself as skippable. A fatal error
	// here would roll back the target's TRUNCATE and RebuildAll would
	// return an error; ErrSkipEvent must instead let it succeed.
	st.RegisterRebuildApply("roles", func(context.Context, *store.Queries, store.PersistedEvent) error {
		return fmt.Errorf("forced skip: %w", store.ErrSkipEvent)
	})

	res, err := st.RebuildAll(ctx, "roles")
	require.NoError(t, err, "ErrSkipEvent must not abort the rebuild")
	require.NotNil(t, res)

	// F-14 / spec 21 AC 7: skipped events are reported SEPARATELY from
	// applied ones — an operator must see that N events were
	// unprojectable, not a total that silently conflates both.
	require.Len(t, res.Targets, 1)
	assert.Zero(t, res.Targets[0].EventsApplied,
		"a skipped event must not count as applied")
	assert.Positive(t, res.Targets[0].Skipped,
		"skipped events must surface in the Skipped counter")

	// The role's create event was skipped, so the truncated projection
	// stays empty — proving the skip path ran (counted, not applied) and
	// did not fatally roll back.
	var after int
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM roles_projection WHERE id = $1`, roleID,
	).Scan(&after))
	assert.Equal(t, 0, after, "skipped events must not be applied, but the rebuild must still complete")
}

// TestRebuildAll_TransactionalAtomicity forces the roles applier to
// fail after the target's TRUNCATE has executed. The outer rebuild
// transaction must roll that destructive statement back, leaving the
// pre-existing projection row intact.
func TestRebuildAll_TransactionalAtomicity(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	roleID := testutil.CreateTestRole(t, st, actorID, "atomic-role-"+testutil.NewID(), []string{"GetDevice"})

	var before int
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM roles_projection WHERE id = $1`, roleID,
	).Scan(&before))
	require.Equal(t, 1, before)

	st.RegisterRebuildApply("roles", func(context.Context, *store.Queries, store.PersistedEvent) error {
		return errors.New("forced roles replay failure")
	})

	_, err := st.RebuildAll(ctx, "roles")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forced roles replay failure")

	var after int
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM roles_projection WHERE id = $1`, roleID,
	).Scan(&after))
	assert.Equal(t, 1, after, "failed rebuild must roll back target TRUNCATE")
}

// TestRebuildAll_UserGroupsRebuildPreservesSCIMMappings pins the
// fix for manchtools/power-manage-server#175. Before the fix,
// `RebuildAll(ctx)` ran the user_groups target whose
// `TRUNCATE user_groups_projection CASCADE` walked the FK graph and
// wiped scim_group_mapping_projection — but the rebuild only
// replayed user_group events, so SCIM mappings stayed empty
// afterwards. The fix adds a scim_group_mappings rebuild target
// (declared after user_groups so the FK is restored first) that
// re-replays the scim_group_mapping stream.
func TestRebuildAll_UserGroupsRebuildPreservesSCIMMappings(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestUserGroup(t, st, actor, "scim-managed-group")

	// Seed an identity provider so the scim_group_mapping FK is
	// satisfied. The minimal IdentityProviderCreated event the
	// projector accepts.
	providerID := testutil.NewID()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider", StreamID: providerID,
		EventType: "IdentityProviderCreated",
		Data: map[string]any{
			"name":          "Test IdP",
			"slug":          "test-idp-" + providerID[:8],
			"provider_type": "oidc",
			"client_id":     "test-client",
			"issuer_url":    "https://idp.test/realms/test",
			"scim_enabled":  true,
		},
		ActorType: "user", ActorID: actor,
	}))

	// Seed the SCIM mapping: maps SCIM group "sg-eng" on this
	// provider to our user group.
	mappingID := testutil.NewID()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "scim_group_mapping", StreamID: mappingID,
		EventType: "SCIMGroupMapped",
		Data: map[string]any{
			"provider_id":       providerID,
			"scim_group_id":     "sg-eng",
			"scim_display_name": "Engineering",
			"user_group_id":     groupID,
		},
		ActorType: "user", ActorID: actor,
	}))

	// Pre-condition: live pipeline projected the mapping.
	beforeCount, err := st.Queries().CountSCIMGroupMappings(ctx, providerID)
	require.NoError(t, err)
	require.Equal(t, int64(1), beforeCount, "live projector must have written the mapping before rebuild")

	// Run the full RebuildAll. user_groups' TRUNCATE CASCADE wipes
	// scim_group_mapping_projection; the new scim_group_mappings
	// target (declared AFTER user_groups in AllRebuildTargets) must
	// then replay the SCIMGroupMapped event and restore the row.
	res, err := st.RebuildAll(ctx)
	require.NoError(t, err)

	// Verify the scim_group_mappings target ran and replayed at
	// least our seeded mapping.
	var scimTarget *store.TargetResult
	for i := range res.Targets {
		if res.Targets[i].Name == "scim_group_mappings" {
			scimTarget = &res.Targets[i]
			break
		}
	}
	require.NotNil(t, scimTarget, "scim_group_mappings target must be present in the result; the WireAll registration is what proves #175 is fixed")
	assert.Greater(t, scimTarget.EventsApplied, int64(0),
		"scim_group_mappings rebuild must have replayed at least the SCIMGroupMapped event we seeded")

	// Post-condition: the mapping survived the rebuild.
	afterCount, err := st.Queries().CountSCIMGroupMappings(ctx, providerID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), afterCount,
		"#175 regression: user_groups rebuild wiped the SCIM mapping but the new scim_group_mappings target should have re-replayed it")
}
