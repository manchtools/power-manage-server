package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestLiveUserWrappedDEKs pins the AC 30 data source: every non-deleted
// user is returned with its wrapped DEK (empty when the row is missing),
// and erased users are excluded.
func TestLiveUserWrappedDEKs(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	withDEK := testutil.CreateTestUser(t, st, "hasdek-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	missing := testutil.CreateTestUser(t, st, "nodek-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	_, err := st.TestingPool().Exec(ctx, `DELETE FROM user_encryption_keys WHERE user_id = $1`, missing)
	require.NoError(t, err)

	erased := testutil.CreateTestUser(t, st, "erased-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	_, err = st.TestingPool().Exec(ctx, `UPDATE users_projection SET is_deleted = true WHERE id = $1`, erased)
	require.NoError(t, err)

	deks, err := store.LiveUserWrappedDEKs(ctx, st.TestingPool())
	require.NoError(t, err)

	m := map[string]string{}
	for _, d := range deks {
		m[d.UserID] = d.Wrapped
	}
	wrapped, ok := m[withDEK]
	assert.True(t, ok, "a live user with a DEK is returned")
	assert.NotEmpty(t, wrapped, "and carries its wrapped DEK bytes")
	empty, ok := m[missing]
	assert.True(t, ok, "a live user with NO DEK row is still returned (the missing-key finding)")
	assert.Empty(t, empty, "with an empty wrapped value")
	_, ok = m[erased]
	assert.False(t, ok, "an erased (is_deleted) user is excluded — AC 30 is about LIVE users")
}

// TestDeletedUsersWithDEK pins the AC 31 anomaly source: an erased user
// that still holds a DEK row is reported; a properly shredded one is not.
func TestDeletedUsersWithDEK(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	// Properly shredded: is_deleted AND no DEK row.
	shredded := testutil.CreateTestUser(t, st, "shred-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	_, err := st.TestingPool().Exec(ctx, `DELETE FROM user_encryption_keys WHERE user_id = $1`, shredded)
	require.NoError(t, err)
	_, err = st.TestingPool().Exec(ctx, `UPDATE users_projection SET is_deleted = true WHERE id = $1`, shredded)
	require.NoError(t, err)

	// Resurrected: is_deleted but the DEK row came back (e.g. backup restore).
	resurrected := testutil.CreateTestUser(t, st, "resur-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	_, err = st.TestingPool().Exec(ctx, `UPDATE users_projection SET is_deleted = true WHERE id = $1`, resurrected)
	require.NoError(t, err)

	// A live user with a DEK is not deleted → never flagged.
	live := testutil.CreateTestUser(t, st, "live-"+testutil.NewID()[:8]+"@test.com", "pass", "user")

	ids, err := store.DeletedUsersWithDEK(ctx, st.TestingPool())
	require.NoError(t, err)
	assert.Contains(t, ids, resurrected, "an erased user still holding a DEK is the anomaly")
	assert.NotContains(t, ids, shredded, "a properly shredded user has no DEK")
	assert.NotContains(t, ids, live, "a live user is not a deletion anomaly")
}

// TestErasedUsersStillProvisioned pins the AC 36 safety-net data source: an
// erased user whose OS account teardown was dropped — their system USER action
// is still live and PRESENT — is reported (with its linked action ids for the
// sweep), while a cleanly-torn-down erased user, a deleted action, and a live
// user are not. A lingering provisioning flag alone is NOT a signal (AC 32).
func TestErasedUsersStillProvisioned(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	pool := st.TestingPool()

	erase := func(id string) {
		_, err := pool.Exec(ctx, `UPDATE users_projection SET is_deleted = true WHERE id = $1`, id)
		require.NoError(t, err)
	}
	// seedUserAction inserts a system action with a chosen desired_state /
	// deleted flag and links it as the user's system USER action.
	seedUserAction := func(userID string, desiredState int, deleted bool) string {
		actID := testutil.NewID()
		_, err := pool.Exec(ctx,
			`INSERT INTO actions_projection (id, name, action_type, is_system, is_deleted, desired_state)
			 VALUES ($1, $2, 0, true, $3, $4)`,
			actID, "sys-user-"+actID[:6], deleted, desiredState)
		require.NoError(t, err)
		_, err = pool.Exec(ctx,
			`UPDATE users_projection SET system_user_action_id = $2 WHERE id = $1`, userID, actID)
		require.NoError(t, err)
		return actID
	}

	// Clean teardown: erased, system action set ABSENT.
	clean := testutil.CreateTestUser(t, st, "clean-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	seedUserAction(clean, 1 /*ABSENT*/, false)
	erase(clean)

	// Provisioning flag left set but no live action — cosmetic, must NOT flag.
	provOn := testutil.CreateTestUser(t, st, "provon-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	_, err := pool.Exec(ctx, `UPDATE users_projection SET user_provisioning_enabled = true WHERE id = $1`, provOn)
	require.NoError(t, err)
	erase(provOn)

	// Live PRESENT system USER action still targeting an erased user — the gap.
	livePresent := testutil.CreateTestUser(t, st, "livep-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	liveActID := seedUserAction(livePresent, 0 /*PRESENT*/, false)
	erase(livePresent)

	// A deleted action is not "live" even if PRESENT → must NOT flag.
	deletedAction := testutil.CreateTestUser(t, st, "delact-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	seedUserAction(deletedAction, 0 /*PRESENT*/, true /*deleted*/)
	erase(deletedAction)

	// A LIVE (non-erased) user with a PRESENT action is not an erasure anomaly.
	liveUser := testutil.CreateTestUser(t, st, "liveu-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	seedUserAction(liveUser, 0 /*PRESENT*/, false)

	orphans, err := store.ErasedUsersStillProvisioned(ctx, pool)
	require.NoError(t, err)

	byID := map[string]store.ErasedProvisioning{}
	for _, o := range orphans {
		byID[o.UserID] = o
	}
	assert.Contains(t, byID, livePresent, "erased user with a live PRESENT system USER action is flagged")
	assert.Equal(t, liveActID, byID[livePresent].SystemUserActionID, "carries the action id for the sweep")
	assert.NotContains(t, byID, clean, "a cleanly torn-down erased user is not flagged")
	assert.NotContains(t, byID, provOn, "a lingering provisioning flag alone is not a signal (AC 32 closes it)")
	assert.NotContains(t, byID, deletedAction, "a deleted (not live) system action does not flag")
	assert.NotContains(t, byID, liveUser, "a live user is not an erasure anomaly")
}

// TestComputeProjectionDrift pins AC 31a: a projection whose tail is
// behind the newest event in its streams is reported as drifted, while a
// healthy projection is not.
func TestComputeProjectionDrift(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	testutil.CreateTestUser(t, st, "drift-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")
	testutil.CreateTestDevice(t, st, "drift-host-"+testutil.NewID()[:6])

	// Healthy: the live listeners kept every projection current.
	drift, err := store.ComputeProjectionDrift(ctx, st.TestingPool())
	require.NoError(t, err)
	require.NotEmpty(t, drift)
	for _, d := range drift {
		assert.Falsef(t, d.Drifted(), "target %q should be current (stream_max=%d proj_max=%d)", d.Target, d.StreamMax, d.ProjMax)
	}

	// Induce drift on the user stream: a raw event the projectors never
	// applied (direct INSERT fires no post-commit listener). Its type is
	// UserCreatedWithRoles — a type the users projection has demonstrably
	// applied before (the seeded user's own creation), so it is a real
	// silently-dropped write, not a co-tenant event of a shared stream.
	_, err = st.TestingPool().Exec(ctx, `
		INSERT INTO events (id, stream_type, stream_id, stream_version, event_type, data, metadata, actor_type, actor_id)
		VALUES ($1, 'user', $2, 1, 'UserCreatedWithRoles', '{}', '{}', 'system', 'drift-test')`,
		testutil.NewID(), "ghost-"+testutil.NewID()[:8])
	require.NoError(t, err)

	drift, err = store.ComputeProjectionDrift(ctx, st.TestingPool())
	require.NoError(t, err)
	users := findTargetDrift(t, drift, "users")
	assert.True(t, users.Drifted(),
		"the users projection (proj_max=%d) is behind the injected event (stream_max=%d)", users.ProjMax, users.StreamMax)

	// A target on an unrelated stream is unaffected.
	devices := findTargetDrift(t, drift, "devices")
	assert.False(t, devices.Drifted(), "the devices projection is untouched by a user-stream event")
}

// TestComputeProjectionDrift_PerTableNotMaskedByFreshSibling pins the CR
// fix: a target with several version-bearing tables must report drift when
// ANY one is behind — a fresh sibling table must not mask a stale one via
// a target-wide MAX. The users target owns users_projection AND
// user_roles_projection; here the latter is left behind while the former
// is pushed ahead.
func TestComputeProjectionDrift_PerTableNotMaskedByFreshSibling(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	// admin creation writes user_roles_projection from its role_ids, so
	// UserCreatedWithRoles is in that table's handled-type set.
	testutil.CreateTestUser(t, st, "mask-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")

	// A raw UserCreatedWithRoles event past user_roles_projection's
	// high-water (a write the projector dropped for that table).
	_, err := st.TestingPool().Exec(ctx, `
		INSERT INTO events (id, stream_type, stream_id, stream_version, event_type, data, metadata, actor_type, actor_id)
		VALUES ($1, 'user', $2, 1, 'UserCreatedWithRoles', '{}', '{}', 'system', 'mask-test')`,
		testutil.NewID(), "ghost-"+testutil.NewID()[:8])
	require.NoError(t, err)
	injected := maxSeq(t, st)

	// Push users_projection AHEAD of the injected event so a target-wide
	// MAX would look current — only user_roles_projection is actually stale.
	_, err = st.TestingPool().Exec(ctx, `UPDATE users_projection SET projection_version = $1`, injected+1000)
	require.NoError(t, err)

	drift, err := store.ComputeProjectionDrift(ctx, st.TestingPool())
	require.NoError(t, err)
	users := findTargetDrift(t, drift, "users")
	assert.True(t, users.Drifted(),
		"user_roles_projection is behind; a fresh users_projection must not mask it (per-table drift)")
	assert.Equal(t, "user_roles_projection", users.LaggingTable,
		"the report names the LAGGING table, not the fresh sibling")
	assert.Less(t, users.LaggingMax, users.ProjMax,
		"and its own high-water, not the target-wide max (which is the fresh sibling's)")
}

// TestReadRetentionPosture pins the AC 29 data source: log size + oldest
// event before any prune, and the last-prune marker fields after one.
func TestReadRetentionPosture(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	testutil.CreateTestUser(t, st, "posture-"+testutil.NewID()[:8]+"@test.com", "pass", "user")

	p, err := store.ReadRetentionPosture(ctx, st.TestingPool())
	require.NoError(t, err)
	assert.Positive(t, p.EventCount)
	assert.False(t, p.OldestEventAt.IsZero(), "a non-empty log has an oldest event")
	assert.Zero(t, p.LastPruneCheckpoint, "never pruned → zero last-prune fields")
	assert.True(t, p.LastPruneAt.IsZero())

	// After a prune, the marker surfaces as the last-prune posture.
	cp := maxSeq(t, st)
	_, err = st.PruneEventsUpTo(ctx, cp, "prune-posture", "sha-posture")
	require.NoError(t, err)

	p, err = store.ReadRetentionPosture(ctx, st.TestingPool())
	require.NoError(t, err)
	assert.Equal(t, cp, p.LastPruneCheckpoint)
	assert.Equal(t, "prune-posture", p.LastPruneRef)
	assert.False(t, p.LastPruneAt.IsZero(), "the marker's occurred_at is the last-prune time")
}

func findTargetDrift(t *testing.T, ds []store.TargetDrift, name string) store.TargetDrift {
	t.Helper()
	for _, d := range ds {
		if d.Target == name {
			return d
		}
	}
	t.Fatalf("target %q not found in drift report", name)
	return store.TargetDrift{}
}
