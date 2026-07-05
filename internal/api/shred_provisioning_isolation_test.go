package api

// Spec 19 Section E — provisioning isolation. An erased user must never
// (re)acquire a system action. Three existing invariants make this hold;
// these tests PIN them so a future refactor can't silently break them.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestAffectedFromEvent_UserDeletedIsSyncOpNone pins AC 33: UserDeleted
// must classify to SyncOpNone — a deletion schedules NO system-action
// sync (which would otherwise try to provision the just-erased user).
func TestAffectedFromEvent_UserDeletedIsSyncOpNone(t *testing.T) {
	op, users := AffectedFromEvent(store.PersistedEvent{
		StreamType: "user",
		StreamID:   "01JUSERAAAAAAAAAAAAAAAAAAA",
		EventType:  string(eventtypes.UserDeleted),
	})
	assert.Equal(t, SyncOpNone, op, "UserDeleted must never map to a sync op (spec 19 AC 33)")
	assert.Empty(t, users)
}

// TestSyncUserSystemActions_RefusesDeletedUser pins AC 32: the
// generation choke point refuses a deleted/erased user explicitly —
// no system action is created or distributed for them.
func TestSyncUserSystemActions_RefusesDeletedUser(t *testing.T) {
	m, st := newManagerForTest(t)
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, "prov-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	setLinuxUsername(t, st, userID, "provuser")
	enableGlobalProvisioning(t, st)

	// Delete (crypto-shred) the user.
	require.NoError(t, st.AppendUserDeletionWithShred(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: string(eventtypes.UserDeleted),
		Data: map[string]any{}, ActorType: "user", ActorID: userID,
	}))

	// The generation path must refuse — gracefully, no error, no action.
	require.NoError(t, m.SyncUserSystemActions(ctx, userID),
		"syncing an erased user is a graceful no-op, not an error")

	var n int
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM actions_projection WHERE is_system = TRUE AND name LIKE 'system:user-provision:%' AND name LIKE '%'||$1||'%'`,
		userID).Scan(&n))
	assert.Zero(t, n, "no system USER action may be generated for an erased user (AC 32)")
}

// TestRebuildAll_DispatchesNoSystemActions pins AC 34: a full rebuild
// dispatches NO system actions — provisioning is a live-only
// post-commit listener (RegisterEventListener), not a rebuild applier
// (RegisterRebuildApply), so a restore materialises the user rows
// without ever generating a provisioning action. An erased user
// therefore comes back as (is_deleted, sentinel) with no account.
func TestRebuildAll_DispatchesNoSystemActions(t *testing.T) {
	m, st := newManagerForTest(t)
	ctx := context.Background()
	_ = m

	userID := testutil.CreateTestUser(t, st, "rb-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	setLinuxUsername(t, st, userID, "rbuser")
	enableGlobalProvisioning(t, st)

	// A rebuild replays only rebuild appliers; the system-action
	// listener is not one, so no provisioning-action rows are created
	// by the replay. Count system USER actions before and after.
	countSystemUserActions := func() int {
		var n int
		require.NoError(t, st.TestingPool().QueryRow(ctx,
			`SELECT COUNT(*) FROM actions_projection WHERE is_system = TRUE`).Scan(&n))
		return n
	}
	before := countSystemUserActions()

	_, err := st.RebuildAll(ctx)
	require.NoError(t, err)

	assert.Equal(t, before, countSystemUserActions(),
		"a rebuild must not generate system actions — provisioning is a live-only listener, not a rebuild applier (AC 34)")
}
