package store_test

// Spec 19 AC 17 (absorbs audit F-04): snapshot-equivalence, proven
// full-fidelity. After a prune at checkpoint N, a snapshot-aware rebuild
// — restore(snapshot@N) + replay(events > N) — must reproduce projection
// state BYTE-IDENTICAL to a full rebuild performed BEFORE the prune,
// compared as a full-row dump of every AllRebuildTargets table (not a
// sampled subset). Self-discovering over the target registry.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestRebuildAllFromSnapshot_FullFidelity pins AC 17: prune@N then
// restore+replay>N == a pre-prune rebuild, byte for byte.
func TestRebuildAllFromSnapshot_FullFidelity(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	// Batch 1: the rich fixture across every stream type. Everything here
	// lands at sequence_num ≤ N.
	seedRichFixture(t, st)
	checkpoint := maxSeq(t, st)
	require.Positive(t, checkpoint)

	// Batch 2: a spread of further events, all at sequence_num > N, so the
	// replay-`>N` leg is non-trivial and touches multiple targets.
	adminID := testutil.CreateTestUser(t, st, "postN-admin-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")
	newUser := testutil.CreateTestUser(t, st, "postN-user-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	newRole := testutil.CreateTestRole(t, st, adminID, "postN-role-"+testutil.NewID()[:8], []string{"GetDevice"})
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_role",
		StreamID:   newUser + ":" + newRole,
		EventType:  "UserRoleAssigned",
		Data:       map[string]any{"user_id": newUser, "role_id": newRole},
		ActorType:  "user",
		ActorID:    adminID,
	}))
	newDevice := testutil.CreateTestDevice(t, st, "postN-host-"+testutil.NewID()[:8])
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   newDevice,
		EventType:  "DeviceLabelSet",
		Data:       map[string]any{"key": "tier", "value": "gold"},
		ActorType:  "user",
		ActorID:    adminID,
	}))
	require.Greater(t, maxSeq(t, st), checkpoint, "batch 2 must add events beyond the checkpoint")

	// Reference: a full rebuild of ALL events, taken BEFORE any prune.
	_, err := st.RebuildAll(ctx)
	require.NoError(t, err)
	baseline := dumpRebuildTables(t, st)
	nonEmpty := 0
	for _, rows := range baseline {
		if rows != "" {
			nonEmpty++
		}
	}
	require.GreaterOrEqual(t, nonEmpty, 10,
		"fixture too thin (%d non-empty tables) — the byte-compare would prove little", nonEmpty)

	// Capture the snapshot @ N while events ≤ N still exist, then prune
	// them: the pruned history is now only in the snapshot.
	snap, err := st.CaptureProjectionSnapshot(ctx, checkpoint)
	require.NoError(t, err)
	deleted, err := st.PruneEventsUpTo(ctx, checkpoint, "test-archive-ref", "0000000000000000000000000000000000000000000000000000000000000000")
	require.NoError(t, err)
	require.Positive(t, deleted, "the prune must actually delete the ≤ N history")

	// Snapshot-aware rebuild: restore state @ N, replay only > N on top.
	res, err := st.RebuildAllFromSnapshot(ctx, snap)
	require.NoError(t, err)
	require.NotEmpty(t, res.Targets)

	after := dumpRebuildTables(t, st)
	for tbl, rows := range baseline {
		assert.Equalf(t, rows, after[tbl],
			"projection table %q not byte-identical after prune@N + restore-snapshot + replay>N — snapshot/replay infidelity (spec 19 AC 17)", tbl)
	}
}

// TestRebuildAllFromSnapshot_RejectsZeroCheckpoint pins that a snapshot
// with a non-positive UpToSeq is refused rather than restoring an empty
// projection and silently "succeeding".
func TestRebuildAllFromSnapshot_RejectsZeroCheckpoint(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	_, err := st.RebuildAllFromSnapshot(ctx, store.Snapshot{UpToSeq: 0})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upToSeq must be positive")
}
