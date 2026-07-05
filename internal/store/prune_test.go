package store_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// Spec 19 retention (PR C1): the sanctioned prune exemption to the
// append-only event log. AC 19 (delete only through the privileged
// path + EventLogPruned in-tx), AC 20 (non-prune mutation still
// rejected), AC 24 (EventLogPruned itself exempt from pruning).

func maxSeq(t *testing.T, st *store.Store) int64 {
	t.Helper()
	var n int64
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		`SELECT COALESCE(MAX(sequence_num), 0) FROM events`).Scan(&n))
	return n
}

func eventCount(t *testing.T, st *store.Store) int64 {
	t.Helper()
	var n int64
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		`SELECT COUNT(*) FROM events`).Scan(&n))
	return n
}

func countByType(t *testing.T, st *store.Store, eventType string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		`SELECT COUNT(*) FROM events WHERE event_type = $1`, eventType).Scan(&n))
	return n
}

// TestPruneEventsUpTo_DeletesAndAppendsPrunedEvent pins AC 19: events
// ≤ N are deleted and a single EventLogPruned is appended in the same
// transaction; the pruned event survives (its seq > N).
func TestPruneEventsUpTo_DeletesAndAppendsPrunedEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	// Seed some history.
	testutil.CreateTestUser(t, st, "prune-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")
	testutil.CreateTestDevice(t, st, "prune-host-"+testutil.NewID()[:6])
	checkpoint := maxSeq(t, st)
	require.Positive(t, checkpoint)
	before := eventCount(t, st)

	deleted, err := st.PruneEventsUpTo(ctx, checkpoint, "prune-000001", "abc123sha")
	require.NoError(t, err)
	assert.Positive(t, deleted, "some events ≤ N were deleted")

	// Exactly one EventLogPruned, and it survived (seq > N).
	assert.Equal(t, int64(1), countByType(t, st, "EventLogPruned"))
	// Every remaining event is either > N or the pruned marker.
	var belowN int64
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM events WHERE sequence_num <= $1 AND event_type <> 'EventLogPruned'`,
		checkpoint).Scan(&belowN))
	assert.Zero(t, belowN, "no non-prune event ≤ N may remain")
	assert.Less(t, eventCount(t, st), before, "the log shrank")
}

// TestEvents_NonPruneMutationStillRejected pins AC 20: any DELETE /
// UPDATE / TRUNCATE on events OUTSIDE the sanctioned prune path is
// still rejected by the append-only trigger.
func TestEvents_NonPruneMutationStillRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	testutil.CreateTestUser(t, st, "guard-"+testutil.NewID()[:8]+"@test.com", "pass", "user")

	// Plain DELETE (no prune guard set) — rejected.
	_, err := st.TestingPool().Exec(ctx, `DELETE FROM events WHERE sequence_num >= 1`)
	require.Error(t, err, "unguarded DELETE must be rejected")
	assert.Contains(t, err.Error(), "append-only")

	// UPDATE — rejected even with the prune guard set (only DELETE is exempt).
	_, err = st.TestingPool().Exec(ctx,
		`BEGIN; SET LOCAL pm.prune_active = 'on'; SET LOCAL pm.prune_up_to_seq = '999999';
		 UPDATE events SET actor_id = 'x' WHERE sequence_num >= 1; COMMIT;`)
	require.Error(t, err, "UPDATE must be rejected even under the prune guard")

	// TRUNCATE — rejected even under the guard.
	_, err = st.TestingPool().Exec(ctx,
		`BEGIN; SET LOCAL pm.prune_active = 'on'; SET LOCAL pm.prune_up_to_seq = '999999';
		 TRUNCATE events; COMMIT;`)
	require.Error(t, err, "TRUNCATE must be rejected even under the prune guard")

	// Events survived every rejected attempt.
	assert.Positive(t, eventCount(t, st))
}

// TestEvents_GuardedDeleteWithoutMarkerRejected pins the spec's double
// condition on the prune exemption (spec 19 tech design): a DELETE is
// sanctioned only when the SET LOCAL guard is set AND an EventLogPruned
// marker was appended in the SAME transaction. A session that sets both
// guards but appends no marker (e.g. leaked DB credentials trying to
// silently erase history) must still be rejected — otherwise the
// tamper-evidence chain has a hole the Go method alone cannot close.
func TestEvents_GuardedDeleteWithoutMarkerRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	testutil.CreateTestUser(t, st, "nomarker-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	before := eventCount(t, st)
	require.Positive(t, before)

	_, err := st.TestingPool().Exec(ctx,
		`BEGIN; SET LOCAL pm.prune_active = 'on'; SET LOCAL pm.prune_up_to_seq = '999999';
		 DELETE FROM events WHERE sequence_num >= 1; COMMIT;`)
	require.Error(t, err,
		"a guarded DELETE with no in-tx EventLogPruned marker must be rejected (double condition)")
	assert.Contains(t, err.Error(), "append-only")
	assert.Equal(t, before, eventCount(t, st), "no event may be deleted without the marker")
}

// TestEvents_MarkerRowsNotDeletableEvenUnderGuard pins AC 24 at the DB
// layer: EventLogPruned rows themselves are never deletable, even inside
// a fully-sanctioned prune transaction — the prune chain must stay
// visible in the live log forever.
func TestEvents_MarkerRowsNotDeletableEvenUnderGuard(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	testutil.CreateTestUser(t, st, "keepmark-"+testutil.NewID()[:8]+"@test.com", "pass", "user")

	// A real prune leaves a marker behind.
	_, err := st.PruneEventsUpTo(ctx, maxSeq(t, st), "prune-keepmark", "sha")
	require.NoError(t, err)
	require.Equal(t, int64(1), countByType(t, st, store.EventLogPrunedType))

	// Even a fully-guarded transaction that appends a fresh marker cannot
	// delete an existing marker row.
	markerSeq := maxSeq(t, st) // the marker is the highest surviving event
	_, err = st.TestingPool().Exec(ctx, fmt.Sprintf(
		`BEGIN; SET LOCAL pm.prune_active = 'on'; SET LOCAL pm.prune_up_to_seq = '%d';
		 INSERT INTO events (id, stream_type, stream_id, stream_version, event_type, data, metadata, actor_type, actor_id)
		 VALUES ('01JZZZZZZZZZZZZZZZZZZZZZZZ', 'retention', 'global', 999, 'EventLogPruned',
		         '{"up_to_seq": %d, "archive_ref": "x", "archive_sha256": "x"}', '{}', 'system', 'attacker');
		 DELETE FROM events WHERE event_type = 'EventLogPruned' AND sequence_num <= %d; COMMIT;`,
		markerSeq, markerSeq, markerSeq))
	require.Error(t, err, "EventLogPruned rows must never be deletable, even under a sanctioned guard")
	assert.GreaterOrEqual(t, countByType(t, st, store.EventLogPrunedType), int64(1),
		"the prune chain survives")
}

// TestPruneEventsUpTo_RangeBounded pins that the guard bounds deletion
// to the archived checkpoint: an event with seq > N is never deleted,
// even inside the prune transaction.
func TestPruneEventsUpTo_RangeBounded(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	testutil.CreateTestUser(t, st, "range-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	checkpoint := maxSeq(t, st)
	// More history AFTER the checkpoint.
	testutil.CreateTestDevice(t, st, "range-host-"+testutil.NewID()[:6])
	afterCheckpoint := maxSeq(t, st)
	require.Greater(t, afterCheckpoint, checkpoint)

	_, err := st.PruneEventsUpTo(ctx, checkpoint, "prune-000001", "sha")
	require.NoError(t, err)

	var survivingAbove int64
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM events WHERE sequence_num > $1 AND event_type <> 'EventLogPruned'`,
		checkpoint).Scan(&survivingAbove))
	assert.Positive(t, survivingAbove, "events > N must survive a prune at N")
}

// TestPruneEventsUpTo_LaterPruneKeepsPriorPrunedEvents pins AC 24: a
// later prune at a higher checkpoint does NOT delete earlier
// EventLogPruned markers — the prune chain stays visible in the live
// log.
func TestPruneEventsUpTo_LaterPruneKeepsPriorPrunedEvents(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	testutil.CreateTestUser(t, st, "chain-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	cp1 := maxSeq(t, st)
	_, err := st.PruneEventsUpTo(ctx, cp1, "prune-000001", "sha1")
	require.NoError(t, err)

	testutil.CreateTestDevice(t, st, "chain-host-"+testutil.NewID()[:6])
	cp2 := maxSeq(t, st)
	_, err = st.PruneEventsUpTo(ctx, cp2, "prune-000002", "sha2")
	require.NoError(t, err)

	assert.Equal(t, int64(2), countByType(t, st, "EventLogPruned"),
		"a later prune must retain the earlier EventLogPruned marker (AC 24)")
}

// TestEventLogPrunedType_MatchesEventtypes pins the store's hardcoded
// EventLogPrunedType to the eventtypes source of truth — the store
// deliberately avoids importing eventtypes, so a rename there must not
// silently diverge the prune marker's event_type.
func TestEventLogPrunedType_MatchesEventtypes(t *testing.T) {
	assert.Equal(t, string(eventtypes.EventLogPruned), store.EventLogPrunedType,
		"store.EventLogPrunedType must track eventtypes.EventLogPruned")
}
