package store_test

// Drain-loop edge-case coverage for evaluate_queued_dynamic_groups
// (manchtools/power-manage-server#168). The function used to return
// just a count, and the cmd/control drain loop inferred queue-empty
// from "count < batch_limit" — fine in the common case but wrong on
// a count == batch_limit boundary hit, which would fire one extra
// round-trip before observing the empty queue.
//
// Migration 044 added a `more` flag to the return tuple so the
// caller can terminate explicitly. These tests pin both behaviours:
// `more` is true while the queue still has rows after the batch,
// and false once it's drained.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// queueDynamicGroup inserts a single row into
// dynamic_group_evaluation_queue, which is the queue the drain loop
// in evaluate_queued_dynamic_groups consumes. Going through SQL
// directly (rather than triggering via DeviceAddedToGroup events)
// keeps the test focused on the drain-loop boundary semantics
// without needing the full dynamic-query evaluator wired up.
func queueDynamicGroup(t *testing.T, st *store.Store, groupID string, queuedAt time.Time) {
	t.Helper()
	_, err := st.Pool().Exec(context.Background(),
		`INSERT INTO dynamic_group_evaluation_queue (group_id, queued_at, reason)
		 VALUES ($1, $2, 'test')
		 ON CONFLICT (group_id) DO UPDATE SET queued_at = EXCLUDED.queued_at`,
		groupID, queuedAt,
	)
	require.NoError(t, err)
}

// drainEvalQueues clears any rows that triggers (queue_dynamic_groups_for_device,
// etc.) inserted as side effects of the test fixture setup. Lets each
// test reason about its own seeded count without leakage from device
// / group create-time triggers.
func drainEvalQueues(t *testing.T, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	_, err := st.Pool().Exec(ctx, "TRUNCATE dynamic_group_evaluation_queue, dynamic_user_group_evaluation_queue")
	require.NoError(t, err)
}

func TestEvaluateQueuedDynamicGroups_EmptyQueue_MoreFalseCountZero(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	drainEvalQueues(t, st)

	r, err := st.Queries().EvaluateQueuedDynamicGroups(ctx)
	require.NoError(t, err)
	assert.Equal(t, int32(0), r.EvaluatedCount)
	assert.False(t, r.More, "an empty queue must report more=false so the drain loop terminates")
}

func TestEvaluateQueuedDynamicGroups_BelowBatchLimit_MoreFalse(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	drainEvalQueues(t, st)
	actor := testutil.NewID()

	// Queue 5 dynamic groups (well below the 1000 batch limit).
	now := time.Now()
	for i := 0; i < 5; i++ {
		gid := testutil.CreateTestDeviceGroup(t, st, actor, fmt.Sprintf("dyn-%d", i))
		queueDynamicGroup(t, st, gid, now.Add(time.Duration(i)*time.Millisecond))
	}

	r, err := st.Queries().EvaluateQueuedDynamicGroups(ctx)
	require.NoError(t, err)
	assert.Equal(t, int32(5), r.EvaluatedCount)
	assert.False(t, r.More, "a sub-batch run drains the queue and must report more=false")
}

func TestEvaluateQueuedDynamicGroups_OverBatchLimit_MoreTrueThenFalse(t *testing.T) {
	// Two batches: queue exactly batch_limit + 1 rows so the first
	// invocation hits the limit and reports more=true; the second
	// invocation processes the leftover and reports more=false.
	// Validates the explicit `more` signal on the boundary the
	// inference-shape used to get wrong.
	if testing.Short() {
		t.Skip("seeds 1001 dynamic groups; skip in -short")
	}
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	drainEvalQueues(t, st)
	actor := testutil.NewID()

	now := time.Now()
	const seedCount = 1001 // one over the 1000 batch limit
	for i := 0; i < seedCount; i++ {
		gid := testutil.CreateTestDeviceGroup(t, st, actor, fmt.Sprintf("dyn-%d", i))
		queueDynamicGroup(t, st, gid, now.Add(time.Duration(i)*time.Millisecond))
	}

	first, err := st.Queries().EvaluateQueuedDynamicGroups(ctx)
	require.NoError(t, err)
	assert.Equal(t, int32(1000), first.EvaluatedCount)
	assert.True(t, first.More, "1001 rows queued, batch_limit=1000 — first batch must report more=true")

	second, err := st.Queries().EvaluateQueuedDynamicGroups(ctx)
	require.NoError(t, err)
	assert.Equal(t, int32(1), second.EvaluatedCount)
	assert.False(t, second.More, "after second batch consumes the leftover, more must be false")
}

// User-group variant — same shape, different batch limit (100).
func TestEvaluateQueuedDynamicUserGroups_EmptyQueue_MoreFalse(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	drainEvalQueues(t, st)

	r, err := st.Queries().EvaluateQueuedDynamicUserGroups(ctx)
	require.NoError(t, err)
	assert.Equal(t, int32(0), r.EvaluatedCount)
	assert.False(t, r.More)
}
