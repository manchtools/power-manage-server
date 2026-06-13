package dyngroupeval_test

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/dyngroupeval"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func enqueueDeviceGroup(t *testing.T, st *store.Store, groupID string) {
	t.Helper()
	reason := "test"
	require.NoError(t, st.Queries().EnqueueDynamicDeviceGroupEvaluation(context.Background(),
		db.EnqueueDynamicDeviceGroupEvaluationParams{GroupID: groupID, Reason: &reason}))
}

// TestDrainDeviceGroupQueue_DrainsUnderLock pins that the per-group advisory
// claim (#15) does not break the normal drain: an enqueued group is evaluated
// and its queue row consumed.
func TestDrainDeviceGroupQueue_DrainsUnderLock(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ev := dyngroupeval.New(st, slog.Default())
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	// A static group is a valid drain target: EvaluateDeviceGroup clears the
	// queue row for a non-dynamic group. That exercises the lock-wrapped drain
	// loop + dequeue without depending on dynamic-query membership recompute
	// (unchanged by #15).
	g := testutil.CreateTestDeviceGroup(t, st, actor, "Plant X")
	enqueueDeviceGroup(t, st, g)

	res, err := ev.DrainDeviceGroupQueue(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int32(1), res.Count, "the enqueued group must be evaluated under the lock")
	assert.False(t, res.More, "queue must be drained")

	has, err := st.Queries().HasDynamicDeviceGroupQueueEntries(context.Background())
	require.NoError(t, err)
	assert.False(t, has, "queue row must be consumed")
}

// TestDrainDeviceGroupQueue_ConcurrentDrainsSafe pins that two concurrent drains
// (modelling two control replicas) neither error nor leave the queue partially
// drained — the per-group advisory claim serializes same-group evaluation.
func TestDrainDeviceGroupQueue_ConcurrentDrainsSafe(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ev := dyngroupeval.New(st, slog.Default())
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	for i := 0; i < 8; i++ {
		enqueueDeviceGroup(t, st, testutil.CreateTestDeviceGroup(t, st, actor, "G"))
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				res, err := ev.DrainDeviceGroupQueue(context.Background())
				if err != nil {
					errs <- err
					return
				}
				if !res.More {
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	has, err := st.Queries().HasDynamicDeviceGroupQueueEntries(context.Background())
	require.NoError(t, err)
	assert.False(t, has, "concurrent drains must fully consume the queue")
}

// TestDrainUserGroupQueue_DrainsUnderLock is the user-group sibling.
func TestDrainUserGroupQueue_DrainsUnderLock(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ev := dyngroupeval.New(st, slog.Default())
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	g := testutil.CreateTestUserGroup(t, st, actor, "Team X")
	reason := "test"
	require.NoError(t, st.Queries().EnqueueDynamicUserGroupEvaluation(context.Background(),
		db.EnqueueDynamicUserGroupEvaluationParams{GroupID: g, Reason: &reason}))

	res, err := ev.DrainUserGroupQueue(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int32(1), res.Count)
	assert.False(t, res.More)

	has, err := st.Queries().HasDynamicUserGroupQueueEntries(context.Background())
	require.NoError(t, err)
	assert.False(t, has, "queue row must be consumed")
}
