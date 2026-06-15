package dyngroupeval_test

import (
	"context"
	"log/slog"
	"sort"
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

// ---------------------------------------------------------------------------
// Membership reconciliation (#12) — the drain tests above only proved the queue
// lifecycle; these pin the actual add/remove of members and the short-circuits.
// ---------------------------------------------------------------------------

func execSQL(t *testing.T, st *store.Store, sql string, args ...any) {
	t.Helper()
	_, err := st.TestingPool().Exec(context.Background(), sql, args...)
	require.NoError(t, err)
}

func deviceMembers(t *testing.T, st *store.Store, groupID string) []string {
	t.Helper()
	rows, err := st.TestingPool().Query(context.Background(),
		`SELECT device_id FROM device_group_members_projection WHERE group_id = $1`, groupID)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		out = append(out, id)
	}
	require.NoError(t, rows.Err())
	sort.Strings(out)
	return out
}

func deviceQueueCount(t *testing.T, st *store.Store, groupID string) int {
	t.Helper()
	var n int
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		`SELECT count(*) FROM dynamic_group_evaluation_queue WHERE group_id = $1`, groupID).Scan(&n))
	return n
}

// TestEvaluateDeviceGroup_AddsAndRemovesMembers pins reconciliation in BOTH
// directions in a single evaluation: a now-matching device is inserted and a
// stale member that no longer matches is deleted.
func TestEvaluateDeviceGroup_AddsAndRemovesMembers(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	dMatch := testutil.CreateTestDevice(t, st, "prod-host")
	dStale := testutil.CreateTestDevice(t, st, "dev-host")
	execSQL(t, st, `INSERT INTO device_labels (device_id, key, value) VALUES ($1, 'env', 'prod')`, dMatch)
	execSQL(t, st, `INSERT INTO device_labels (device_id, key, value) VALUES ($1, 'env', 'dev')`, dStale)

	groupID := testutil.NewID()
	execSQL(t, st, `INSERT INTO device_groups_projection (id, name, is_dynamic, dynamic_query) VALUES ($1, 'dyn', TRUE, $2)`,
		groupID, `labels.env equals "prod"`)
	// dStale is a leftover member that no longer matches.
	execSQL(t, st, `INSERT INTO device_group_members_projection (group_id, device_id) VALUES ($1, $2)`, groupID, dStale)
	enqueueDeviceGroup(t, st, groupID)

	require.NoError(t, dyngroupeval.New(st, slog.Default()).EvaluateDeviceGroup(ctx, groupID))
	assert.Equal(t, []string{dMatch}, deviceMembers(t, st, groupID),
		"matching device added, stale non-matching device removed")
}

// TestEvaluateUserGroup_AddsAndRemovesMembers — same reconciliation for user
// groups, matching on user.email.
func TestEvaluateUserGroup_AddsAndRemovesMembers(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	uMatch := testutil.CreateTestUser(t, st, "alice@prod.example", "pw", "user")
	uStale := testutil.CreateTestUser(t, st, "bob@dev.example", "pw", "user")

	groupID := testutil.NewID()
	execSQL(t, st, `INSERT INTO user_groups_projection (id, name, is_dynamic, dynamic_query) VALUES ($1, 'dyn', TRUE, $2)`,
		groupID, `user.email endsWith "@prod.example"`)
	execSQL(t, st, `INSERT INTO user_group_members_projection (group_id, user_id) VALUES ($1, $2)`, groupID, uStale)
	reason := "test"
	require.NoError(t, st.Queries().EnqueueDynamicUserGroupEvaluation(ctx,
		db.EnqueueDynamicUserGroupEvaluationParams{GroupID: groupID, Reason: &reason}))

	require.NoError(t, dyngroupeval.New(st, slog.Default()).EvaluateUserGroup(ctx, groupID))

	rows, err := st.TestingPool().Query(ctx, `SELECT user_id FROM user_group_members_projection WHERE group_id = $1`, groupID)
	require.NoError(t, err)
	defer rows.Close()
	var members []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		members = append(members, id)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{uMatch}, members, "matching user added, stale non-matching user removed")
}

// TestEvaluateDeviceGroup_NonDynamicOrMissingClearsQueueNoOp pins the two
// short-circuits: a non-dynamic group and a missing group each clear their queue
// row and write no membership.
func TestEvaluateDeviceGroup_NonDynamicOrMissingClearsQueueNoOp(t *testing.T) {
	ctx := context.Background()

	t.Run("non-dynamic group clears queue, no membership", func(t *testing.T) {
		st := testutil.SetupPostgres(t)
		actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.co", "pw", "admin")
		groupID := testutil.CreateTestDeviceGroup(t, st, actor, "static")
		enqueueDeviceGroup(t, st, groupID)

		require.NoError(t, dyngroupeval.New(st, slog.Default()).EvaluateDeviceGroup(ctx, groupID))
		assert.Equal(t, 0, deviceQueueCount(t, st, groupID), "queue row cleared for a non-dynamic group")
		assert.Empty(t, deviceMembers(t, st, groupID), "no membership written for a non-dynamic group")
	})

	t.Run("missing group clears queue", func(t *testing.T) {
		st := testutil.SetupPostgres(t)
		groupID := testutil.NewID() // never created
		enqueueDeviceGroup(t, st, groupID)

		require.NoError(t, dyngroupeval.New(st, slog.Default()).EvaluateDeviceGroup(ctx, groupID))
		assert.Equal(t, 0, deviceQueueCount(t, st, groupID), "queue row cleared for a missing group")
	})
}

// TestEvaluateDeviceGroup_ParseErrorLeavesQueueIntact pins the fail-safe: an
// unparseable dynamic_query returns an error, writes no membership, and leaves
// the queue row intact so a fixed query re-queues and re-evaluates.
func TestEvaluateDeviceGroup_ParseErrorLeavesQueueIntact(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	device := testutil.CreateTestDevice(t, st, "host")
	execSQL(t, st, `INSERT INTO device_labels (device_id, key, value) VALUES ($1, 'env', 'prod')`, device)

	groupID := testutil.NewID()
	// "equalz" is not a valid operator — the parser rejects it.
	execSQL(t, st, `INSERT INTO device_groups_projection (id, name, is_dynamic, dynamic_query) VALUES ($1, 'dyn', TRUE, $2)`,
		groupID, `labels.env equalz "prod"`)
	enqueueDeviceGroup(t, st, groupID)

	err := dyngroupeval.New(st, slog.Default()).EvaluateDeviceGroup(ctx, groupID)
	require.Error(t, err, "an unparseable dynamic_query must surface an error")
	assert.Equal(t, 1, deviceQueueCount(t, st, groupID), "the queue row must survive a parse error so a fix re-queues")
	assert.Empty(t, deviceMembers(t, st, groupID), "no membership written on a parse error")
}
