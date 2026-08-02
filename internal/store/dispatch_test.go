package store_test

// Delivery and job schema behaviour.
//
// These tables carry their state machines in CHECK constraints and
// their claim semantics in conditional UPDATEs, so the invariants are
// exercised where they live: against the real database, through the
// real statements a dispatcher and a scheduler will issue.

import (
	"context"
	"testing"
	"time"

	"github.com/manchtools/power-manage/server/internal/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedDevice inserts a device deliveries can legitimately belong to.
// A delivery is work for one device, so the row cannot exist without
// one.
func seedDevice(t *testing.T, pool *testdb.DB) string {
	t.Helper()
	id := newID()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO devices (id, hostname, agent_sealing_public_key) VALUES ($1, $2, $3)`,
		id, "dispatch-"+id, make([]byte, 32))
	require.NoError(t, err)
	return id
}

func TestDeliveries_StateMachineRejectsImpossibleRows(t *testing.T) {
	_, pool := setupSQLite(t)
	ctx := context.Background()
	now := time.Now().UTC()
	device := seedDevice(t, pool)

	insert := `INSERT INTO deliveries
		(delivery_id, device_id, manifest_id, manifest, state, pushed_at, acked_receipt_at, terminal_at)
		VALUES ($1, $2, $3, '{}', $4, $5, $6, $7)`

	t.Run("PENDING cannot claim it was pushed", func(t *testing.T) {
		_, err := pool.Exec(ctx, insert, newID(), device, newID(), "PENDING", now, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CASE state")
	})

	t.Run("PUSHED needs a push time", func(t *testing.T) {
		_, err := pool.Exec(ctx, insert, newID(), device, newID(), "PUSHED", nil, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CASE state")
	})

	// Acknowledgement follows DURABLE receipt, never a successful
	// socket write, so a result cannot exist without one.
	t.Run("a result cannot precede a confirmed receipt", func(t *testing.T) {
		_, err := pool.Exec(ctx, insert, newID(), device, newID(), "SUCCEEDED", now, nil, now)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "acked_receipt_at")
	})

	t.Run("expiry may terminate a delivery that was never received", func(t *testing.T) {
		_, err := pool.Exec(ctx, insert, newID(), device, newID(), "EXPIRED", now, nil, now)
		require.NoError(t, err)
	})

	t.Run("a full lifecycle is representable", func(t *testing.T) {
		_, err := pool.Exec(ctx, insert, newID(), device, newID(), "SUCCEEDED", now, now, now)
		require.NoError(t, err)
	})

	t.Run("identifiers must be ULIDs", func(t *testing.T) {
		_, err := pool.Exec(ctx, insert, "delivery-1", device, newID(), "PENDING", nil, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "delivery_id")
	})
}

// A stale connection must not be able to claim a push. push_epoch only
// moves forward, so an older epoch matches zero rows.
func TestDeliveries_StaleEpochCannotClaimAPush(t *testing.T) {
	_, pool := setupSQLite(t)
	ctx := context.Background()
	now := time.Now().UTC()
	device := seedDevice(t, pool)

	id := newID()
	_, err := pool.Exec(ctx, `INSERT INTO deliveries
		(delivery_id, device_id, manifest_id, manifest, state)
		VALUES ($1, $2, $3, '{}', 'PENDING')`, id, device, newID())
	require.NoError(t, err)

	push := `UPDATE deliveries
		SET state = 'PUSHED', pushed_at = $2, push_epoch = $3, attempt_count = attempt_count + 1
		WHERE delivery_id = $1 AND state IN ('PENDING', 'PUSHED') AND push_epoch <= $3`

	tag, err := pool.Exec(ctx, push, id, now, int64(7))
	require.NoError(t, err)
	require.Equal(t, int64(1), tag.RowsAffected())

	tag, err = pool.Exec(ctx, push, id, now, int64(3))
	require.NoError(t, err)
	assert.Zero(t, tag.RowsAffected(), "an older connection epoch must not be able to push")

	var epoch int64
	var attempts int32
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT push_epoch, attempt_count FROM deliveries WHERE delivery_id = $1`, id).
		Scan(&epoch, &attempts))
	assert.Equal(t, int64(7), epoch)
	assert.Equal(t, int32(1), attempts, "attempt counts are diagnostic and must not be bumped by a refused push")
}

// Two workers racing for the same due job produce one winner: the
// second conditional UPDATE matches nothing.
func TestJobs_ConditionalClaimAdmitsExactlyOneWorker(t *testing.T) {
	_, pool := setupSQLite(t)
	ctx := context.Background()
	now := time.Now().UTC()

	id := newID()
	workerA, workerB := newID(), newID()
	_, err := pool.Exec(ctx, `INSERT INTO jobs (job_id, kind, state, due_at)
		VALUES ($1, 'dynamic_group.evaluate', 'PENDING', $2)`, id, now.Add(-time.Minute))
	require.NoError(t, err)

	claim := `UPDATE jobs
		SET state = 'CLAIMED', claimed_at = $2, claimed_until = $3, claimed_by = $4,
		    attempt_count = attempt_count + 1, updated_at = $2
		WHERE job_id = $1
		  AND ((state = 'PENDING' AND due_at <= $2) OR (state = 'CLAIMED' AND claimed_until <= $2))`

	tag, err := pool.Exec(ctx, claim, id, now, now.Add(time.Minute), workerA)
	require.NoError(t, err)
	require.Equal(t, int64(1), tag.RowsAffected())

	tag, err = pool.Exec(ctx, claim, id, now, now.Add(time.Minute), workerB)
	require.NoError(t, err)
	assert.Zero(t, tag.RowsAffected(), "a live claim must not be stealable")

	// Once the lease expires the row is reclaimable, which is how a
	// worker that died holding it does not strand the job.
	later := now.Add(2 * time.Minute)
	tag, err = pool.Exec(ctx, claim, id, later, later.Add(time.Minute), workerB)
	require.NoError(t, err)
	assert.Equal(t, int64(1), tag.RowsAffected(), "an expired lease must be reclaimable")

	var attempts int32
	var by string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT attempt_count, claimed_by FROM jobs WHERE job_id = $1`, id).Scan(&attempts, &by))
	assert.Equal(t, int32(2), attempts)
	assert.Equal(t, workerB, by)
}

// A scheduled singleton cannot be enqueued twice while one is live,
// and becomes enqueueable again once the previous run is terminal.
func TestJobs_DedupeKeyAdmitsOneLiveRow(t *testing.T) {
	_, pool := setupSQLite(t)
	ctx := context.Background()
	now := time.Now().UTC()

	insert := `INSERT INTO jobs (job_id, kind, state, due_at, dedupe_key)
		VALUES ($1, 'retention.sweep', 'PENDING', $2, 'retention.sweep')`

	first := newID()
	_, err := pool.Exec(ctx, insert, first, now)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, insert, newID(), now)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jobs.dedupe_key")

	_, err = pool.Exec(ctx, `UPDATE jobs SET state = 'SUCCEEDED', terminal_at = $2 WHERE job_id = $1`, first, now)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, insert, newID(), now)
	require.NoError(t, err, "a terminal run must not block the next one")
}

func TestJobs_StateMachineRequiresTerminalTimestamps(t *testing.T) {
	_, pool := setupSQLite(t)
	ctx := context.Background()
	now := time.Now().UTC()

	_, err := pool.Exec(ctx, `INSERT INTO jobs (job_id, kind, state, due_at)
		VALUES ($1, 'retention.sweep', 'SUCCEEDED', $2)`, newID(), now)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CASE state")

	_, err = pool.Exec(ctx, `INSERT INTO jobs (job_id, kind, state, due_at, claimed_at)
		VALUES ($1, 'retention.sweep', 'CLAIMED', $2, $2)`, newID(), now)
	require.Error(t, err, "a claim needs both a start and a lease expiry")
	assert.Contains(t, err.Error(), "claimed_at IS NULL")
}
