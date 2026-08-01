package store_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/jobs"
	"github.com/manchtools/power-manage/server/internal/store"
)

type jobFixture struct {
	store   *store.Store
	raw     *pgxpool.Pool
	now     time.Time
	jobID   string
	worker1 string
	worker2 string
	service *jobs.Service
}

func newJobFixture(t *testing.T) *jobFixture {
	t.Helper()
	st, raw := setupPostgres(t)
	now := time.Date(2026, 8, 1, 13, 0, 0, 0, time.UTC)
	op := mutationOp()
	op.OperationID = newID()
	op.RequestDescriptor = "jobs.test/enqueue"
	var jobID string
	_, err := st.WithAudit(context.Background(), op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		var err error
		jobID, err = jobs.InsertInTx(ctx, tx, rec, jobs.InsertParams{
			OperationID: op.OperationID,
			Kind:        "retention.sweep",
			Payload:     json.RawMessage(`{"stream":"control"}`),
			DueAt:       now,
			MaxAttempts: 3,
			DedupeKey:   "retention.sweep",
		})
		return err
	})
	require.NoError(t, err)
	f := &jobFixture{store: st, raw: raw, now: now, jobID: jobID, worker1: newID(), worker2: newID()}
	f.service = jobs.New(jobs.Config{
		Store: st, Now: func() time.Time { return f.now }, LeaseDuration: time.Minute, RetryDelay: 30 * time.Second,
	})
	return f
}

func TestJob_InsertCommitsBoundedPayloadWithAudit(t *testing.T) {
	f := newJobFixture(t)
	row, err := f.store.GetJob(context.Background(), f.jobID)
	require.NoError(t, err)
	assert.Equal(t, jobs.StatePending, row.State)
	assert.Equal(t, "retention.sweep", row.Kind)
	assert.JSONEq(t, `{"stream":"control"}`, string(row.Payload))
	require.NotNil(t, row.DedupeKey)
	assert.Equal(t, "retention.sweep", *row.DedupeKey)

	var action string
	require.NoError(t, f.raw.QueryRow(context.Background(), `
		SELECT action FROM audit_effects
		WHERE resource_type = 'job' AND resource_id = $1
	`, f.jobID).Scan(&action))
	assert.Equal(t, "CREATE", action)
}

func TestJob_InsertRejectsUnboundedOrAmbiguousWork(t *testing.T) {
	f := newJobFixture(t)
	tests := map[string]jobs.InsertParams{
		"array payload": {
			Kind: "retention.sweep", Payload: json.RawMessage(`[]`), DueAt: f.now, MaxAttempts: 3,
		},
		"oversized payload": {
			Kind: "retention.sweep", Payload: json.RawMessage(`{"value":"` + strings.Repeat("x", 65536) + `"}`),
			DueAt: f.now, MaxAttempts: 3,
		},
		"unbounded attempts": {
			Kind: "retention.sweep", Payload: json.RawMessage(`{}`), DueAt: f.now, MaxAttempts: 101,
		},
		"invalid dedupe key": {
			Kind: "retention.sweep", Payload: json.RawMessage(`{}`), DueAt: f.now, MaxAttempts: 3, DedupeKey: "spaces are not tokens",
		},
	}
	for name, params := range tests {
		t.Run(name, func(t *testing.T) {
			op := mutationOp()
			op.OperationID = newID()
			params.OperationID = op.OperationID
			_, err := f.store.WithAudit(context.Background(), op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
				_, err := jobs.InsertInTx(ctx, tx, rec, params)
				return err
			})
			assert.ErrorIs(t, err, jobs.ErrInvalidInput)
		})
	}
	var count int
	require.NoError(t, f.raw.QueryRow(context.Background(), `SELECT count(*) FROM jobs`).Scan(&count))
	assert.Equal(t, 1, count)
}

func TestJob_LeaseRetryAndCompletionRejectStaleWorkers(t *testing.T) {
	f := newJobFixture(t)
	ctx := context.Background()

	row, changed, err := f.service.Claim(ctx, f.jobID, f.worker1)
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, jobs.StateClaimed, row.State)
	assert.Equal(t, f.worker1, row.ClaimedBy)

	_, changed, err = f.service.Claim(ctx, f.jobID, f.worker2)
	require.NoError(t, err)
	assert.False(t, changed, "a live lease admits exactly one worker")
	changed, err = f.service.Release(ctx, f.jobID, f.worker2, "RETRY")
	assert.ErrorIs(t, err, jobs.ErrClaimLost)
	assert.False(t, changed)
	changed, err = f.service.Release(ctx, f.jobID, f.worker1, "RETRY")
	require.NoError(t, err)
	assert.True(t, changed)

	_, changed, err = f.service.Claim(ctx, f.jobID, f.worker2)
	require.NoError(t, err)
	assert.False(t, changed, "retry delay must be durable")
	f.now = f.now.Add(31 * time.Second)
	_, changed, err = f.service.Claim(ctx, f.jobID, f.worker2)
	require.NoError(t, err)
	assert.True(t, changed)
	changed, err = f.service.Finish(ctx, f.jobID, f.worker1, jobs.StateSucceeded, "OK")
	assert.ErrorIs(t, err, jobs.ErrClaimLost)
	assert.False(t, changed)
	changed, err = f.service.Finish(ctx, f.jobID, f.worker2, jobs.StateSucceeded, "OK")
	require.NoError(t, err)
	assert.True(t, changed)
	changed, err = f.service.Finish(ctx, f.jobID, f.worker2, jobs.StateSucceeded, "OK")
	require.NoError(t, err)
	assert.False(t, changed, "terminal replay must be absorbed")

	var actions []string
	require.NoError(t, f.raw.QueryRow(ctx, `
		SELECT array_agg(action ORDER BY chain_seq)
		FROM audit_effects WHERE resource_type = 'job' AND resource_id = $1
	`, f.jobID).Scan(&actions))
	assert.Equal(t, []string{"CREATE", "CLAIM", "RELEASE", "CLAIM", "COMPLETE"}, actions)
}

func TestJob_ConcurrentClaimsHaveOneWinner(t *testing.T) {
	f := newJobFixture(t)
	type result struct {
		changed bool
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for _, workerID := range []string{f.worker1, f.worker2} {
		go func() {
			<-start
			_, changed, err := f.service.Claim(context.Background(), f.jobID, workerID)
			results <- result{changed: changed, err: err}
		}()
	}
	close(start)
	winners := 0
	for range 2 {
		got := <-results
		require.NoError(t, got.err)
		if got.changed {
			winners++
		}
	}
	assert.Equal(t, 1, winners)
	var claims int
	require.NoError(t, f.raw.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_effects
		WHERE resource_type = 'job' AND resource_id = $1 AND action = 'CLAIM'
	`, f.jobID).Scan(&claims))
	assert.Equal(t, 1, claims)
}

func TestJob_ExpiredLeaseIsReclaimedAndOldWorkerCannotFinish(t *testing.T) {
	f := newJobFixture(t)
	ctx := context.Background()
	_, changed, err := f.service.Claim(ctx, f.jobID, f.worker1)
	require.NoError(t, err)
	require.True(t, changed)
	f.now = f.now.Add(2 * time.Minute)
	row, changed, err := f.service.Claim(ctx, f.jobID, f.worker2)
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, f.worker2, row.ClaimedBy)
	assert.Equal(t, int32(2), row.AttemptCount)
	changed, err = f.service.Finish(ctx, f.jobID, f.worker1, jobs.StateSucceeded, "OK")
	assert.ErrorIs(t, err, jobs.ErrClaimLost)
	assert.False(t, changed)
}

func TestJob_CompletionAuditFailureRollsBackState(t *testing.T) {
	f := newJobFixture(t)
	ctx := context.Background()
	_, changed, err := f.service.Claim(ctx, f.jobID, f.worker1)
	require.NoError(t, err)
	require.True(t, changed)
	_, err = f.raw.Exec(ctx, `ALTER TABLE audit_effects ADD CONSTRAINT reject_job_complete CHECK (action <> 'COMPLETE')`)
	require.NoError(t, err)

	changed, err = f.service.Finish(ctx, f.jobID, f.worker1, jobs.StateSucceeded, "OK")
	require.Error(t, err)
	assert.False(t, changed)
	row, getErr := f.store.GetJob(ctx, f.jobID)
	require.NoError(t, getErr)
	assert.Equal(t, jobs.StateClaimed, row.State)
	assert.Equal(t, f.worker1, row.ClaimedBy)
}
