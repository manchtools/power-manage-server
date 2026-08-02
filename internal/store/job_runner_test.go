package store_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/jobs"
)

func waitForJobState(t *testing.T, f *jobFixture, state string) {
	waitForJobIDState(t, f, f.jobID, state)
}

func waitForJobIDState(t *testing.T, f *jobFixture, jobID, state string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		row, err := f.store.GetJob(context.Background(), jobID)
		require.NoError(t, err)
		if row.State == state {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job did not reach %s", state)
}

func newJobRunner(f *jobFixture, handlers map[string]jobs.Handler, poll time.Duration, logger *slog.Logger) *jobs.Runner {
	return jobs.NewRunner(jobs.RunnerConfig{
		Store: f.store, State: f.service, Handlers: handlers, Logger: logger,
		Now: func() time.Time { return f.now }, PollInterval: poll,
		Workers: 1, QueueSize: 8, BatchSize: 32,
	})
}

func TestJobRunner_WakeExecutesAndFinishesDueJob(t *testing.T) {
	f := newJobFixture(t)
	handled := make(chan jobs.Job, 1)
	runner := newJobRunner(f, map[string]jobs.Handler{
		"retention.sweep": func(_ context.Context, job jobs.Job) error {
			handled <- job
			return nil
		},
	}, time.Hour, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	require.True(t, runner.Wake(f.jobID))
	select {
	case job := <-handled:
		assert.Equal(t, f.jobID, job.ID)
		assert.Equal(t, "retention.sweep", job.Kind)
		assert.JSONEq(t, `{"stream":"control"}`, string(job.Payload))
	case <-time.After(2 * time.Second):
		t.Fatal("job wake was not executed")
	}
	waitForJobState(t, f, jobs.StateSucceeded)
	row, err := f.store.GetJob(context.Background(), f.jobID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), row.AttemptCount)
	assert.Equal(t, "OK", row.ResultCode)
	assert.ErrorIs(t, runner.Run(context.Background()), jobs.ErrAlreadyRunning)
	cancel()
	require.NoError(t, <-done)
}

func TestJobRunner_RecurringSuccessReschedulesTheSameDurableRow(t *testing.T) {
	f := newJobFixture(t)
	runner := jobs.NewRunner(jobs.RunnerConfig{
		Store: f.store, State: f.service,
		Handlers: map[string]jobs.Handler{
			"retention.sweep": func(context.Context, jobs.Job) error { return nil },
		},
		Recurring: map[string]time.Duration{"retention.sweep": time.Hour},
		Now:       func() time.Time { return f.now },
		Workers:   1, QueueSize: 1, BatchSize: 1, PollInterval: time.Hour,
	})

	require.NoError(t, runner.Dispatch(context.Background(), f.jobID))
	row, err := f.store.GetJob(context.Background(), f.jobID)
	require.NoError(t, err)
	assert.Equal(t, jobs.StatePending, row.State)
	assert.True(t, row.DueAt.Equal(f.now.Add(time.Hour)))
	assert.Zero(t, row.AttemptCount, "a successful interval starts with a fresh retry budget")
	assert.Equal(t, "OK", row.ResultCode)

	actions := auditActions(t, f.raw, "job", f.jobID)
	assert.Equal(t, []string{"CREATE", "CLAIM", "RESCHEDULE"}, actions)
}

func TestJobRunner_SweepReclaimsExpiredLease(t *testing.T) {
	f := newJobFixture(t)
	_, changed, err := f.service.Claim(context.Background(), f.jobID, f.worker1)
	require.NoError(t, err)
	require.True(t, changed)
	f.now = f.now.Add(2 * time.Minute)
	handled := make(chan struct{}, 1)
	runner := newJobRunner(f, map[string]jobs.Handler{
		"retention.sweep": func(context.Context, jobs.Job) error {
			handled <- struct{}{}
			return nil
		},
	}, 10*time.Millisecond, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	select {
	case <-handled:
	case <-time.After(2 * time.Second):
		t.Fatal("expired lease was not recovered by the database sweep")
	}
	waitForJobState(t, f, jobs.StateSucceeded)
	row, err := f.store.GetJob(context.Background(), f.jobID)
	require.NoError(t, err)
	assert.Equal(t, int32(2), row.AttemptCount)
	cancel()
	require.NoError(t, <-done)
}

func TestJobRunner_FailuresUseFixedCodesAndStopAtAttemptLimit(t *testing.T) {
	f := newJobFixture(t)
	_, err := f.raw.Exec(context.Background(), `UPDATE jobs SET max_attempts = 2 WHERE job_id = $1`, f.jobID)
	require.NoError(t, err)
	const secretError = "database failed for password=hunter2"
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	runner := newJobRunner(f, map[string]jobs.Handler{
		"retention.sweep": func(context.Context, jobs.Job) error { return errors.New(secretError) },
	}, time.Hour, logger)

	require.NoError(t, runner.Dispatch(context.Background(), f.jobID))
	row, err := f.store.GetJob(context.Background(), f.jobID)
	require.NoError(t, err)
	assert.Equal(t, jobs.StatePending, row.State)
	assert.Equal(t, "RETRY", row.ResultCode)
	f.now = f.now.Add(31 * time.Second)
	require.NoError(t, runner.Dispatch(context.Background(), f.jobID))
	row, err = f.store.GetJob(context.Background(), f.jobID)
	require.NoError(t, err)
	assert.Equal(t, jobs.StateFailed, row.State)
	assert.Equal(t, "MAX_ATTEMPTS", row.ResultCode)
	assert.NotContains(t, logs.String(), secretError)
	assert.NotContains(t, string(row.Payload), "hunter2")
	var auditText string
	require.NoError(t, f.raw.QueryRow(context.Background(), `
		SELECT coalesce(string_agg(result_code, ' '), '')
		FROM audit_operations WHERE operation_id IN (
			SELECT operation_id FROM audit_effects WHERE resource_type = 'job' AND resource_id = $1
		)
	`, f.jobID).Scan(&auditText))
	assert.NotContains(t, auditText, "hunter2")
}

func TestJobRunner_UnknownKindFailsWithoutExecutingAnything(t *testing.T) {
	f := newJobFixture(t)
	runner := newJobRunner(f, nil, time.Hour, slog.Default())
	require.NoError(t, runner.Dispatch(context.Background(), f.jobID))
	row, err := f.store.GetJob(context.Background(), f.jobID)
	require.NoError(t, err)
	assert.Equal(t, jobs.StateFailed, row.State)
	assert.Equal(t, "UNKNOWN_KIND", row.ResultCode)
}

func TestJobRunner_HandlerPanicIsContainedAndNextJobRuns(t *testing.T) {
	f := newJobFixture(t)
	ctx := context.Background()
	_, err := f.raw.Exec(ctx, `UPDATE jobs SET due_at = $2, max_attempts = 1 WHERE job_id = $1`, f.jobID, f.now.Add(-time.Minute))
	require.NoError(t, err)
	secondID := newID()
	_, err = f.raw.Exec(ctx, `
		INSERT INTO jobs (job_id, kind, payload, state, due_at, max_attempts)
		VALUES ($1, 'retention.sweep', '{}', 'PENDING', $2, 1)
	`, secondID, f.now)
	require.NoError(t, err)
	secondRan := make(chan struct{}, 1)
	var logs bytes.Buffer
	runner := newJobRunner(f, map[string]jobs.Handler{
		"retention.sweep": func(_ context.Context, job jobs.Job) error {
			if job.ID == f.jobID {
				panic("password=hunter2")
			}
			secondRan <- struct{}{}
			return nil
		},
	}, 10*time.Millisecond, slog.New(slog.NewTextHandler(&logs, nil)))
	runCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- runner.Run(runCtx) }()
	select {
	case <-secondRan:
	case <-time.After(2 * time.Second):
		t.Fatal("a handler panic killed the worker")
	}
	waitForJobState(t, f, jobs.StateFailed)
	waitForJobIDState(t, f, secondID, jobs.StateSucceeded)
	first, err := f.store.GetJob(ctx, f.jobID)
	require.NoError(t, err)
	assert.Equal(t, "HANDLER_PANIC", first.ResultCode)
	assert.NotContains(t, logs.String(), "hunter2")
	cancel()
	require.NoError(t, <-done)
}

func TestJobRunner_WakeQueueIsBounded(t *testing.T) {
	f := newJobFixture(t)
	runner := jobs.NewRunner(jobs.RunnerConfig{
		Store: f.store, State: f.service, PollInterval: time.Hour,
		Workers: 1, QueueSize: 1, BatchSize: 1,
	})
	assert.True(t, runner.Wake(f.jobID))
	assert.False(t, runner.Wake(newID()), "a full job queue must not grow without bound")
}
