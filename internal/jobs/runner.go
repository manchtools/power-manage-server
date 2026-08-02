package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	defaultPollInterval = time.Second
	defaultWorkers      = 8
	defaultQueueSize    = 1024
	defaultBatchSize    = int32(256)
)

// ErrAlreadyRunning means Run was called twice on one runner.
var ErrAlreadyRunning = errors.New("job runner already running")

// Job is the bounded input handed to a registered handler.
type Job struct {
	ID           string
	Kind         string
	Payload      json.RawMessage
	Attempt      int32
	MaxAttempts  int32
	ScheduledFor time.Time
}

// Handler executes one claimed job. It must be idempotent: a process can die
// after the effect commits but before the job reaches its terminal state.
type Handler func(context.Context, Job) error

// RunnerConfig supplies handlers and process-local concurrency bounds.
type RunnerConfig struct {
	Store        *store.Store
	State        *Service
	Handlers     map[string]Handler
	Recurring    map[string]time.Duration
	Logger       *slog.Logger
	Now          func() time.Time
	PollInterval time.Duration
	Workers      int
	QueueSize    int
	BatchSize    int32
}

// Runner is a bounded in-process executor. PostgreSQL leases are the durable
// queue and crash-recovery mechanism.
type Runner struct {
	store        *store.Store
	state        *Service
	handlers     map[string]Handler
	recurring    map[string]time.Duration
	logger       *slog.Logger
	now          func() time.Time
	pollInterval time.Duration
	workers      int
	batchSize    int32
	queue        chan string
	running      atomic.Bool
}

// NewRunner constructs a job runner and freezes its handler registry.
func NewRunner(cfg RunnerConfig) *Runner {
	if cfg.Store == nil || cfg.State == nil {
		panic("job runner: store and state are required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.Workers == 0 {
		cfg.Workers = defaultWorkers
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = defaultQueueSize
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.PollInterval < 0 || cfg.Workers < 1 || cfg.QueueSize < 1 || cfg.BatchSize < 1 {
		panic("job runner: invalid bounds")
	}
	handlers := make(map[string]Handler, len(cfg.Handlers))
	for kind, handler := range cfg.Handlers {
		if !kindPattern.MatchString(kind) || handler == nil {
			panic("job runner: invalid handler registration")
		}
		handlers[kind] = handler
	}
	recurring := make(map[string]time.Duration, len(cfg.Recurring))
	for kind, interval := range cfg.Recurring {
		if handlers[kind] == nil || interval <= 0 {
			panic("job runner: invalid recurring registration")
		}
		recurring[kind] = interval
	}
	return &Runner{
		store: cfg.Store, state: cfg.State, handlers: handlers, recurring: recurring, logger: cfg.Logger,
		now: cfg.Now, pollInterval: cfg.PollInterval, workers: cfg.Workers,
		batchSize: cfg.BatchSize, queue: make(chan string, cfg.QueueSize),
	}
}

// Wake queues one committed job without blocking the transaction's caller.
// False means the id was invalid or the bounded queue was full; polling remains
// the correctness path.
func (r *Runner) Wake(jobID string) bool {
	if !validID(jobID) {
		return false
	}
	select {
	case r.queue <- jobID:
		return true
	default:
		return false
	}
}

// Run starts the bounded workers and PostgreSQL poller.
func (r *Runner) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidInput
	}
	if !r.running.CompareAndSwap(false, true) {
		return ErrAlreadyRunning
	}
	defer r.running.Store(false)

	var workers sync.WaitGroup
	for range r.workers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			r.worker(ctx)
		}()
	}
	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()
	defer workers.Wait()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.queueDue(ctx); err != nil && !errors.Is(err, context.Canceled) {
				// Query errors can contain driver detail. Keep logs structural so a
				// future handler payload can never be reflected by accident.
				r.logger.Error("job poll failed", "code", "STORE_ERROR")
			}
		}
	}
}

func (r *Runner) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case jobID := <-r.queue:
			if err := r.Dispatch(ctx, jobID); err != nil && !errors.Is(err, context.Canceled) {
				// Handler errors may quote secrets from their payload. Never log the
				// error value here; durable state carries a fixed result code.
				r.logger.Error("job dispatch failed", "job_id", jobID, "code", "RUNNER_ERROR")
			}
		}
	}
}

func (r *Runner) queueDue(ctx context.Context) error {
	rows, err := r.store.ListClaimableJobs(ctx, r.now().UTC(), r.batchSize)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if !r.Wake(row.JobID) {
			break
		}
	}
	return nil
}

// Dispatch claims and executes one job. A fresh claim id is minted for every
// attempt, so a slow attempt cannot finish a lease that a later worker reclaimed.
func (r *Runner) Dispatch(ctx context.Context, jobID string) error {
	if ctx == nil || !validID(jobID) {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	claimID := ulid.Make().String()
	row, changed, err := r.state.Claim(ctx, jobID, claimID)
	if err != nil || !changed {
		return err
	}
	handler, ok := r.handlers[row.Kind]
	if !ok {
		return r.finish(ctx, jobID, claimID, StateFailed, "UNKNOWN_KIND")
	}

	job := Job{
		ID: jobID, Kind: row.Kind, Payload: append(json.RawMessage(nil), row.Payload...),
		Attempt: row.AttemptCount, MaxAttempts: row.MaxAttempts, ScheduledFor: row.DueAt,
	}
	handlerErr, panicked := invokeHandler(ctx, handler, job)
	if err := ctx.Err(); err != nil {
		// Leave the claim alone. Its lease is the durable recovery path, and
		// trying to mutate with a cancelled context would only hide shutdown.
		return err
	}
	if panicked {
		if row.AttemptCount >= row.MaxAttempts {
			return r.finish(ctx, jobID, claimID, StateFailed, "HANDLER_PANIC")
		}
		return r.release(ctx, jobID, claimID, "RETRY")
	}
	if handlerErr != nil {
		if row.AttemptCount >= row.MaxAttempts {
			return r.finish(ctx, jobID, claimID, StateFailed, "MAX_ATTEMPTS")
		}
		return r.release(ctx, jobID, claimID, "RETRY")
	}
	if interval := r.recurring[row.Kind]; interval > 0 {
		_, err := r.state.Reschedule(ctx, jobID, claimID, r.now().UTC().Add(interval))
		return err
	}
	return r.finish(ctx, jobID, claimID, StateSucceeded, "OK")
}

func invokeHandler(ctx context.Context, handler Handler, job Job) (err error, panicked bool) {
	defer func() {
		if recover() != nil {
			err, panicked = errors.New("job handler panic"), true
		}
	}()
	return handler(ctx, job), false
}

func (r *Runner) release(ctx context.Context, jobID, claimID, code string) error {
	_, err := r.state.Release(ctx, jobID, claimID, code)
	if errors.Is(err, ErrClaimLost) {
		return nil
	}
	return err
}

func (r *Runner) finish(ctx context.Context, jobID, claimID, state, code string) error {
	_, err := r.state.Finish(ctx, jobID, claimID, state, code)
	if errors.Is(err, ErrClaimLost) {
		return nil
	}
	return err
}
