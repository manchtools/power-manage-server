// Periodic-worker boot helpers extracted from main.go (audit F043 / #157).
// These are pure goroutine launchers — they own the ticker loop, the
// ctx-cancellation shutdown, and the structured-log surface, but they
// take all collaborators as arguments so each can be unit-tested in
// isolation against a fake store/Queries.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/manchtools/power-manage/server/internal/dyngroupeval"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
)

// runPeriodic calls fn on every tick until ctx is cancelled.
// If runImmediately is true, fn is called once before the first tick.
func runPeriodic(ctx context.Context, interval time.Duration, fn func(), runImmediately bool) {
	if runImmediately {
		fn()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			fn()
		case <-ctx.Done():
			return
		}
	}
}

// dynamicQueueBatch is what one drain iteration reports: how many rows
// the SQL function evaluated and whether the queue still has more rows
// after the batch (closes audit F035 / #168 — the prior shape inferred
// queue-empty from `count < batchSize`, which fired one wasted iteration
// on a batch that processed exactly the limit).
type dynamicQueueBatch struct {
	count int32
	more  bool
}

// drainDynamicQueue runs the same drain loop shape against either
// dynamic-group queue. evalFn evaluates one batch and reports
// (count, more); the loop terminates when more is false or evalFn
// returns an error (logged, treated as terminal so we don't busy-loop
// on a wedged DB).
func drainDynamicQueue(ctx context.Context, label string, logger *slog.Logger, evalFn func(context.Context) (dynamicQueueBatch, error)) {
	for {
		res, err := evalFn(ctx)
		if err != nil {
			logger.Error("failed to evaluate queued "+label, "error", err)
			return
		}
		if res.count > 0 {
			logger.Info("evaluated queued "+label, "count", res.count)
		}
		if !res.more {
			return // queue is drained — explicit signal from the SQL function
		}
	}
}

// startDynamicGroupWorker launches the worker that drains both dynamic-
// group queues on the configured interval and queues a full re-evaluation
// every 24h as a safety net. Returns immediately after spawning its
// goroutines; ctx cancellation stops them.
//
// When interval is 0 the worker is disabled entirely (a one-line Info
// is logged in main.go's else branch — kept there because main owns
// the boot-time "feature is disabled" reporting).
func startDynamicGroupWorker(ctx context.Context, st *store.Store, interval time.Duration, logger *slog.Logger) {
	ev := dyngroupeval.New(st, logger)
	evalGroups := func() {
		drainDynamicQueue(ctx, "dynamic groups", logger, func(ctx context.Context) (dynamicQueueBatch, error) {
			r, err := ev.DrainDeviceGroupQueue(ctx)
			return dynamicQueueBatch{count: r.Count, more: r.More}, err
		})
	}
	evalUserGroups := func() {
		drainDynamicQueue(ctx, "dynamic user groups", logger, func(ctx context.Context) (dynamicQueueBatch, error) {
			r, err := ev.DrainUserGroupQueue(ctx)
			return dynamicQueueBatch{count: r.Count, more: r.More}, err
		})
	}

	go func() {
		// Run immediately on startup to process any groups queued during downtime
		evalGroups()
		evalUserGroups()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				evalGroups()
				evalUserGroups()
			case <-ctx.Done():
				return
			}
		}
	}()

	// Periodic full re-evaluation as a safety net (every 24h).
	// Queues all dynamic groups for evaluation; the worker above drains them.
	// Wave F replacement for the PL/pgSQL queue_all_dynamic_groups
	// function — two typed enqueues here instead of one SELECT
	// fn() that did both inserts internally.
	go runPeriodic(ctx, 24*time.Hour, func() {
		const reason = "periodic_full_evaluation"
		if err := st.Queries().EnqueueAllDynamicDeviceGroups(ctx, reason); err != nil {
			logger.Error("failed to queue full dynamic device-group re-evaluation", "error", err)
		}
		if err := st.Queries().EnqueueAllDynamicUserGroups(ctx, reason); err != nil {
			logger.Error("failed to queue full dynamic user-group re-evaluation", "error", err)
		} else {
			logger.Info("queued full dynamic group re-evaluation")
		}
	}, false)
}

// startStaleExecutionExpiry launches a 1-minute ticker that lists
// executions stuck in pending/dispatched past their deadline and emits
// ExecutionTimedOut events for each. The 1-minute cadence is fixed —
// there's no operator knob today and the prior inline goroutine in
// main.go didn't expose one either; this is a straight extraction.
func startStaleExecutionExpiry(ctx context.Context, st *store.Store, logger *slog.Logger, now func() time.Time) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				stale, err := st.Repos().Execution.ListStale(ctx)
				if err != nil {
					logger.Error("failed to list stale executions", "error", err)
					continue
				}
				for _, exec := range stale {
					errMsg := fmt.Sprintf("execution timed out: device did not respond (status was %s)", exec.Status)
					completedAt := now().UTC().Format(time.RFC3339Nano)
					if err := st.AppendEvent(ctx, store.Event{
						StreamType: "execution",
						StreamID:   exec.ID,
						EventType:  string(eventtypes.ExecutionTimedOut),
						Data: payloads.ExecutionTimedOut{
							Error:       &errMsg,
							CompletedAt: &completedAt,
						},
						ActorType: "system",
						ActorID:   "expiry",
					}); err != nil {
						logger.Error("failed to expire stale execution", "error", err, "execution_id", exec.ID)
					} else {
						logger.Info("expired stale execution", "execution_id", exec.ID, "status", exec.Status, "device_id", exec.DeviceID)
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}
