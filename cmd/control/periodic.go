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

	"github.com/manchtools/power-manage/server/internal/archive"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/dyngroupeval"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/inventorysched"
	"github.com/manchtools/power-manage/server/internal/retention"
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

// startRetentionWorker launches the spec-19 audit-log retention worker:
// every tick it runs one advisory-lock-single-flighted prune cycle
// (choose checkpoint → seal ciphertext events ≤ N into the archive →
// delete ≤ N with the in-tx EventLogPruned marker). Construction errors
// (nil archive, non-positive window) are returned for a FATAL boot — a
// destructive worker must not be silently skipped. The first cycle runs
// immediately: enabled means active, and the worker no-ops when nothing
// is prune-eligible (its 1h safety floor additionally protects fresh
// events).
//
// The per-tick timeout bounds a wedged DB/archive call so a hung cycle
// cannot pin its goroutine forever; a slow-but-healthy prune simply
// delays the next tick (runPeriodic calls fn synchronously).
func startRetentionWorker(ctx context.Context, st *store.Store, arch archive.ArchiveStore, cfg retention.EnvConfig, logger *slog.Logger) error {
	w, err := retention.NewWorker(st, arch, retention.Config{Window: cfg.Window}, logger)
	if err != nil {
		return err
	}
	go runPeriodic(ctx, cfg.Interval, func() {
		// A panic in one prune cycle must not crash the whole control
		// server — recover, log, and let the next tick retry (WS15
		// posture: background jobs are isolated, not load-bearing).
		defer func() {
			if r := recover(); r != nil {
				logger.Error("retention prune cycle panicked", "panic", r)
			}
		}()
		tickCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		defer cancel()
		res, err := w.Prune(tickCtx)
		if err != nil {
			logger.Error("retention prune cycle failed", "error", err)
			return
		}
		if !res.Ran {
			logger.Debug("retention prune skipped — another replica holds the lock")
		}
		// Pruned outcomes are logged by the worker itself (checkpoint,
		// events_deleted, archive_ref); no-op runs stay quiet by design.
	}, true)
	return nil
}

// inventoryScheduleRunner is the slice of inventorysched.Worker one
// tick needs — an interface so the panic-recovery shape is testable
// without a store.
type inventoryScheduleRunner interface {
	RunOnce(ctx context.Context) (inventorysched.RunResult, error)
}

// startInventoryScheduleWorker launches the spec-22 inventory
// collection scheduler: every fixed tick it runs one advisory-lock
// single-flighted cycle that enqueues a signed RequestInventory to
// every stale connected device. The first cycle runs immediately —
// enabled means active, and the cycle no-ops when nothing is stale.
func startInventoryScheduleWorker(ctx context.Context, st *store.Store, aq inventorysched.Enqueuer, signer ca.ActionSigner, logger *slog.Logger) {
	w := inventorysched.New(st, aq, signer, logger)
	go runPeriodic(ctx, inventorysched.Tick, inventoryScheduleTick(ctx, w, logger), true)
}

// inventoryScheduleTick builds one tick's body: panic-recovered (a
// panic in one cycle must not crash the control server — WS15
// posture) and timeout-bounded so a wedged DB/Valkey call cannot pin
// the goroutine past the next tick.
func inventoryScheduleTick(ctx context.Context, w inventoryScheduleRunner, logger *slog.Logger) func() {
	return func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("inventory schedule tick panicked", "panic", r)
			}
		}()
		tickCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		res, err := w.RunOnce(tickCtx)
		if err != nil {
			logger.Error("inventory schedule tick failed", "error", err)
			return
		}
		if !res.Ran {
			logger.Debug("inventory schedule tick skipped — another replica holds the lock")
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
