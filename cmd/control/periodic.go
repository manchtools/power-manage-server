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

// advisoryKeyStaleExpiry single-flights the stale-execution-expiry tick across
// control replicas (spec 31 AC15), so exactly one replica emits ExecutionTimedOut
// for a given stale execution per tick — matching the retention, inventory, and
// dynamic-group workers. "stale" in ASCII/hex; distinct from advisoryKeyPrune,
// advisoryKeyInventorySchedule, advisoryKeyAdminMutation, and the cert/dyngroup
// namespaces so two unrelated workers never contend on the same key.
const advisoryKeyStaleExpiry int64 = 0x7374616c65 // "stale"

// startStaleExecutionExpiry launches a 1-minute ticker that lists
// executions stuck in pending/dispatched past their deadline and emits
// ExecutionTimedOut events for each. The 1-minute cadence is fixed —
// there's no operator knob today and the prior inline goroutine in
// main.go didn't expose one either. Each tick runs under a cross-replica
// advisory lock (AC15) so N replicas do not each emit a duplicate timeout.
func startStaleExecutionExpiry(ctx context.Context, st *store.Store, logger *slog.Logger, now func() time.Time) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ran, err := expireStaleExecutions(ctx, st, logger, now)
				if err != nil {
					logger.Error("failed to expire stale executions", "error", err)
				} else if !ran {
					logger.Debug("stale-execution expiry skipped — another replica holds the lock")
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// advisoryKeyProjectionDrift serializes the projection-drift scan across control
// replicas: TryWithAdvisoryLock ensures no two replicas run the (read-only) scan
// concurrently — bounding peak DB load and matching the retention, inventory,
// dynamic-group, and stale-expiry workers' lock discipline. It does NOT make the
// scan cluster-wide once-per-window: each replica owns its ticker, so with offset
// ticks each may still run its own scan within a window. Unlike stale-expiry
// (whose emitted state transition makes a later replica's re-run a no-op), this
// scan is read-only, so like the per-replica rate limiters (audit M2/M3/L12) it
// is deliberately per-replica — under ADR-0031 HA its cheap indexed reads and,
// under real drift, its identical ERROR logs scale with replica count. Accepted
// for a read-only alert: the signal is correct however many replicas emit it, and
// a shared-store next-run lease (the exactly-once upgrade) is deliberately NOT
// taken here, consistent with the M2/M3/L12 per-replica decision.
// "drft" in ASCII/hex; distinct from every other advisory key so two unrelated
// workers never contend on the same lock.
const advisoryKeyProjectionDrift int64 = 0x64726674 // "drft"

// projectionDriftCheckInterval is the fixed cadence of the drift-reconcile
// tick. No operator knob today (like the stale-expiry cadence): 15 min is
// frequent enough to surface a silently-dropped projection write well before
// the far slower retention prune could delete the source events, without adding
// meaningful load (the scan is a handful of indexed aggregate queries).
const projectionDriftCheckInterval = 15 * time.Minute

// driftRecheckGrace is how long a suspected-drift target must stay behind
// before the tick alerts. A committed event is visible in the events table the
// instant its transaction commits, but its post-commit projector apply runs
// just after and takes a few milliseconds; a single scan reading the events and
// projection tables independently can catch that in-flight window and read a
// healthy projection as "behind" (false positive). Genuine drift — a projector
// that stopped applying — is permanent, so a second scan after this grace still
// sees it while transient apply-lag has cleared. Kept well above worst-case
// apply latency yet trivial against the 15-min cadence.
const driftRecheckGrace = 5 * time.Second

// startProjectionDriftCheck launches the M1 drift-reconcile tick: every
// projectionDriftCheckInterval it runs one advisory-lock single-flighted
// ComputeProjectionDrift scan and logs an ERROR for every projection that has
// fallen behind the event log. This is the scheduled counterpart to the
// operator-manual `control doctor` drift check — a post-commit projector apply
// that fails after the event commits (DB blip, ctx cancel mid-dispatch) drifts
// silently and permanently, and without this tick stays invisible until someone
// runs doctor.
//
// Detection only: remediation stays operator-driven (`control doctor` + the
// cascade-safe rebuild tool). The drift heuristic has an accepted sampled-type
// blind spot (see store.ComputeProjectionDrift), so an unattended TRUNCATE+replay
// on a false-positive verdict is a worse failure mode than the drift it would
// "fix"; the ERROR log is the actionable signal an operator acts on.
//
// The first scan runs immediately on boot to catch drift left by a crash during
// the previous run.
func startProjectionDriftCheck(ctx context.Context, st *store.Store, logger *slog.Logger) {
	go runPeriodic(ctx, projectionDriftCheckInterval, func() {
		// A panic in one scan must not crash the control server — recover,
		// log, and let the next tick retry (WS15 posture: background jobs are
		// isolated, not load-bearing).
		defer func() {
			if r := recover(); r != nil {
				logger.Error("projection-drift check panicked", "panic", r)
			}
		}()
		tickCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		ran, drifted, err := runProjectionDriftCheck(tickCtx, st, logger, driftRecheckGrace)
		if err != nil {
			logger.Error("projection-drift check failed", "error", err)
			return
		}
		if !ran {
			logger.Debug("projection-drift check skipped — another replica holds the lock")
			return
		}
		if len(drifted) == 0 {
			logger.Debug("projection-drift check clean — every projection is current")
		}
	}, true)
}

// runProjectionDriftCheck runs one drift scan under the cross-replica advisory
// lock, alerting only on drift that PERSISTS across a grace-separated recheck
// (see driftRecheckGrace / rescreenDrift), so a projection caught mid-apply is
// not mistaken for a stopped one. Returns ran=false (no error) when another
// replica holds the lock — the caller treats that as a clean skip. When it ran,
// drifted lists every persistently-Behind target (empty when clean); each is
// also logged at ERROR here so the alert fires even for callers that ignore the
// slice. Only a ComputeProjectionDrift failure returns an error.
func runProjectionDriftCheck(ctx context.Context, st *store.Store, logger *slog.Logger, grace time.Duration) (ran bool, drifted []store.TargetDrift, err error) {
	ran, err = st.TryWithAdvisoryLock(ctx, advisoryKeyProjectionDrift, func() error {
		confirmed, screenErr := rescreenDrift(ctx, st.ComputeProjectionDrift, grace)
		if screenErr != nil {
			return screenErr
		}
		drifted = confirmed
		for _, d := range confirmed {
			// Remediation is deliberately investigate-first, not "rebuild": a
			// rebuild TRUNCATEs then replays, refuses once history has been
			// pruned (store.ErrHistoryPruned), and cascade-widens to FK-child
			// targets — a heavy, operator-judgment recovery, never a reflexive
			// fix for an alert. A stopped projector is usually a control-process
			// fault to diagnose first.
			logger.Error("projection drift detected — a projection has stopped applying events it should",
				"target", d.Target,
				"lagging_table", d.LaggingTable,
				"lagging_max", d.LaggingMax,
				"stream_max", d.StreamMax,
				"remediation", "diagnose this target's projector apply failure in the control logs; recovery is a targeted rebuild from un-pruned history via `control doctor` — a heavy operation, not a routine fix, and impossible once retention has pruned the source events")
		}
		return nil
	})
	return ran, drifted, err
}

// rescreenDrift returns only the targets that are Behind in TWO scans separated
// by grace. compute is the drift probe (store.ComputeProjectionDrift in
// production; a deterministic fake in tests). The first scan is the cheap common
// path: with nothing behind it returns immediately, no wait and no re-scan. When
// something is behind it waits grace — long enough for any in-flight post-commit
// apply to finish — and re-scans; a target still Behind in both is a genuinely
// stopped projector, while transient apply-lag has cleared by the second read.
// Intersection is by target name. ctx cancellation during the grace aborts with
// the ctx error.
//
// Only the two-scan intersection gates the alert, deliberately NOT a "high-water
// did not advance" refinement: a target's high-water can advance on a co-owned
// sibling table (e.g. users owns users_projection + user_roles_projection) while
// the stalled table stays frozen, so gating on forward progress would MISS a
// partial stall. A false negative on an integrity alert is worse than the
// negligible residual false positive of a projector so overloaded it is mid-apply
// in both scans — itself a real signal worth surfacing.
func rescreenDrift(ctx context.Context, compute func(context.Context) ([]store.TargetDrift, error), grace time.Duration) ([]store.TargetDrift, error) {
	first, err := compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("compute projection drift: %w", err)
	}
	firstBehind := map[string]bool{}
	for _, d := range first {
		if d.Drifted() {
			firstBehind[d.Target] = true
		}
	}
	if len(firstBehind) == 0 {
		return nil, nil // clean on the first scan — no recheck needed
	}

	select {
	case <-time.After(grace):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	second, err := compute(ctx)
	if err != nil {
		return nil, fmt.Errorf("recompute projection drift: %w", err)
	}
	var confirmed []store.TargetDrift
	for _, d := range second {
		if d.Drifted() && firstBehind[d.Target] {
			confirmed = append(confirmed, d)
		}
	}
	return confirmed, nil
}

// expireStaleExecutions runs one stale-execution sweep under the cross-replica
// advisory lock. Returns ran=false (no error) when another replica currently
// holds the lock — the caller treats that as a clean skip. A per-execution
// AppendEvent failure is logged and does NOT abort the remaining sweep (matching
// the pre-lock behavior); only a ListStale failure aborts the tick.
func expireStaleExecutions(ctx context.Context, st *store.Store, logger *slog.Logger, now func() time.Time) (ran bool, err error) {
	return st.TryWithAdvisoryLock(ctx, advisoryKeyStaleExpiry, func() error {
		stale, listErr := st.Repos().Execution.ListStale(ctx)
		if listErr != nil {
			return fmt.Errorf("list stale executions: %w", listErr)
		}
		for _, exec := range stale {
			errMsg := fmt.Sprintf("execution timed out: device did not respond (status was %s)", exec.Status)
			completedAt := now().UTC().Format(time.RFC3339Nano)
			if appendErr := st.AppendEvent(ctx, store.Event{
				StreamType: "execution",
				StreamID:   exec.ID,
				EventType:  string(eventtypes.ExecutionTimedOut),
				Data: payloads.ExecutionTimedOut{
					Error:       &errMsg,
					CompletedAt: &completedAt,
				},
				ActorType: "system",
				ActorID:   "expiry",
			}); appendErr != nil {
				logger.Error("failed to expire stale execution", "error", appendErr, "execution_id", exec.ID)
			} else {
				logger.Info("expired stale execution", "execution_id", exec.ID, "status", exec.Status, "device_id", exec.DeviceID)
			}
		}
		return nil
	})
}
