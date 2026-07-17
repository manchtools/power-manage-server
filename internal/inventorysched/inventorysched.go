// Package inventorysched implements the spec-22 server-side inventory
// collection scheduler and the freshness policy it shares with the
// Device RPC read paths.
//
// The interval is server-held policy (device override > group minimum >
// DefaultIntervalMinutes); the worker ticks on a fixed cadence,
// single-flighted across control replicas via an advisory lock, and
// enqueues at most one CA-signed RequestInventory per stale connected
// device per tick over the exact signing + enqueue path the manual
// RefreshDeviceInventory RPC uses. The agent is unchanged: collection
// stays server-initiated and WS4-verified.
package inventorysched

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

const (
	// Tick is the fixed scheduler cadence (spec 22 AC 5). Deliberately
	// not configurable — the stale query is cheap; the only operational
	// knob is CONTROL_INVENTORY_SCHEDULER_ENABLED.
	Tick = 15 * time.Minute

	// DefaultIntervalMinutes is the server default inventory interval
	// (24 h) applied when neither the device nor any of its groups set
	// one. Passed into the SQL resolution queries so the constant has
	// one home.
	DefaultIntervalMinutes = 1440

	// enqueueDeadlineSlack keeps the Asynq deadline below the tick
	// period (AC 5): a request to a disconnected device expires before
	// the next tick can enqueue a fresh one, so requests never
	// accumulate.
	enqueueDeadlineSlack = time.Minute

	// advisoryKeyInventorySchedule single-flights the tick across
	// control replicas ("invsched" in hex, same convention as the
	// retention worker's "prune" key).
	advisoryKeyInventorySchedule int64 = 0x696e767363686564
)

// Grace is the slack added to the resolved interval before a device
// counts as overdue (spec 22 AC 7): max(1 h, 25 % of the interval).
// The scheduler re-collects as soon as inventory is due, so under
// normal operation the grace gap means overdue only trips when
// collection is failing — the stale-by-policy vs stale-because-broken
// distinction.
func Grace(interval time.Duration) time.Duration {
	grace := interval / 4
	if grace < time.Hour {
		grace = time.Hour
	}
	return grace
}

// Overdue reports whether a device's inventory freshness has exceeded
// its resolved interval plus grace (spec 22 AC 7). Computed from the
// server-held cadence, so it is valid even while the device is offline.
// A never-collected device ages from registered_at: a fresh enrollment
// gets one full interval+grace before the flag trips, while an old
// device that never delivered inventory still reads as
// collection-failing. Missing both timestamps fails closed (overdue).
func Overdue(lastInventoryAt, registeredAt *time.Time, intervalMinutes int32, now time.Time) bool {
	base := lastInventoryAt
	if base == nil {
		base = registeredAt
	}
	if base == nil {
		return true
	}
	interval := time.Duration(intervalMinutes) * time.Minute
	return now.Sub(*base) > interval+Grace(interval)
}

// Enqueuer is the slice of taskqueue.Client the worker needs; an
// interface so tests can capture enqueues without a Valkey instance.
type Enqueuer interface {
	EnqueueToDevice(deviceID, taskType string, payload any, opts ...asynq.Option) error
}

// Worker requests inventory from stale devices once per tick.
type Worker struct {
	store  *store.Store
	aq     Enqueuer
	signer ca.ActionSigner
	logger *slog.Logger
	now    func() time.Time
}

// New builds a Worker. signer and aq must be the same instances the
// manual RefreshDeviceInventory path uses so both emit identical
// signed requests.
func New(st *store.Store, aq Enqueuer, signer ca.ActionSigner, logger *slog.Logger) *Worker {
	return &Worker{
		store:  st,
		aq:     aq,
		signer: signer,
		logger: logger,
		now:    time.Now,
	}
}

// SetNowForTest overrides the worker's clock.
func (w *Worker) SetNowForTest(now func() time.Time) { w.now = now }

// RunResult reports one tick's outcome.
type RunResult struct {
	// Ran is false when another replica held the advisory lock.
	Ran bool
	// Enqueued is the number of signed requests handed to Asynq.
	Enqueued int
}

// RunOnce executes a single scheduler tick, single-flighted across
// replicas. Deliberately no per-tick batch cap (spec 22, pinned): the
// first-rollout herd is absorbed by Asynq's queueing and the sub-tick
// deadline expires whatever cannot be delivered.
func (w *Worker) RunOnce(ctx context.Context) (RunResult, error) {
	var res RunResult
	ran, err := w.store.TryWithAdvisoryLock(ctx, advisoryKeyInventorySchedule, func() error {
		var rerr error
		res, rerr = w.runLocked(ctx)
		return rerr
	})
	if err != nil {
		return RunResult{}, err
	}
	res.Ran = ran
	if !ran {
		w.logger.Debug("inventory schedule: tick already running on another replica; skipping")
	}
	return res, nil
}

func (w *Worker) runLocked(ctx context.Context) (RunResult, error) {
	var res RunResult
	now := w.now()

	ids, err := w.store.Queries().ListStaleInventoryDevices(ctx, db.ListStaleInventoryDevicesParams{
		SeenSince:              pgtype.Timestamptz{Time: now.Add(-Tick), Valid: true},
		DefaultIntervalMinutes: DefaultIntervalMinutes,
		Now:                    pgtype.Timestamptz{Time: now, Valid: true},
	})
	if err != nil {
		return res, fmt.Errorf("inventory schedule: list stale devices: %w", err)
	}
	if len(ids) == 0 {
		return res, nil
	}

	deadline := now.Add(Tick - enqueueDeadlineSlack)
	for _, deviceID := range ids {
		payload := taskqueue.InventoryRequestPayload{QueryID: ulid.Make().String(), TargetDeviceID: deviceID}
		if err := taskqueue.SignInventoryRequest(w.signer, &payload); err != nil {
			// Signing failure is systemic (nil signer / broken key):
			// abort the cycle fail-closed instead of log-spamming one
			// error per device; the next tick retries.
			return res, fmt.Errorf("inventory schedule: sign for %s: %w", deviceID, err)
		}
		if err := w.aq.EnqueueToDevice(deviceID, taskqueue.TypeInventoryRequest, payload,
			asynq.MaxRetry(3),
			asynq.Deadline(deadline),
		); err != nil {
			// Enqueue failure means Valkey trouble — abort; devices not
			// reached stay stale and the next tick picks them up again.
			return res, fmt.Errorf("inventory schedule: enqueue for %s: %w", deviceID, err)
		}
		res.Enqueued++
	}
	w.logger.Info("inventory schedule: requested inventory from stale devices",
		"stale", len(ids), "enqueued", res.Enqueued)
	return res, nil
}
