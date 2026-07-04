package projectors

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// LuksKeyListener returns a store.EventListener that applies every
// LUKS-key event:
//
//   - LuksKeyRotated: 3 writes (mark previous not-current, insert
//     new, trim to last 3) wrapped in store.WithTx so the projection
//     never observes the intermediate "no current row" state.
//   - LuksDeviceKeyRevocationDispatched: UPDATE current row's
//     revocation_status='dispatched' + revocation_at, clear error.
//   - LuksDeviceKeyRevoked: UPDATE current row's revocation_status='success'
//     (note column-value vs event-name mismatch retained for backward compat).
//   - LuksDeviceKeyRevocationFailed: UPDATE revocation_status='failed'
//     and capture revocation_error.
//
// LuksDeviceKeyRevocationRequested is intentionally a no-op. The
// Requested event is a marker the dispatcher handler appends before
// enqueueing; the projection only changes once Dispatched / Revoked /
// Failed lands.
//
// Asymmetric stale-replay guard (audit N007, mirrors LPS audit
// F020/F021): the guarded MarkLuksKeysNotCurrent UPDATE returns
// rows-affected. If a re-fired old event would otherwise re-mark the
// latest real-current row as not_current, the projection_version filter
// rejects it (n == 0) and the listener short-circuits the cascade
// insert + trim. Without this guard a reconciler-driven re-delivery of
// an old LuksKeyRotated would corrupt is_current and insert a stale
// duplicate underneath the real key.
//
// Live dispatch wraps ApplyLuksKey (opening its own WithTx for the
// LuksKeyRotated multi-write case so the three writes stay atomic on the
// autocommit pool); the rebuild path (#497) registers ApplyLuksKey via
// RegisterRebuildApply — the rebuild dispatcher already runs inside one
// transaction and passes q bound to it, so every write executes directly
// on q with no nested transaction.
//
// Wired in projectors.WireAll. Refs #99, tracker #107, audit N007, #497.
func LuksKeyListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "luks_key" {
			return
		}
		// LuksKeyRotated is a three-write cascade — route it through
		// WithTx on the live path so the writes stay atomic on the
		// autocommit pool. The single-write revocation events go on the
		// pool directly. Both share ApplyLuksKey's body via the
		// tx-bound / pool-bound Queries.
		if e.EventType == string(eventtypes.LuksKeyRotated) {
			if err := st.WithTx(ctx, func(q *store.Queries) error {
				return ApplyLuksKey(ctx, q, e)
			}); err != nil {
				logger.Warn("luks_key projector: failed to apply event",
					"event_id", e.ID, "event_type", e.EventType, "error", err)
			}
			return
		}
		if err := ApplyLuksKey(ctx, st.Queries(), e); err != nil {
			logger.Warn("luks_key projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "error", err)
		}
	}
}

// ApplyLuksKey is the transactional core of the luks_key projector: it
// writes through the supplied Queries and RETURNS errors instead of
// logging-and-swallowing. Every write runs directly on q — the caller
// supplies the transaction (WithTx for LuksKeyRotated on the live path,
// the rebuild tx on the rebuild path), so ApplyLuksKey does NOT open a
// nested transaction of its own.
//
// LuksDeviceKeyRevocationRequested and every other event_type are
// silently ignored — same behaviour as the deleted PL/pgSQL projector's
// CASE ... ELSE NULL.
func ApplyLuksKey(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "luks_key" {
		return nil
	}
	switch e.EventType {
	case string(eventtypes.LuksKeyRotated):
		return applyLuksKeyRotated(ctx, q, e)
	case string(eventtypes.LuksDeviceKeyRevocationDispatched):
		return applyLuksRevocation(ctx, q, e, LuksRevocationDispatchedFromEvent)
	case string(eventtypes.LuksDeviceKeyRevoked):
		return applyLuksRevocation(ctx, q, e, LuksRevokedFromEvent)
	case string(eventtypes.LuksDeviceKeyRevocationFailed):
		return applyLuksRevocation(ctx, q, e, LuksRevocationFailedFromEvent)
	}
	return nil
}

func applyLuksKeyRotated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := LuksKeyRotatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		// A malformed historical payload must not abort the whole luks_keys
		// rebuild; report it skippable so the live listener logs-and-swallows
		// and RebuildAll skips-and-continues.
		return fmt.Errorf("luks_key projector: malformed LuksKeyRotated %s: %w: %w",
			e.ID, err, store.ErrSkipEvent)
	}
	projVer := e.SequenceNum

	n, err := q.MarkLuksKeysNotCurrent(ctx, db.MarkLuksKeysNotCurrentParams{
		DeviceID:          payload.DeviceID,
		ActionID:          payload.ActionID,
		DevicePath:        payload.DevicePath,
		ProjectionVersion: projVer,
	})
	if err != nil {
		return err
	}
	// n==0 has TWO causes that the rest of the code path
	// handles oppositely (audit N007, mirrors LPS F020/F021):
	//   1. Stale replay: rows exist for (device, action, path)
	//      but their projection_version is >= the replaying
	//      event's sequence_num. The rotation has already been
	//      projected — skip the insert.
	//   2. First rotation for this triple: no rows exist at
	//      all. The UPDATE matched nothing because there was
	//      nothing to flip. Proceed to insert.
	// Disambiguate via an existence check; only the stale case
	// skips.
	if n == 0 {
		exists, err := q.LuksKeyExistsForDeviceActionPath(ctx, db.LuksKeyExistsForDeviceActionPathParams{
			DeviceID:   payload.DeviceID,
			ActionID:   payload.ActionID,
			DevicePath: payload.DevicePath,
		})
		if err != nil {
			return err
		}
		if exists {
			return nil
		}
	}
	if err := q.InsertLuksKey(ctx, db.InsertLuksKeyParams{
		// The rotating event's ULID: deterministic under replay
		// (F-15 / spec 20) — a rebuild reproduces the same row id.
		ID:                e.ID,
		DeviceID:          payload.DeviceID,
		ActionID:          payload.ActionID,
		DevicePath:        payload.DevicePath,
		Passphrase:        payload.Passphrase,
		RotatedAt:         payload.RotatedAt,
		RotationReason:    payload.RotationReason,
		ProjectionVersion: projVer,
	}); err != nil {
		return err
	}
	return q.TrimLuksKeysToLast3(ctx, db.TrimLuksKeysToLast3Params{
		DeviceID:   payload.DeviceID,
		ActionID:   payload.ActionID,
		DevicePath: payload.DevicePath,
	})
}

// applyLuksRevocation is generic across the three revocation event
// types — they all UPDATE the current row's (revocation_status,
// revocation_error, revocation_at). The decoder picks the right
// timestamp key + status value; the writer is identical.
func applyLuksRevocation(
	ctx context.Context,
	q *store.Queries,
	e store.PersistedEvent,
	decode func(store.PersistedEvent) (LuksRevocationPayload, error),
) error {
	payload, err := decode(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	at := payload.At
	return q.UpdateLuksKeyRevocationStatus(ctx, db.UpdateLuksKeyRevocationStatusParams{
		DeviceID:         payload.DeviceID,
		ActionID:         payload.ActionID,
		RevocationStatus: stringPtr(payload.Status),
		RevocationError:  payload.Error,
		RevocationAt:     &at,
	})
}

func stringPtr(s string) *string { return &s }
