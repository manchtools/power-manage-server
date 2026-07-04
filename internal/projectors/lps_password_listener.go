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

// LpsPasswordListener returns a store.EventListener that applies
// LpsPasswordRotated events to lps_passwords_projection. Replaces the
// deleted PL/pgSQL project_lps_password_event function.
//
// Three writes per event (mark previous not-current, insert new,
// trim history to 3) wrapped in store.WithTx so the projection never
// observes the intermediate "no current row" state mid-listener.
// Atomicity-with-the-event-commit is sacrificed (the listener fires
// post-commit), but atomicity-of-the-three-writes is preserved.
//
// Asymmetric stale-replay guard (audit F020/F021): the guarded
// MarkLpsPasswordsNotCurrent UPDATE returns rows-affected. If a
// re-fired old event would otherwise re-mark the latest real-current
// row as not_current, the projection_version filter rejects it
// (n == 0) and the listener short-circuits the cascade insert + trim.
// Without this guard a reconciler-driven re-delivery of an old
// LpsPasswordRotated would corrupt is_current and insert a stale
// duplicate underneath the real password.
//
// LpsPasswordRotated is the only event the lps_password stream emits
// today; the switch is intentionally a single case so a future event
// type slots in next to it without touching the wiring.
//
// Live dispatch wraps ApplyLpsPassword (opening its own WithTx so the
// three writes stay atomic on the autocommit pool); the rebuild path
// (#497) registers ApplyLpsPassword via RegisterRebuildApply — the
// rebuild dispatcher already runs inside one transaction and passes q
// bound to it, so the three writes execute directly on q with no nested
// transaction.
//
// Wired in projectors.WireAll.
//
// Refs #98, tracker #107, audit F020/F021, #497.
func LpsPasswordListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		// Filter before opening a transaction so unrelated events don't pay
		// a BEGIN/COMMIT round-trip (ApplyLpsPassword also filters, but only
		// after WithTx has already opened the tx). Mirrors LuksKeyListener.
		if e.StreamType != "lps_password" || e.EventType != string(eventtypes.LpsPasswordRotated) {
			return
		}
		// Live dispatch keeps the three writes atomic on the autocommit
		// pool via WithTx; the tx-bound queries are handed to
		// ApplyLpsPassword.
		if err := st.WithTx(ctx, func(q *store.Queries) error {
			return ApplyLpsPassword(ctx, q, e)
		}); err != nil {
			logger.Warn("lps_password projector: failed to apply LpsPasswordRotated",
				"event_id", e.ID,
				"event_type", e.EventType,
				"error", err)
		}
	}
}

// ApplyLpsPassword is the transactional core of the lps_password
// projector: it writes through the supplied Queries and RETURNS errors
// instead of logging-and-swallowing. The three writes (mark previous
// not-current, insert new, trim history to 3) run directly on q — the
// caller supplies the transaction (WithTx on the live path, the rebuild
// tx on the rebuild path), so ApplyLpsPassword does NOT open a nested
// transaction of its own.
//
// The asymmetric stale-replay guard (audit F020/F021) is preserved: the
// guarded MarkLpsPasswordsNotCurrent UPDATE returns rows-affected; on
// n == 0 an existence check disambiguates stale replay (skip) from a
// first rotation (proceed).
func ApplyLpsPassword(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "lps_password" {
		return nil
	}
	if e.EventType != string(eventtypes.LpsPasswordRotated) {
		return nil
	}

	payload, err := LpsPasswordRotatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		// A malformed historical payload must not abort the whole
		// lps_passwords rebuild; report it skippable so the live listener
		// logs-and-swallows and RebuildAll skips-and-continues.
		return fmt.Errorf("lps_password projector: malformed LpsPasswordRotated %s: %w: %w",
			e.ID, err, store.ErrSkipEvent)
	}

	projVer := e.SequenceNum

	n, err := q.MarkLpsPasswordsNotCurrent(ctx, db.MarkLpsPasswordsNotCurrentParams{
		DeviceID:          payload.DeviceID,
		Username:          payload.Username,
		ProjectionVersion: projVer,
	})
	if err != nil {
		return err
	}
	// n==0 has TWO causes that the rest of the code path
	// handles oppositely:
	//   1. Stale replay: rows exist for (device, username)
	//      but their projection_version is >= the
	//      replaying event's sequence_num. The rotation
	//      has already been projected — skip the insert.
	//   2. First rotation for this user: no rows exist at
	//      all. The UPDATE matched nothing because there
	//      was nothing to flip. Proceed to insert.
	// Disambiguate via an existence check; only the stale
	// case skips. (Audit F020/F021 / CR-CLI catch.)
	if n == 0 {
		exists, err := q.LpsPasswordExistsForDeviceUsername(ctx, db.LpsPasswordExistsForDeviceUsernameParams{
			DeviceID: payload.DeviceID,
			Username: payload.Username,
		})
		if err != nil {
			return err
		}
		if exists {
			return nil
		}
	}
	if err := q.InsertLpsPassword(ctx, db.InsertLpsPasswordParams{
		// The rotating event's ULID: deterministic under replay
		// (F-15 / spec 20) — a rebuild reproduces the same row id.
		ID:                e.ID,
		DeviceID:          payload.DeviceID,
		ActionID:          payload.ActionID,
		Username:          payload.Username,
		Password:          payload.Password,
		RotatedAt:         payload.RotatedAt,
		RotationReason:    payload.RotationReason,
		ProjectionVersion: projVer,
		// created_at from the event, not now(): a rebuild must
		// reproduce the row byte-identically (spec 21 AC 6).
		CreatedAt: e.OccurredAt,
	}); err != nil {
		return err
	}
	return q.TrimLpsPasswordsToLast3(ctx, db.TrimLpsPasswordsToLast3Params{
		DeviceID: payload.DeviceID,
		Username: payload.Username,
	})
}
