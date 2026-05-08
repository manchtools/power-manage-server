package projectors

import (
	"context"
	"errors"
	"log/slog"

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
// Wired in projectors.WireAll.
//
// Refs #98, tracker #107, audit F020/F021.
func LpsPasswordListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "lps_password" {
			return
		}
		if e.EventType != "LpsPasswordRotated" {
			return
		}

		payload, err := LpsPasswordRotatedFromEvent(e)
		if err != nil {
			if errors.Is(err, ErrIgnoredEvent) {
				return
			}
			logger.Warn("lps_password projector: invalid event payload",
				"event_id", e.ID, "event_type", e.EventType, "error", err)
			return
		}

		projVer := deref(e.SequenceNum)

		if err := st.WithTx(ctx, func(q *store.Queries) error {
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
				DeviceID:          payload.DeviceID,
				ActionID:          payload.ActionID,
				Username:          payload.Username,
				Password:          payload.Password,
				RotatedAt:         payload.RotatedAt,
				RotationReason:    payload.RotationReason,
				ProjectionVersion: projVer,
			}); err != nil {
				return err
			}
			return q.TrimLpsPasswordsToLast3(ctx, db.TrimLpsPasswordsToLast3Params{
				DeviceID: payload.DeviceID,
				Username: payload.Username,
			})
		}); err != nil {
			logger.Warn("lps_password projector: failed to apply LpsPasswordRotated",
				"event_id", e.ID,
				"device_id", payload.DeviceID,
				"username", payload.Username,
				"error", err)
		}
	}
}
