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
// LpsPasswordRotated is the only event the lps_password stream emits
// today; the switch is intentionally a single case so a future event
// type slots in next to it without touching the wiring.
//
// Wired in projectors.WireAll.
//
// Refs #98, tracker #107.
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

		if err := st.WithTx(ctx, func(q *store.Queries) error {
			if err := q.MarkLpsPasswordsNotCurrent(ctx, db.MarkLpsPasswordsNotCurrentParams{
				DeviceID: payload.DeviceID,
				Username: payload.Username,
			}); err != nil {
				return err
			}
			if err := q.InsertLpsPassword(ctx, db.InsertLpsPasswordParams{
				DeviceID:       payload.DeviceID,
				ActionID:       payload.ActionID,
				Username:       payload.Username,
				Password:       payload.Password,
				RotatedAt:      payload.RotatedAt,
				RotationReason: payload.RotationReason,
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
