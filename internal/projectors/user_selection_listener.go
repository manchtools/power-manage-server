package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// UserSelectionListener returns a store.EventListener that applies
// UserSelectionChanged events to user_selections_projection.
// Single event type, single UPSERT — no transaction wrap needed.
//
// Replaces the deleted PL/pgSQL project_user_selection_event.
// Wired in projectors.WireAll. Refs #106, tracker #107.
func UserSelectionListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "user_selection" {
			return
		}
		if e.EventType != "UserSelectionChanged" {
			return
		}

		payload, err := UserSelectionChangedFromEvent(e)
		if err != nil {
			if errors.Is(err, ErrIgnoredEvent) {
				return
			}
			logger.Warn("user_selection projector: invalid UserSelectionChanged payload",
				"event_id", e.ID, "error", err)
			return
		}

		if err := st.Queries().UpsertUserSelectionProjection(ctx, db.UpsertUserSelectionProjectionParams{
			ID:                payload.ID,
			DeviceID:          payload.DeviceID,
			SourceType:        payload.SourceType,
			SourceID:          payload.SourceID,
			Selected:          payload.Selected,
			UpdatedAt:         e.OccurredAt,
			CreatedBy:         payload.CreatedBy,
			ProjectionVersion: deref(e.SequenceNum),
		}); err != nil {
			logger.Warn("user_selection projector: failed to upsert UserSelectionChanged",
				"event_id", e.ID,
				"device_id", payload.DeviceID,
				"source_type", payload.SourceType,
				"source_id", payload.SourceID,
				"error", err)
		}
	}
}
