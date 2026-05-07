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
		if err := ApplyUserSelection(ctx, st.Queries(), e); err != nil {
			logger.Warn("user_selection projector: failed to apply UserSelectionChanged",
				"event_id", e.ID,
				"stream_id", e.StreamID,
				"error", err)
		}
	}
}

// ApplyUserSelection is the transactional core of the user_selection
// projector. The listener wraps it for live-event dispatch; the
// rebuild path (manchtools/power-manage-server#125) registers it via
// RegisterRebuildApply so RebuildAll re-derives the projection from
// the event store instead of dispatching to the no-op PL/pgSQL stub.
//
// Returns nil for non-matching stream/event types so the rebuild
// loop treats them as harmless no-ops.
func ApplyUserSelection(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "user_selection" {
		return nil
	}
	if e.EventType != "UserSelectionChanged" {
		return nil
	}
	payload, err := UserSelectionChangedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	return q.UpsertUserSelectionProjection(ctx, db.UpsertUserSelectionProjectionParams{
		ID:                payload.ID,
		DeviceID:          payload.DeviceID,
		SourceType:        payload.SourceType,
		SourceID:          payload.SourceID,
		Selected:          payload.Selected,
		UpdatedAt:         e.OccurredAt,
		CreatedBy:         payload.CreatedBy,
		ProjectionVersion: deref(e.SequenceNum),
	})
}
