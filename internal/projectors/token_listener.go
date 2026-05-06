package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// TokenListener returns a store.EventListener that applies every
// token-stream event the deleted PL/pgSQL project_token_event
// handled. Six event types, each a single statement:
//
//   - TokenCreated:  INSERT … ON CONFLICT DO NOTHING
//   - TokenRenamed:  UPDATE name
//   - TokenUsed:     UPDATE current_uses += 1
//   - TokenDisabled: UPDATE disabled = TRUE
//   - TokenEnabled:  UPDATE disabled = FALSE
//   - TokenDeleted:  UPDATE is_deleted = TRUE
//
// Every UPDATE has a projection_version < $N guard rejecting stale
// reconciler replays — load-bearing for TokenUsed since a duplicate
// would erroneously bump current_uses twice.
//
// Wired in projectors.WireAll. Refs #103, tracker #107.
func TokenListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if err := ApplyToken(ctx, st.Queries(), e); err != nil {
			logger.Warn("token projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "token_id", e.StreamID, "error", err)
		}
	}
}

// ApplyToken is the transactional core of the token projector. The
// listener wraps it for live-event dispatch; the rebuild path
// (manchtools/power-manage-server#125) registers it via
// RegisterRebuildApply so RebuildAll re-derives the projection from
// the event store instead of dispatching to the no-op PL/pgSQL stub.
func ApplyToken(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "token" {
		return nil
	}
	ver := deref(e.SequenceNum)
	switch e.EventType {
	case "TokenCreated":
		return applyTokenCreated(ctx, q, e)
	case "TokenRenamed":
		return applyTokenRenamed(ctx, q, e)
	case "TokenUsed":
		return q.IncrementTokenUseProjection(ctx, db.IncrementTokenUseProjectionParams{
			ID: e.StreamID, ProjectionVersion: ver,
		})
	case "TokenDisabled":
		return q.SetTokenDisabledProjection(ctx, db.SetTokenDisabledProjectionParams{
			ID: e.StreamID, Disabled: true, ProjectionVersion: ver,
		})
	case "TokenEnabled":
		return q.SetTokenDisabledProjection(ctx, db.SetTokenDisabledProjectionParams{
			ID: e.StreamID, Disabled: false, ProjectionVersion: ver,
		})
	case "TokenDeleted":
		return q.SoftDeleteTokenProjection(ctx, db.SoftDeleteTokenProjectionParams{
			ID: e.StreamID, ProjectionVersion: ver,
		})
	}
	return nil
}

func applyTokenCreated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := TokenCreatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	return q.InsertTokenProjection(ctx, db.InsertTokenProjectionParams{
		ID:                payload.ID,
		ValueHash:         payload.ValueHash,
		Name:              payload.Name,
		OneTime:           payload.OneTime,
		MaxUses:           payload.MaxUses,
		ExpiresAt:         payload.ExpiresAt,
		CreatedAt:         &e.OccurredAt,
		CreatedBy:         payload.CreatedBy,
		OwnerID:           payload.OwnerID,
		ProjectionVersion: deref(e.SequenceNum),
	})
}

func applyTokenRenamed(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := TokenRenamedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	return q.RenameTokenProjection(ctx, db.RenameTokenProjectionParams{
		ID:                payload.ID,
		Name:              payload.Name,
		ProjectionVersion: deref(e.SequenceNum),
	})
}
