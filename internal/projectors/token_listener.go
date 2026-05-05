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
		if e.StreamType != "token" {
			return
		}
		switch e.EventType {
		case "TokenCreated":
			applyTokenCreated(ctx, st, logger, e)
		case "TokenRenamed":
			applyTokenRenamed(ctx, st, logger, e)
		case "TokenUsed":
			applyTokenSimpleUpdate(ctx, st, logger, e, func(q *store.Queries, ver int64) error {
				return q.IncrementTokenUseProjection(ctx, db.IncrementTokenUseProjectionParams{
					ID: e.StreamID, ProjectionVersion: ver,
				})
			})
		case "TokenDisabled":
			applyTokenSimpleUpdate(ctx, st, logger, e, func(q *store.Queries, ver int64) error {
				return q.SetTokenDisabledProjection(ctx, db.SetTokenDisabledProjectionParams{
					ID: e.StreamID, Disabled: true, ProjectionVersion: ver,
				})
			})
		case "TokenEnabled":
			applyTokenSimpleUpdate(ctx, st, logger, e, func(q *store.Queries, ver int64) error {
				return q.SetTokenDisabledProjection(ctx, db.SetTokenDisabledProjectionParams{
					ID: e.StreamID, Disabled: false, ProjectionVersion: ver,
				})
			})
		case "TokenDeleted":
			applyTokenSimpleUpdate(ctx, st, logger, e, func(q *store.Queries, ver int64) error {
				return q.SoftDeleteTokenProjection(ctx, db.SoftDeleteTokenProjectionParams{
					ID: e.StreamID, ProjectionVersion: ver,
				})
			})
		}
	}
}

func applyTokenCreated(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	payload, err := TokenCreatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return
		}
		logger.Warn("token projector: invalid TokenCreated payload",
			"event_id", e.ID, "error", err)
		return
	}
	if err := st.Queries().InsertTokenProjection(ctx, db.InsertTokenProjectionParams{
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
	}); err != nil {
		logger.Warn("token projector: failed to insert TokenCreated",
			"event_id", e.ID, "token_id", payload.ID, "error", err)
	}
}

func applyTokenRenamed(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	payload, err := TokenRenamedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return
		}
		logger.Warn("token projector: invalid TokenRenamed payload",
			"event_id", e.ID, "error", err)
		return
	}
	if err := st.Queries().RenameTokenProjection(ctx, db.RenameTokenProjectionParams{
		ID:                payload.ID,
		Name:              payload.Name,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		logger.Warn("token projector: failed to apply TokenRenamed",
			"event_id", e.ID, "token_id", payload.ID, "error", err)
	}
}

// applyTokenSimpleUpdate is the shared scaffold for the four
// no-payload event types (Used, Disabled, Enabled, Deleted). They
// all key off StreamID + the event sequence_num and differ only in
// which sqlc query they call — the closure isolates that one
// difference.
func applyTokenSimpleUpdate(
	ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent,
	apply func(q *store.Queries, projectionVersion int64) error,
) {
	if err := apply(st.Queries(), deref(e.SequenceNum)); err != nil {
		logger.Warn("token projector: failed to apply token update",
			"event_id", e.ID, "event_type", e.EventType, "token_id", e.StreamID, "error", err)
	}
}
