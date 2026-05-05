package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// UserRoleListener returns a store.EventListener that applies every
// user_role stream event the deleted PL/pgSQL project_user_role_event
// handled. Two event types, two single-statement writes — no
// transaction wrap needed.
//
//   - UserRoleAssigned: INSERT … ON CONFLICT DO NOTHING (replay-safe)
//   - UserRoleRevoked:  DELETE WHERE (user_id, role_id)
//
// Wired in projectors.WireAll. Refs #102, tracker #107.
func UserRoleListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "user_role" {
			return
		}
		switch e.EventType {
		case "UserRoleAssigned":
			applyUserRoleAssigned(ctx, st, logger, e)
		case "UserRoleRevoked":
			applyUserRoleRevoked(ctx, st, logger, e)
		}
	}
}

func applyUserRoleAssigned(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	payload, err := UserRoleAssignedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return
		}
		logger.Warn("user_role projector: invalid UserRoleAssigned payload",
			"event_id", e.ID, "error", err)
		return
	}
	if err := st.Queries().InsertUserRoleProjection(ctx, db.InsertUserRoleProjectionParams{
		UserID:            payload.UserID,
		RoleID:            payload.RoleID,
		AssignedAt:        e.OccurredAt,
		AssignedBy:        payload.AssignedBy,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		logger.Warn("user_role projector: failed to insert UserRoleAssigned",
			"event_id", e.ID,
			"user_id", payload.UserID,
			"role_id", payload.RoleID,
			"error", err)
	}
}

func applyUserRoleRevoked(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	payload, err := UserRoleRevokedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return
		}
		logger.Warn("user_role projector: invalid UserRoleRevoked payload",
			"event_id", e.ID, "error", err)
		return
	}
	if err := st.Queries().DeleteUserRoleProjection(ctx, db.DeleteUserRoleProjectionParams{
		UserID: payload.UserID,
		RoleID: payload.RoleID,
	}); err != nil {
		logger.Warn("user_role projector: failed to delete user_roles_projection row",
			"event_id", e.ID,
			"user_id", payload.UserID,
			"role_id", payload.RoleID,
			"error", err)
	}
}
