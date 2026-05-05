package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// RoleListener returns a store.EventListener that applies every role
// stream event the deleted PL/pgSQL project_role_event handled.
// Replaces the three-case dispatcher with one switch in Go:
//
//   - RoleCreated:  INSERT … ON CONFLICT DO NOTHING (replay-safe)
//   - RoleUpdated:  partial UPDATE (COALESCE preserves omitted fields;
//     projection_version guard rejects stale reconciler replays)
//   - RoleDeleted:  is_deleted=TRUE + cascade DELETE on
//     user_roles_projection, wrapped in store.WithTx so the
//     projection never observes "role marked deleted but
//     memberships remain"
//
// Wired in projectors.WireAll. Refs #101, tracker #107.
func RoleListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "role" {
			return
		}
		switch e.EventType {
		case "RoleCreated":
			applyRoleCreated(ctx, st, logger, e)
		case "RoleUpdated":
			applyRoleUpdated(ctx, st, logger, e)
		case "RoleDeleted":
			applyRoleDeleted(ctx, st, logger, e)
		}
	}
}

func applyRoleCreated(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	payload, err := RoleCreatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return
		}
		logger.Warn("role projector: invalid RoleCreated payload",
			"event_id", e.ID, "error", err)
		return
	}
	if err := st.Queries().InsertRoleProjection(ctx, db.InsertRoleProjectionParams{
		ID:                payload.ID,
		Name:              payload.Name,
		Description:       payload.Description,
		Permissions:       payload.Permissions,
		IsSystem:          payload.IsSystem,
		CreatedAt:         e.OccurredAt,
		CreatedBy:         payload.CreatedBy,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		logger.Warn("role projector: failed to insert RoleCreated",
			"event_id", e.ID, "role_id", payload.ID, "error", err)
	}
}

func applyRoleUpdated(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	payload, err := RoleUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return
		}
		logger.Warn("role projector: invalid RoleUpdated payload",
			"event_id", e.ID, "error", err)
		return
	}
	updatedAt := e.OccurredAt
	if err := st.Queries().UpdateRoleProjection(ctx, db.UpdateRoleProjectionParams{
		ID:                payload.ID,
		Name:              payload.Name,
		Description:       payload.Description,
		Permissions:       derefSlice(payload.Permissions),
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		logger.Warn("role projector: failed to apply RoleUpdated",
			"event_id", e.ID, "role_id", payload.ID, "error", err)
	}
}

func applyRoleDeleted(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	roleID := e.StreamID
	if err := st.WithTx(ctx, func(q *store.Queries) error {
		// SoftDeleteRoleProjection returns rows-affected. If the
		// projection_version guard rejected the UPDATE (stale
		// reconciler replay, or row already at a newer version), we
		// must NOT cascade the membership delete — otherwise an old
		// RoleDeleted re-applied later would silently nuke a
		// freshly-restored role's memberships. CR caught this on PR
		// #123.
		n, err := q.SoftDeleteRoleProjection(ctx, db.SoftDeleteRoleProjectionParams{
			ID:                roleID,
			UpdatedAt:         &e.OccurredAt,
			ProjectionVersion: deref(e.SequenceNum),
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		return q.DeleteUserRolesByRole(ctx, roleID)
	}); err != nil {
		logger.Warn("role projector: failed to apply RoleDeleted",
			"event_id", e.ID, "role_id", roleID, "error", err)
	}
}

// derefSlice returns the value behind a pointer slice, or nil when
// the pointer is nil. Distinguishes "nil pointer = no update" from
// "non-nil pointer to empty slice = explicit empty array update".
// sqlc's nullable []TEXT[] params accept []string nil for "preserve
// existing" via COALESCE.
func derefSlice[T any](p *[]T) []T {
	if p == nil {
		return nil
	}
	return *p
}
