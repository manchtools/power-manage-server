package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
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
		// RoleDeleted needs the SoftDelete + cascade DELETE wrapped
		// in a transaction so the projection never observes "role
		// marked deleted but memberships remain". The other event
		// types are single statements and run on the autocommit
		// connection. ApplyRole handles all three when called with
		// tx-bound queries (the rebuild path), so we share its body
		// for RoleDeleted via WithTx and short-circuit the simple
		// cases through the pool.
		if e.EventType == string(eventtypes.RoleDeleted) {
			err := st.WithTx(ctx, func(q *store.Queries) error {
				return ApplyRole(ctx, q, e)
			})
			if err != nil {
				logger.Warn("role projector: failed to apply RoleDeleted",
					"event_id", e.ID, "role_id", e.StreamID, "error", err)
			}
			return
		}
		if err := ApplyRole(ctx, st.Queries(), e); err != nil {
			logger.Warn("role projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "role_id", e.StreamID, "error", err)
		}
	}
}

// ApplyRole is the transactional core of the role projector. The
// listener wraps it for live-event dispatch (using WithTx for
// RoleDeleted's two-write atomicity); the rebuild path
// (manchtools/power-manage-server#125) registers it via
// RegisterRebuildApply so RebuildAll re-derives the projection from
// the event store instead of dispatching to the no-op PL/pgSQL stub.
//
// The asymmetric-guard discipline for RoleDeleted is preserved:
// when the version-guarded SoftDelete affects zero rows, the cascade
// DELETE is skipped — a stale RoleDeleted re-applied later must not
// silently nuke a freshly-restored role's memberships (CR #123).
func ApplyRole(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "role" {
		return nil
	}
	switch e.EventType {
	case string(eventtypes.RoleCreated):
		return applyRoleCreated(ctx, q, e)
	case string(eventtypes.RoleUpdated):
		return applyRoleUpdated(ctx, q, e)
	case string(eventtypes.RoleDeleted):
		return applyRoleDeleted(ctx, q, e)
	}
	return nil
}

func applyRoleCreated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := RoleCreatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	return q.InsertRoleProjection(ctx, db.InsertRoleProjectionParams{
		ID:                payload.ID,
		Name:              payload.Name,
		Description:       payload.Description,
		Permissions:       payload.Permissions,
		IsSystem:          payload.IsSystem,
		CreatedAt:         e.OccurredAt,
		CreatedBy:         payload.CreatedBy,
		ProjectionVersion: e.SequenceNum,
	})
}

func applyRoleUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := RoleUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	return q.UpdateRoleProjection(ctx, db.UpdateRoleProjectionParams{
		ID:                payload.ID,
		Name:              payload.Name,
		Description:       payload.Description,
		Permissions:       derefSlice(payload.Permissions),
		UpdatedAt:         &updatedAt,
		ProjectionVersion: e.SequenceNum,
	})
}

func applyRoleDeleted(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	n, err := q.SoftDeleteRoleProjection(ctx, db.SoftDeleteRoleProjectionParams{
		ID:                e.StreamID,
		UpdatedAt:         &e.OccurredAt,
		ProjectionVersion: e.SequenceNum,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	return q.DeleteUserRolesByRole(ctx, e.StreamID)
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
