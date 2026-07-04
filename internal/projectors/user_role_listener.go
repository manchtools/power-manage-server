package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
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
// Live dispatch wraps ApplyUserRole and logs-and-swallows; the rebuild path
// (#497) registers ApplyUserRole via RegisterRebuildApply so RebuildAll
// re-derives every post-creation grant from the event store. Before #497 the
// user_role stream was replayed by NO target — a full rebuild silently lost
// every grant made after account creation.
//
// Wired in projectors.WireAll. Refs #102, tracker #107, #497.
func UserRoleListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if err := ApplyUserRole(ctx, st.Queries(), e); err != nil {
			logger.Warn("user_role projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "error", err)
		}
	}
}

// ApplyUserWithRoles is the rebuild applier for the merged "users"
// target (spec 21 AC 6 finding): user_roles_projection has TWO writers
// — ApplyUser inserts the creation-time role_ids carried by
// UserCreatedWithRoles (user stream) and ApplyUserRole applies
// post-creation grants (user_role stream). As separate rebuild targets,
// whichever TRUNCATEd second silently wiped the other applier's
// replayed rows. The merged target replays BOTH streams in true
// sequence order through this dispatcher.
func ApplyUserWithRoles(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	switch e.StreamType {
	case "user":
		return ApplyUser(ctx, q, e)
	case "user_role":
		return ApplyUserRole(ctx, q, e)
	}
	return nil
}

// ApplyUserRole is the transactional core of the user_role projector: it
// writes through the supplied Queries (the rebuild tx or the live autocommit
// handle) and RETURNS errors instead of logging-and-swallowing, so a rebuild
// fails loudly rather than producing a partial RBAC projection.
func ApplyUserRole(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "user_role" {
		return nil
	}
	switch e.EventType {
	case string(eventtypes.UserRoleAssigned):
		payload, err := UserRoleAssignedFromEvent(e)
		if err != nil {
			if errors.Is(err, ErrIgnoredEvent) {
				return nil
			}
			return err
		}
		return q.InsertUserRoleProjection(ctx, db.InsertUserRoleProjectionParams{
			UserID:            payload.UserID,
			RoleID:            payload.RoleID,
			ScopeKind:         payload.ScopeKind,
			ScopeID:           payload.ScopeID,
			AssignedAt:        e.OccurredAt,
			AssignedBy:        payload.AssignedBy,
			ProjectionVersion: e.SequenceNum,
		})
	case string(eventtypes.UserRoleRevoked):
		payload, err := UserRoleRevokedFromEvent(e)
		if err != nil {
			if errors.Is(err, ErrIgnoredEvent) {
				return nil
			}
			return err
		}
		return q.DeleteUserRoleProjection(ctx, db.DeleteUserRoleProjectionParams{
			UserID:            payload.UserID,
			RoleID:            payload.RoleID,
			ScopeKind:         payload.ScopeKind,
			ScopeID:           payload.ScopeID,
			ProjectionVersion: e.SequenceNum,
		})
	}
	return nil
}
