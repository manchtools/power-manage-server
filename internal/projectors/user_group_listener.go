package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// reasonGroupCreated and reasonQueryUpdated mirror the PL/pgSQL
// projector's `INSERT INTO dynamic_user_group_evaluation_queue
// (group_id, reason) VALUES (..., 'group_created' / 'query_updated')`
// constants. Held as pointers so they can be passed straight to the
// EnqueueDynamicUserGroupEvaluation params (the column is nullable).
var (
	reasonGroupCreatedString  = "group_created"
	reasonQueryUpdatedString  = "query_updated"
	reasonGroupCreatedPointer = &reasonGroupCreatedString
	reasonQueryUpdatedPointer = &reasonQueryUpdatedString
)

// UserGroupListener returns a store.EventListener that applies every
// user_group stream event the deleted PL/pgSQL project_user_group_event
// handled. Ten event types: Created, Updated, QueryUpdated,
// MaintenanceWindowSet, Deleted, MemberAdded, MemberRemoved,
// RoleAssigned, RoleRevoked, MembersRebuilt.
//
// Event-type families:
//   - Group CRUD: Created (INSERT + optional dynamic-queue enqueue),
//     Updated / MaintenanceWindowSet (single guarded UPDATE), QueryUpdated
//     (UPDATE + optional flip-to-dynamic cascade), Deleted (soft-delete +
//     SCIM mapping cleanup + member wipe + role-assignment wipe + queue
//     cleanup, wrapped in store.WithTx).
//   - Membership edits: MemberAdded (INSERT + increment, gated by
//     parent-is-dynamic short-circuit), MemberRemoved (DELETE + decrement,
//     same gate), MembersRebuilt (TRUNCATE-style member wipe + bulk
//     re-insert + member_count set), each wrapped in store.WithTx so the
//     parent row never observes "member changed but member_count stale".
//   - Role assignments: RoleAssigned (INSERT) and RoleRevoked (DELETE),
//     both single-statement composite-PK writes (no parent-row update).
//
// Multi-write listeners (Deleted, MemberAdded, MemberRemoved,
// MembersRebuilt, QueryUpdated when flip-to-dynamic) follow the
// asymmetric-guard discipline: the guarded UPDATE is :execrows, and
// the listener short-circuits the downstream cascade when n == 0
// (stale projection_version replay).
//
// Dynamic-query engine scope: per #136 the dynamic-query evaluator
// (evaluate_dynamic_user_group, validate_user_group_query) STAYS in
// PL/pgSQL until a later phase. The Go listener only persists the
// query string column + (re-)enqueues the group via
// EnqueueDynamicUserGroupEvaluation when is_dynamic flips on; the
// evaluator itself runs unchanged inside Postgres.
//
// Wired in projectors.WireAll. Refs #138, tracker #107 (Phase 2).
func UserGroupListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "user_group" {
			return
		}
		// Multi-write events route through ApplyUserGroup via WithTx
		// so the cascade stays atomic; single-statement events go on
		// the autocommit pool. ApplyUserGroup handles all ten event
		// types when called with tx-bound queries (the rebuild path),
		// so we share its body here for the multi-write cases via
		// WithTx and short-circuit the simple cases through the pool.
		switch e.EventType {
		case "UserGroupCreated",
			"UserGroupQueryUpdated",
			"UserGroupDeleted",
			"UserGroupMemberAdded",
			"UserGroupMemberRemoved",
			"UserGroupMembersRebuilt":
			if err := st.WithTx(ctx, func(q *store.Queries) error {
				return ApplyUserGroup(ctx, q, e)
			}); err != nil {
				logger.Warn("user_group projector: failed to apply event",
					"event_id", e.ID, "event_type", e.EventType, "group_id", e.StreamID, "error", err)
			}
			return
		}
		if err := ApplyUserGroup(ctx, st.Queries(), e); err != nil {
			logger.Warn("user_group projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "group_id", e.StreamID, "error", err)
		}
	}
}

// ApplyUserGroup is the transactional core of the user_group projector.
// The listener wraps it for live-event dispatch (using WithTx for the
// multi-write event types); future rebuild wiring would register it via
// RegisterRebuildApply so RebuildAll re-derives the projection from
// the event store instead of dispatching to the no-op PL/pgSQL stub
// (manchtools/power-manage-server#125 + #138).
//
// Asymmetric-guard discipline is preserved across every multi-write
// event: when the version-guarded UPDATE on the parent row affects
// zero rows, every cascading INSERT/DELETE downstream is skipped —
// otherwise a stale event re-applied later would leak member-count
// drift, dangling members, role assignments, or downstream SCIM-
// mapping rows reappearing.
func ApplyUserGroup(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "user_group" {
		return nil
	}
	switch e.EventType {
	case "UserGroupCreated":
		return applyUserGroupCreated(ctx, q, e)
	case "UserGroupUpdated":
		return applyUserGroupUpdated(ctx, q, e)
	case "UserGroupQueryUpdated":
		return applyUserGroupQueryUpdated(ctx, q, e)
	case "UserGroupMaintenanceWindowSet":
		return applyUserGroupMaintenanceWindowSet(ctx, q, e)
	case "UserGroupDeleted":
		return applyUserGroupDeleted(ctx, q, e)
	case "UserGroupMemberAdded":
		return applyUserGroupMemberAdded(ctx, q, e)
	case "UserGroupMemberRemoved":
		return applyUserGroupMemberRemoved(ctx, q, e)
	case "UserGroupRoleAssigned":
		return applyUserGroupRoleAssigned(ctx, q, e)
	case "UserGroupRoleRevoked":
		return applyUserGroupRoleRevoked(ctx, q, e)
	case "UserGroupMembersRebuilt":
		return applyUserGroupMembersRebuilt(ctx, q, e)
	}
	return nil
}

func applyUserGroupCreated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserGroupCreatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	createdAt := e.OccurredAt
	if err := q.InsertUserGroupProjection(ctx, db.InsertUserGroupProjectionParams{
		ID:                payload.ID,
		Name:              payload.Name,
		Description:       payload.Description,
		CreatedAt:         createdAt,
		CreatedBy:         payload.CreatedBy,
		ProjectionVersion: deref(e.SequenceNum),
		IsDynamic:         payload.IsDynamic,
		DynamicQuery:      payload.DynamicQuery,
	}); err != nil {
		return err
	}
	if !payload.IsDynamic {
		return nil
	}
	// Dynamic group: enqueue for the still-PL/pgSQL evaluator to pick
	// up. ON CONFLICT DO UPDATE on (group_id) refreshes queued_at if
	// the group was already queued, matching the PL/pgSQL projector.
	return q.EnqueueDynamicUserGroupEvaluation(ctx, db.EnqueueDynamicUserGroupEvaluationParams{
		GroupID: payload.ID,
		Reason:  reasonGroupCreatedPointer,
	})
}

func applyUserGroupUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserGroupUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	if _, err := q.UpdateUserGroupProjection(ctx, db.UpdateUserGroupProjectionParams{
		ID:                payload.ID,
		Name:              payload.Name,
		Description:       payload.Description,
		UpdatedAt:         updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyUserGroupQueryUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserGroupQueryUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	n, err := q.UpdateUserGroupQueryProjection(ctx, db.UpdateUserGroupQueryProjectionParams{
		ID:                payload.ID,
		IsDynamic:         payload.IsDynamic,
		DynamicQuery:      payload.DynamicQuery,
		UpdatedAt:         updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		// Stale UserGroupQueryUpdated replay against a row whose
		// projection_version has moved past this event. Skipping the
		// flip-to-dynamic cascade (member wipe + member_count reset +
		// re-enqueue) is mandatory: otherwise an old QueryUpdated
		// re-applied later would silently nuke the live group's
		// members and re-enqueue a group whose query has already
		// changed downstream.
		return nil
	}
	if !payload.IsDynamic {
		return nil
	}
	// Flip-to-dynamic cascade: wipe static members + zero member_count
	// + (re-)enqueue for the evaluator. Mirrors the PL/pgSQL
	// projector's order verbatim.
	if err := q.WipeUserGroupMembers(ctx, payload.ID); err != nil {
		return err
	}
	if err := q.ResetUserGroupMemberCount(ctx, payload.ID); err != nil {
		return err
	}
	return q.EnqueueDynamicUserGroupEvaluation(ctx, db.EnqueueDynamicUserGroupEvaluationParams{
		GroupID: payload.ID,
		Reason:  reasonQueryUpdatedPointer,
	})
}

func applyUserGroupMaintenanceWindowSet(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserGroupMaintenanceWindowSetFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	if _, err := q.UpdateUserGroupMaintenanceWindowProjection(ctx, db.UpdateUserGroupMaintenanceWindowProjectionParams{
		ID:                payload.ID,
		MaintenanceWindow: payload.MaintenanceWindow,
		UpdatedAt:         updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyUserGroupDeleted(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	updatedAt := e.OccurredAt
	n, err := q.SoftDeleteUserGroupProjection(ctx, db.SoftDeleteUserGroupProjectionParams{
		ID:                e.StreamID,
		UpdatedAt:         updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		// Stale UserGroupDeleted replay against a row whose
		// projection_version has moved past this event. Skipping the
		// cascade (SCIM mapping cleanup, member wipe, role-assignment
		// wipe, dynamic-queue cleanup) is mandatory: otherwise an old
		// delete re-applied by the reconciler against a freshly-
		// restored group would silently nuke its members + role
		// assignments + downstream SCIM mapping.
		return nil
	}
	if err := q.DeleteScimGroupMappingsByUserGroup(ctx, e.StreamID); err != nil {
		return err
	}
	if err := q.DeleteUserGroupMembersByGroup(ctx, e.StreamID); err != nil {
		return err
	}
	if err := q.DeleteUserGroupRolesByGroup(ctx, e.StreamID); err != nil {
		return err
	}
	return q.DeleteDynamicUserGroupEvaluationQueueRow(ctx, e.StreamID)
}

func applyUserGroupMemberAdded(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserGroupMemberAddedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	// Mirrors the PL/pgSQL `IF NOT EXISTS (... is_dynamic = TRUE)`
	// guard: the dynamic-query evaluator owns the member set for
	// dynamic groups, so member-mutation events are no-ops there. A
	// missing or soft-deleted parent group also short-circuits via
	// the COALESCE-FALSE return on IsUserGroupDynamic — matches the
	// PL/pgSQL NOT EXISTS branch (a non-existent group has no row
	// with is_dynamic = TRUE, so the projector falls through to the
	// INSERT; we tighten that to "skip if the group can't be confirmed
	// static" to keep ghost-membership rows out of the projection).
	dynamic, err := q.IsUserGroupDynamic(ctx, payload.GroupID)
	if err != nil {
		return err
	}
	if dynamic {
		return nil
	}
	addedAt := e.OccurredAt
	if err := q.InsertUserGroupMember(ctx, db.InsertUserGroupMemberParams{
		GroupID:           payload.GroupID,
		UserID:            payload.UserID,
		AddedAt:           addedAt,
		AddedBy:           e.ActorID,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	if _, err := q.IncrementUserGroupMemberCount(ctx, db.IncrementUserGroupMemberCountParams{
		ID:                payload.GroupID,
		UpdatedAt:         addedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyUserGroupMemberRemoved(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserGroupMemberRemovedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	dynamic, err := q.IsUserGroupDynamic(ctx, payload.GroupID)
	if err != nil {
		return err
	}
	if dynamic {
		return nil
	}
	if err := q.DeleteUserGroupMember(ctx, db.DeleteUserGroupMemberParams{
		GroupID: payload.GroupID,
		UserID:  payload.UserID,
	}); err != nil {
		return err
	}
	updatedAt := e.OccurredAt
	if _, err := q.DecrementUserGroupMemberCount(ctx, db.DecrementUserGroupMemberCountParams{
		ID:                payload.GroupID,
		UpdatedAt:         updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyUserGroupRoleAssigned(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserGroupRoleAssignedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	assignedAt := e.OccurredAt
	return q.InsertUserGroupRole(ctx, db.InsertUserGroupRoleParams{
		GroupID:           payload.GroupID,
		RoleID:            payload.RoleID,
		AssignedAt:        assignedAt,
		AssignedBy:        e.ActorID,
		ProjectionVersion: deref(e.SequenceNum),
	})
}

func applyUserGroupRoleRevoked(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserGroupRoleRevokedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	return q.DeleteUserGroupRole(ctx, db.DeleteUserGroupRoleParams{
		GroupID: payload.GroupID,
		RoleID:  payload.RoleID,
	})
}

func applyUserGroupMembersRebuilt(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserGroupMembersRebuiltFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	// Wipe the existing member set, then bulk-insert the rebuilt list.
	// The PL/pgSQL projector did this with a SELECT FROM
	// jsonb_array_elements_text(...) inside the INSERT; the Go
	// listener iterates the slice in Go since `pgx`'s batched insert
	// for one-row-per-id is microsecond-scale at this scale (a rebuilt
	// list is usually <100 users).
	if err := q.WipeUserGroupMembers(ctx, payload.GroupID); err != nil {
		return err
	}
	addedAt := e.OccurredAt
	for _, userID := range payload.UserIDs {
		if err := q.InsertUserGroupMember(ctx, db.InsertUserGroupMemberParams{
			GroupID:           payload.GroupID,
			UserID:            userID,
			AddedAt:           addedAt,
			AddedBy:           "system",
			ProjectionVersion: deref(e.SequenceNum),
		}); err != nil {
			return err
		}
	}
	if _, err := q.SetUserGroupMemberCount(ctx, db.SetUserGroupMemberCountParams{
		ID:                payload.GroupID,
		MemberCount:       int32(len(payload.UserIDs)),
		UpdatedAt:         addedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}
