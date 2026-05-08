package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jackc/pgx/v5"

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
//   - Role assignments: RoleAssigned (INSERT) and RoleRevoked (DELETE).
//     Each runs a Claim guard against the parent before touching
//     user_group_roles_projection so a stale replay can't silently
//     grant or revoke inherited permissions; both wrapped in
//     store.WithTx so the guard + mutation are atomic.
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
			"UserGroupMembersRebuilt",
			"UserGroupRoleAssigned",
			"UserGroupRoleRevoked":
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
	prevIsDynamic, err := q.UpdateUserGroupQueryProjection(ctx, db.UpdateUserGroupQueryProjectionParams{
		ID:                payload.ID,
		IsDynamic:         payload.IsDynamic,
		DynamicQuery:      payload.DynamicQuery,
		UpdatedAt:         e.OccurredAt,
		ProjectionVersion: deref(e.SequenceNum),
	})
	if err != nil {
		// pgx surfaces sql.ErrNoRows / pgx.ErrNoRows when the inner
		// UPDATE's :execrows guard rejects a stale replay (the
		// CTE join collapses to zero rows). That MUST be treated as
		// "skip cascade" — propagating the error would roll back the
		// listener TX and surface a hot loop on every reconciler pass.
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	// Cascade ONLY on a true static→dynamic flip. Editing the
	// dynamic_query of an already-dynamic group must preserve the
	// live evaluator-owned member set (CR catch on PR #174); without
	// this gate, a steady-state query edit would wipe + zero +
	// re-enqueue every member.
	if !payload.IsDynamic || prevIsDynamic {
		return nil
	}
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
	// Atomic guard FIRST: the claim query bumps projection_version
	// only when the parent group exists, is static, alive, and the
	// event is newer. n==0 means one of those preconditions failed —
	// skip the membership mutation entirely. Doing the version check
	// AFTER the INSERT (the prior shape) let stale events recreate
	// soft-deleted membership rows even when the parent guard
	// rejected the bump (CR catch on PR #174).
	n, err := q.ClaimUserGroupForMembership(ctx, db.ClaimUserGroupForMembershipParams{
		ID:                payload.GroupID,
		UpdatedAt:         e.OccurredAt,
		ProjectionVersion: deref(e.SequenceNum),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if err := q.InsertUserGroupMember(ctx, db.InsertUserGroupMemberParams{
		GroupID:           payload.GroupID,
		UserID:            payload.UserID,
		AddedAt:           e.OccurredAt,
		AddedBy:           e.ActorID,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	// Recount after mutate (live COUNT(*)) so ON CONFLICT DO NOTHING
	// idempotency does not drift the count: a duplicate Add is a
	// no-op on the table AND on member_count.
	return q.RecountUserGroupMembers(ctx, payload.GroupID)
}

func applyUserGroupMemberRemoved(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := UserGroupMemberRemovedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	n, err := q.ClaimUserGroupForMembership(ctx, db.ClaimUserGroupForMembershipParams{
		ID:                payload.GroupID,
		UpdatedAt:         e.OccurredAt,
		ProjectionVersion: deref(e.SequenceNum),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if err := q.DeleteUserGroupMember(ctx, db.DeleteUserGroupMemberParams{
		GroupID: payload.GroupID,
		UserID:  payload.UserID,
	}); err != nil {
		return err
	}
	if err := q.RecountUserGroupMembers(ctx, payload.GroupID); err != nil {
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
	// Atomic guard FIRST: bumps projection_version only when the
	// parent group exists, is alive, and the event is newer.
	// n==0 means skip the role mutation. Doing the version check
	// AFTER the INSERT (the prior shape) let stale replays reinsert
	// revoked role assignments — silently re-granting inherited
	// permissions (CR catch on PR #174).
	n, err := q.ClaimUserGroupForRoleMutation(ctx, db.ClaimUserGroupForRoleMutationParams{
		ID:                payload.GroupID,
		UpdatedAt:         e.OccurredAt,
		ProjectionVersion: deref(e.SequenceNum),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	return q.InsertUserGroupRole(ctx, db.InsertUserGroupRoleParams{
		GroupID:           payload.GroupID,
		RoleID:            payload.RoleID,
		AssignedAt:        e.OccurredAt,
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
	n, err := q.ClaimUserGroupForRoleMutation(ctx, db.ClaimUserGroupForRoleMutationParams{
		ID:                payload.GroupID,
		UpdatedAt:         e.OccurredAt,
		ProjectionVersion: deref(e.SequenceNum),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
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
	// Atomic guard FIRST: a stale Rebuilt replayed after later
	// member edits must not nuke the live member set. The Claim
	// query bumps projection_version + acts as the gate; n==0 means
	// the parent is dynamic, soft-deleted, missing, or already at a
	// newer version — skip the wipe-and-replace entirely (CR catch
	// on PR #174).
	n, err := q.ClaimUserGroupForMembership(ctx, db.ClaimUserGroupForMembershipParams{
		ID:                payload.GroupID,
		UpdatedAt:         e.OccurredAt,
		ProjectionVersion: deref(e.SequenceNum),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if err := q.WipeUserGroupMembers(ctx, payload.GroupID); err != nil {
		return err
	}
	for _, userID := range payload.UserIDs {
		if err := q.InsertUserGroupMember(ctx, db.InsertUserGroupMemberParams{
			GroupID:           payload.GroupID,
			UserID:            userID,
			AddedAt:           e.OccurredAt,
			AddedBy:           "system",
			ProjectionVersion: deref(e.SequenceNum),
		}); err != nil {
			return err
		}
	}
	return q.RecountUserGroupMembers(ctx, payload.GroupID)
}
