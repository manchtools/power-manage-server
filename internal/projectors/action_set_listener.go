package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// ActionSetListener returns a store.EventListener that applies every
// action_set stream event the deleted PL/pgSQL project_action_set_event
// handled. Eight event types: Created, Renamed, DescriptionUpdated,
// ScheduleUpdated, MemberAdded, MemberRemoved, MemberReordered,
// Deleted.
//
// Event-type families:
//   - Set CRUD: Created (INSERT), Renamed / DescriptionUpdated /
//     ScheduleUpdated (single guarded UPDATE), Deleted (soft-delete +
//     cascade DELETE on members + decrement-and-clean parent
//     definitions, wrapped in store.WithTx).
//   - Member edits: MemberAdded (INSERT + recount), MemberRemoved
//     (DELETE + recount), MemberReordered (per-row UPDATE + bump-
//     parent-updated_at), each wrapped in store.WithTx so the parent
//     row never observes "member changed but member_count stale".
//
// Multi-write listeners (Deleted, MemberAdded, MemberRemoved,
// MemberReordered) follow the asymmetric-guard discipline: the
// guarded UPDATE is :execrows, and the listener short-circuits the
// downstream cascade when n == 0 (stale projection_version replay).
//
// Wired in projectors.WireAll. Refs #136, tracker #107 (Phase 2).
func ActionSetListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "action_set" {
			return
		}
		// Multi-write events route through ApplyActionSet via WithTx
		// so the cascade stays atomic; single-statement events go on
		// the autocommit pool. ApplyActionSet handles all eight event
		// types when called with tx-bound queries (the rebuild path),
		// so we share its body here for the multi-write cases via
		// WithTx and short-circuit the simple cases through the pool.
		switch e.EventType {
		case "ActionSetMemberAdded",
			"ActionSetMemberRemoved",
			"ActionSetMemberReordered",
			"ActionSetDeleted":
			if err := st.WithTx(ctx, func(q *store.Queries) error {
				return ApplyActionSet(ctx, q, e)
			}); err != nil {
				logger.Warn("action_set projector: failed to apply event",
					"event_id", e.ID, "event_type", e.EventType, "set_id", e.StreamID, "error", err)
			}
			return
		}
		if err := ApplyActionSet(ctx, st.Queries(), e); err != nil {
			logger.Warn("action_set projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "set_id", e.StreamID, "error", err)
		}
	}
}

// ApplyActionSet is the transactional core of the action_set projector.
// The listener wraps it for live-event dispatch (using WithTx for the
// multi-write event types); the rebuild path
// (manchtools/power-manage-server#125) registers it via
// RegisterRebuildApply so RebuildAll re-derives the projection from
// the event store instead of dispatching to the no-op PL/pgSQL stub.
//
// Asymmetric-guard discipline is preserved across every multi-write
// event: when the version-guarded UPDATE on the parent row affects
// zero rows, every cascading INSERT/DELETE downstream is skipped —
// otherwise a stale event re-applied later would leak member-count
// drift, dangling members, or deleted rows reappearing.
func ApplyActionSet(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "action_set" {
		return nil
	}
	switch e.EventType {
	case "ActionSetCreated":
		return applyActionSetCreated(ctx, q, e)
	case "ActionSetRenamed":
		return applyActionSetRenamed(ctx, q, e)
	case "ActionSetDescriptionUpdated":
		return applyActionSetDescriptionUpdated(ctx, q, e)
	case "ActionSetScheduleUpdated":
		return applyActionSetScheduleUpdated(ctx, q, e)
	case "ActionSetMemberAdded":
		return applyActionSetMemberAdded(ctx, q, e)
	case "ActionSetMemberRemoved":
		return applyActionSetMemberRemoved(ctx, q, e)
	case "ActionSetMemberReordered":
		return applyActionSetMemberReordered(ctx, q, e)
	case "ActionSetDeleted":
		return applyActionSetDeleted(ctx, q, e)
	}
	return nil
}

func applyActionSetCreated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ActionSetCreatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	return q.InsertActionSetProjection(ctx, db.InsertActionSetProjectionParams{
		ID:                payload.ID,
		Name:              payload.Name,
		Description:       payload.Description,
		Schedule:          payload.Schedule,
		CreatedAt:         &e.OccurredAt,
		CreatedBy:         payload.CreatedBy,
		ProjectionVersion: deref(e.SequenceNum),
	})
}

func applyActionSetRenamed(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ActionSetRenamedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	if _, err := q.RenameActionSetProjection(ctx, db.RenameActionSetProjectionParams{
		ID:                payload.ID,
		Name:              payload.Name,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyActionSetDescriptionUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ActionSetDescriptionUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	if _, err := q.UpdateActionSetDescriptionProjection(ctx, db.UpdateActionSetDescriptionProjectionParams{
		ID:                payload.ID,
		Description:       payload.Description,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyActionSetScheduleUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ActionSetScheduleUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	if _, err := q.UpdateActionSetScheduleProjection(ctx, db.UpdateActionSetScheduleProjectionParams{
		ID:                payload.ID,
		Schedule:          payload.Schedule,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyActionSetMemberAdded(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ActionSetMemberAddedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	// Atomic guard FIRST: bumps projection_version only when the
	// parent set exists, is alive, and the event is newer. n==0
	// means skip the membership mutation entirely. Doing the version
	// check AFTER the INSERT (the prior shape) let stale events
	// recreate deleted membership rows even when the recount guard
	// rejected the bump (CR catch on user_group port PR #174;
	// applied here as a follow-up sibling-sweep).
	updatedAt := e.OccurredAt
	n, err := q.ClaimActionSetForMembership(ctx, db.ClaimActionSetForMembershipParams{
		ID:                payload.SetID,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	addedAt := e.OccurredAt
	if err := q.InsertActionSetMember(ctx, db.InsertActionSetMemberParams{
		SetID:             payload.SetID,
		ActionID:          payload.ActionID,
		SortOrder:         payload.SortOrder,
		AddedAt:           &addedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return q.RecountActionSetMembers(ctx, payload.SetID)
}

func applyActionSetMemberRemoved(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ActionSetMemberRemovedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	n, err := q.ClaimActionSetForMembership(ctx, db.ClaimActionSetForMembershipParams{
		ID:                payload.SetID,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if err := q.DeleteActionSetMember(ctx, db.DeleteActionSetMemberParams{
		SetID:    payload.SetID,
		ActionID: payload.ActionID,
	}); err != nil {
		return err
	}
	return q.RecountActionSetMembers(ctx, payload.SetID)
}

func applyActionSetMemberReordered(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ActionSetMemberReorderedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	// Claim the parent first so a stale reorder can't bump the
	// per-member sort_order against a fresher parent projection_version.
	updatedAt := e.OccurredAt
	n, err := q.ClaimActionSetForMembership(ctx, db.ClaimActionSetForMembershipParams{
		ID:                payload.SetID,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	// Per-member projection_version guard still runs to prevent
	// reorders applied out of order from clobbering each other.
	if _, err := q.UpdateActionSetMemberSortOrder(ctx, db.UpdateActionSetMemberSortOrderParams{
		SetID:             payload.SetID,
		ActionID:          payload.ActionID,
		SortOrder:         payload.SortOrder,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyActionSetDeleted(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	updatedAt := e.OccurredAt
	n, err := q.SoftDeleteActionSetProjection(ctx, db.SoftDeleteActionSetProjectionParams{
		ID:                e.StreamID,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		// Stale ActionSetDeleted replay against a row whose
		// projection_version has moved past this event. Skipping the
		// cascade is mandatory: otherwise an old delete re-applied by
		// the reconciler against a freshly-restored set would silently
		// nuke its members and decrement member_count on every
		// definition that contains it.
		return nil
	}
	if err := q.DeleteActionSetMembersBySet(ctx, e.StreamID); err != nil {
		return err
	}
	// Order matters: decrement BEFORE deleting the
	// definition_members rows. Once those are gone the subquery
	// inside DecrementDefinitionMemberCountByActionSet sees no
	// matches and the recount no-ops.
	if err := q.DecrementDefinitionMemberCountByActionSet(ctx, e.StreamID); err != nil {
		return err
	}
	return q.DeleteDefinitionMembersByActionSet(ctx, e.StreamID)
}
