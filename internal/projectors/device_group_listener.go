package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// reasonDeviceGroupCreated and reasonDeviceGroupQueryUpdated mirror the
// PL/pgSQL projector's `INSERT INTO dynamic_group_evaluation_queue
// (group_id, queued_at, reason) VALUES (..., ..., 'group_created' /
// 'query_updated')` constants. Held as pointers so they can be passed
// straight to the EnqueueDynamicDeviceGroupEvaluation params (the
// reason column is nullable).
var (
	reasonDeviceGroupCreatedString       = "group_created"
	reasonDeviceGroupQueryUpdatedString  = "query_updated"
	reasonDeviceGroupCreatedPointer      = &reasonDeviceGroupCreatedString
	reasonDeviceGroupQueryUpdatedPointer = &reasonDeviceGroupQueryUpdatedString
)

// DeviceGroupListener returns a store.EventListener that applies every
// device_group stream event the deleted PL/pgSQL
// project_device_group_event handled. Nine event types:
// DeviceGroupCreated, DeviceGroupRenamed, DeviceGroupDescriptionUpdated,
// DeviceGroupQueryUpdated, DeviceGroupSyncIntervalSet,
// DeviceGroupMaintenanceWindowSet, DeviceGroupMemberAdded /
// DeviceAddedToGroup, DeviceGroupMemberRemoved / DeviceRemovedFromGroup,
// DeviceGroupDeleted.
//
// Event-type families:
//   - Group CRUD: Created (INSERT + optional dynamic-queue enqueue),
//     Renamed / DescriptionUpdated / SyncIntervalSet /
//     MaintenanceWindowSet (single guarded UPDATE), QueryUpdated
//     (UPDATE + optional flip-to-dynamic cascade), Deleted (soft-delete +
//     member wipe + queue cleanup, wrapped in store.WithTx).
//   - Membership edits: MemberAdded / DeviceAddedToGroup (INSERT +
//     recount, gated by parent-is-dynamic short-circuit), MemberRemoved /
//     DeviceRemovedFromGroup (DELETE + recount, same gate). Each wrapped
//     in store.WithTx so the parent row never observes "member changed
//     but member_count stale".
//
// Multi-write listeners (Created when dynamic, QueryUpdated when
// flipping to dynamic, Deleted, MemberAdded, MemberRemoved) follow the
// asymmetric-guard discipline: the guarded UPDATE on the parent row is
// :execrows, and the listener short-circuits the downstream cascade
// when n == 0 (stale projection_version replay).
//
// Dynamic-query engine scope: per #136 the dynamic-query evaluator
// (evaluate_dynamic_group, evaluate_queued_dynamic_groups,
// validate_dynamic_query) STAYS in PL/pgSQL until a later phase. The
// Go listener only persists the query string column + (re-)enqueues
// the group via EnqueueDynamicDeviceGroupEvaluation when is_dynamic
// flips on; the evaluator runs unchanged inside Postgres.
//
// Wired in projectors.WireAll. Refs #136 (Phase 2 of tracker #107).
func DeviceGroupListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "device_group" {
			return
		}
		// Multi-write events route through ApplyDeviceGroup via WithTx
		// so the cascade stays atomic; single-statement events go on
		// the autocommit pool. ApplyDeviceGroup handles all event
		// types when called with tx-bound queries (the rebuild path),
		// so we share its body here for the multi-write cases via
		// WithTx and short-circuit the simple cases through the pool.
		switch e.EventType {
		case string(eventtypes.DeviceGroupCreated),
			string(eventtypes.DeviceGroupQueryUpdated),
			string(eventtypes.DeviceGroupDeleted),
			string(eventtypes.DeviceGroupMemberAdded),
			string(eventtypes.DeviceAddedToGroup),
			string(eventtypes.DeviceGroupMemberRemoved),
			string(eventtypes.DeviceRemovedFromGroup),
			string(eventtypes.DeviceGroupMembersReevaluated):
			if err := st.WithTx(ctx, func(q *store.Queries) error {
				return ApplyDeviceGroup(ctx, q, e)
			}); err != nil {
				logger.Warn("device_group projector: failed to apply event",
					"event_id", e.ID, "event_type", e.EventType, "group_id", e.StreamID, "error", err)
			}
			return
		}
		if err := ApplyDeviceGroup(ctx, st.Queries(), e); err != nil {
			logger.Warn("device_group projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "group_id", e.StreamID, "error", err)
		}
	}
}

// ApplyDeviceGroup is the transactional core of the device_group
// projector. The listener wraps it for live-event dispatch (using
// WithTx for the multi-write event types); the rebuild path
// (manchtools/power-manage-server#125) registers it via
// RegisterRebuildApply so RebuildAll re-derives the projection from
// the event store instead of dispatching to the no-op PL/pgSQL stub.
//
// Asymmetric-guard discipline is preserved across every multi-write
// event: when the version-guarded UPDATE on the parent row affects
// zero rows, every cascading INSERT/DELETE downstream is skipped —
// otherwise a stale event re-applied later would leak member-count
// drift, dangling members, or deleted rows reappearing.
func ApplyDeviceGroup(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "device_group" {
		return nil
	}
	switch e.EventType {
	case string(eventtypes.DeviceGroupCreated):
		return applyDeviceGroupCreated(ctx, q, e)
	case string(eventtypes.DeviceGroupRenamed):
		return applyDeviceGroupRenamed(ctx, q, e)
	case string(eventtypes.DeviceGroupDescriptionUpdated):
		return applyDeviceGroupDescriptionUpdated(ctx, q, e)
	case string(eventtypes.DeviceGroupQueryUpdated):
		return applyDeviceGroupQueryUpdated(ctx, q, e)
	case string(eventtypes.DeviceGroupSyncIntervalSet):
		return applyDeviceGroupSyncIntervalSet(ctx, q, e)
	case string(eventtypes.DeviceGroupInventoryIntervalSet):
		return applyDeviceGroupInventoryIntervalSet(ctx, q, e)
	case string(eventtypes.DeviceGroupMaintenanceWindowSet):
		return applyDeviceGroupMaintenanceWindowSet(ctx, q, e)
	case string(eventtypes.DeviceGroupMemberAdded), string(eventtypes.DeviceAddedToGroup):
		return applyDeviceGroupMemberAdded(ctx, q, e)
	case string(eventtypes.DeviceGroupMemberRemoved), string(eventtypes.DeviceRemovedFromGroup):
		return applyDeviceGroupMemberRemoved(ctx, q, e)
	case string(eventtypes.DeviceGroupMembersReevaluated):
		return applyDeviceGroupMembersReevaluated(ctx, q, e)
	case string(eventtypes.DeviceGroupDeleted):
		return applyDeviceGroupDeleted(ctx, q, e)
	}
	return nil
}

// applyDeviceGroupMembersReevaluated projects the dynamic-group membership delta
// the evaluator emits (#7 spec 14). The event is the SOURCE OF TRUTH for dynamic
// membership (the evaluator no longer writes the projection directly), so a
// rebuild reconstructs membership by replaying these events. Asymmetric-guard
// discipline: the version+dynamic guard runs FIRST; on n==0 (stale replay,
// flipped-to-static, or deleted) the delta is skipped so it can't resurrect
// removed members or wipe live ones.
func applyDeviceGroupMembersReevaluated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	p, err := decodePayload[payloads.DeviceGroupMembersReevaluated](e, "device_group", eventtypes.DeviceGroupMembersReevaluated)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	n, err := q.ClaimDynamicDeviceGroupForMembership(ctx, db.ClaimDynamicDeviceGroupForMembershipParams{
		ID:                e.StreamID,
		ProjectionVersion: e.SequenceNum,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	addedAt := e.OccurredAt
	for _, id := range p.AddedDeviceIDs {
		if id == "" {
			continue
		}
		if err := q.InsertDeviceGroupMember(ctx, db.InsertDeviceGroupMemberParams{
			GroupID:           e.StreamID,
			DeviceID:          id,
			AddedAt:           &addedAt,
			ProjectionVersion: e.SequenceNum,
		}); err != nil {
			return err
		}
	}
	for _, id := range p.RemovedDeviceIDs {
		if id == "" {
			continue
		}
		if err := q.DeleteDeviceGroupMember(ctx, db.DeleteDeviceGroupMemberParams{
			GroupID:  e.StreamID,
			DeviceID: id,
		}); err != nil {
			return err
		}
	}
	return q.RecountDeviceGroupMembers(ctx, e.StreamID)
}

func applyDeviceGroupCreated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceGroupCreatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	createdAt := e.OccurredAt
	if err := q.InsertDeviceGroupProjection(ctx, db.InsertDeviceGroupProjectionParams{
		ID:                payload.ID,
		Name:              payload.Name,
		Description:       payload.Description,
		IsDynamic:         payload.IsDynamic,
		DynamicQuery:      payload.DynamicQuery,
		CreatedAt:         &createdAt,
		CreatedBy:         payload.CreatedBy,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		return err
	}
	if !payload.IsDynamic {
		return nil
	}
	// Dynamic group: enqueue for the still-PL/pgSQL evaluator to pick
	// up. ON CONFLICT DO UPDATE on (group_id) refreshes queued_at if
	// the group was already queued, matching the PL/pgSQL projector.
	return q.EnqueueDynamicDeviceGroupEvaluation(ctx, db.EnqueueDynamicDeviceGroupEvaluationParams{
		GroupID: payload.ID,
		Reason:  reasonDeviceGroupCreatedPointer,
	})
}

func applyDeviceGroupRenamed(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceGroupRenamedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	if _, err := q.RenameDeviceGroupProjection(ctx, db.RenameDeviceGroupProjectionParams{
		ID:                payload.ID,
		Name:              payload.Name,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		return err
	}
	return nil
}

func applyDeviceGroupDescriptionUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceGroupDescriptionUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	if _, err := q.UpdateDeviceGroupDescriptionProjection(ctx, db.UpdateDeviceGroupDescriptionProjectionParams{
		ID:                payload.ID,
		Description:       payload.Description,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		return err
	}
	return nil
}

func applyDeviceGroupQueryUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceGroupQueryUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	prevIsDynamic, err := q.UpdateDeviceGroupQueryProjection(ctx, db.UpdateDeviceGroupQueryProjectionParams{
		ID:                payload.ID,
		IsDynamic:         payload.IsDynamic,
		DynamicQuery:      payload.DynamicQuery,
		ProjectionVersion: e.SequenceNum,
	})
	if err != nil {
		// pgx surfaces ErrNoRows when the inner UPDATE's version
		// guard rejects a stale replay (the CTE join collapses to
		// zero rows). Treat that as "skip cascade".
		if store.IsNotFound(err) {
			return nil
		}
		return err
	}
	// Cascade ONLY on a true static→dynamic flip. Editing the
	// dynamic_query of an already-dynamic group must preserve the
	// live evaluator-owned member set (sibling fix to the CR catch
	// on the user_group port, PR #174).
	if !payload.IsDynamic || prevIsDynamic {
		return nil
	}
	if err := q.WipeDeviceGroupMembers(ctx, payload.ID); err != nil {
		return err
	}
	if err := q.ResetDeviceGroupMemberCount(ctx, payload.ID); err != nil {
		return err
	}
	return q.EnqueueDynamicDeviceGroupEvaluation(ctx, db.EnqueueDynamicDeviceGroupEvaluationParams{
		GroupID: payload.ID,
		Reason:  reasonDeviceGroupQueryUpdatedPointer,
	})
}

func applyDeviceGroupSyncIntervalSet(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceGroupSyncIntervalSetFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	if _, err := q.UpdateDeviceGroupSyncIntervalProjection(ctx, db.UpdateDeviceGroupSyncIntervalProjectionParams{
		ID:                  payload.ID,
		SyncIntervalMinutes: payload.SyncIntervalMinutes,
		ProjectionVersion:   e.SequenceNum,
	}); err != nil {
		return err
	}
	return nil
}

func applyDeviceGroupInventoryIntervalSet(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceGroupInventoryIntervalSetFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	if _, err := q.UpdateDeviceGroupInventoryIntervalProjection(ctx, db.UpdateDeviceGroupInventoryIntervalProjectionParams{
		ID:                       payload.ID,
		InventoryIntervalMinutes: payload.InventoryIntervalMinutes,
		ProjectionVersion:        e.SequenceNum,
	}); err != nil {
		return err
	}
	return nil
}

func applyDeviceGroupMaintenanceWindowSet(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceGroupMaintenanceWindowSetFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	if _, err := q.UpdateDeviceGroupMaintenanceWindowProjection(ctx, db.UpdateDeviceGroupMaintenanceWindowProjectionParams{
		ID:                payload.ID,
		MaintenanceWindow: payload.MaintenanceWindow,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		return err
	}
	return nil
}

func applyDeviceGroupMemberAdded(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceGroupMemberAddedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	// Atomic guard FIRST: bumps projection_version only when the
	// parent exists, is static, alive, and the event is newer.
	// n==0 means one of those preconditions failed — skip the
	// membership mutation. Doing the version check AFTER the
	// INSERT (the prior shape) let stale events recreate
	// soft-deleted membership rows; CR caught the same hole on
	// the user_group port (PR #174).
	n, err := q.ClaimDeviceGroupForMembership(ctx, db.ClaimDeviceGroupForMembershipParams{
		ID:                payload.GroupID,
		ProjectionVersion: e.SequenceNum,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	addedAt := e.OccurredAt
	if err := q.InsertDeviceGroupMember(ctx, db.InsertDeviceGroupMemberParams{
		GroupID:           payload.GroupID,
		DeviceID:          payload.DeviceID,
		AddedAt:           &addedAt,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		return err
	}
	return q.RecountDeviceGroupMembers(ctx, payload.GroupID)
}

func applyDeviceGroupMemberRemoved(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceGroupMemberRemovedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	n, err := q.ClaimDeviceGroupForMembership(ctx, db.ClaimDeviceGroupForMembershipParams{
		ID:                payload.GroupID,
		ProjectionVersion: e.SequenceNum,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if err := q.DeleteDeviceGroupMember(ctx, db.DeleteDeviceGroupMemberParams{
		GroupID:  payload.GroupID,
		DeviceID: payload.DeviceID,
	}); err != nil {
		return err
	}
	return q.RecountDeviceGroupMembers(ctx, payload.GroupID)
}

func applyDeviceGroupDeleted(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	n, err := q.SoftDeleteDeviceGroupProjection(ctx, db.SoftDeleteDeviceGroupProjectionParams{
		ID:                e.StreamID,
		ProjectionVersion: e.SequenceNum,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		// Stale DeviceGroupDeleted replay against a row whose
		// projection_version has moved past this event. Skipping the
		// cascade (member wipe + dynamic-queue cleanup) is mandatory:
		// otherwise an old delete re-applied by the reconciler against
		// a freshly-restored group would silently nuke its members
		// and remove its evaluation queue entry.
		return nil
	}
	if err := q.DeleteDeviceGroupMembersByGroup(ctx, e.StreamID); err != nil {
		return err
	}
	return q.DeleteDynamicDeviceGroupEvaluationQueueRow(ctx, e.StreamID)
}
