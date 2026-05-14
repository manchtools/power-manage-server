package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// AssignmentListener returns a store.EventListener that applies every
// assignment stream event the deleted PL/pgSQL project_assignment_event
// handled. Four event types: AssignmentCreated, AssignmentModeChanged,
// AssignmentSortOrderChanged, AssignmentDeleted.
//
// AssignmentModeChanged and AssignmentSortOrderChanged are not emitted
// by the current handler layer (the project's mutation model is
// "assignments are immutable; mutate by delete-and-recreate"), but the
// projector keeps parity with the PL/pgSQL version so production event
// stores containing such historical events still replay cleanly during
// a rebuild.
//
// Compliance cascade: AssignmentCreated and AssignmentDeleted both
// invoke evaluate_device_compliance_policies (still PL/pgSQL, deferred
// to a later phase of #136) when source_type == "compliance_policy".
// AssignmentDeleted additionally clears the matching
// compliance_policy_evaluation_projection rows BEFORE the re-evaluation
// so the recompute sees a clean slate for the unassigned policy. For
// device_group targets the cascade fans out to every member device.
//
// Multi-write listeners (Created with cascade, Deleted) follow the
// asymmetric-guard discipline: the guarded writer (InsertAssignment-
// Projection / SoftDeleteAssignmentProjection) is :execrows / :one-
// returning, and the listener short-circuits the compliance cascade
// when the guarded write affected zero rows (stale projection_version
// replay).
//
// Wired in projectors.WireAll. Refs #137, tracker #107 (Phase 2).
func AssignmentListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "assignment" {
			return
		}
		// Cascade-bearing events route through ApplyAssignment via
		// WithTx so the guarded write + the compliance cascade share a
		// transaction (the cascade itself touches the still-PL/pgSQL
		// compliance_policy_evaluation_projection and invokes
		// evaluate_device_compliance_policies; tx atomicity keeps the
		// projection consistent if the function raises mid-cascade).
		// Single-statement events go on the autocommit pool.
		switch e.EventType {
		case string(eventtypes.AssignmentCreated), string(eventtypes.AssignmentDeleted):
			if err := st.WithTx(ctx, func(q *store.Queries) error {
				return ApplyAssignment(ctx, q, e)
			}); err != nil {
				logger.Warn("assignment projector: failed to apply event",
					"event_id", e.ID, "event_type", e.EventType, "assignment_id", e.StreamID, "error", err)
			}
			return
		}
		if err := ApplyAssignment(ctx, st.Queries(), e); err != nil {
			logger.Warn("assignment projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "assignment_id", e.StreamID, "error", err)
		}
	}
}

// ApplyAssignment is the transactional core of the assignment
// projector. The listener wraps it for live-event dispatch (using
// WithTx for the cascade-bearing event types); the rebuild path
// (manchtools/power-manage-server#125) registers it via
// RegisterRebuildApply so RebuildAll re-derives the projection from
// the event store instead of dispatching to the no-op PL/pgSQL stub.
//
// Asymmetric-guard discipline is preserved across every multi-write
// event: when the version-guarded write affects zero rows, the
// downstream compliance cascade is skipped — otherwise a stale event
// re-applied later would re-evaluate compliance against a fresher row
// the listener wasn't allowed to write, leaving the evaluation
// projection inconsistent with the assignment row it derives from.
func ApplyAssignment(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "assignment" {
		return nil
	}
	switch e.EventType {
	case string(eventtypes.AssignmentCreated):
		return applyAssignmentCreated(ctx, q, e)
	case string(eventtypes.AssignmentModeChanged):
		return applyAssignmentModeChanged(ctx, q, e)
	case string(eventtypes.AssignmentSortOrderChanged):
		return applyAssignmentSortOrderChanged(ctx, q, e)
	case string(eventtypes.AssignmentDeleted):
		return applyAssignmentDeleted(ctx, q, e)
	}
	return nil
}

func applyAssignmentCreated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := AssignmentCreatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	createdAt := e.OccurredAt
	n, err := q.InsertAssignmentProjection(ctx, db.InsertAssignmentProjectionParams{
		ID:                payload.ID,
		SourceType:        payload.SourceType,
		SourceID:          payload.SourceID,
		TargetType:        payload.TargetType,
		TargetID:          payload.TargetID,
		SortOrder:         payload.SortOrder,
		Mode:              payload.Mode,
		CreatedAt:         &createdAt,
		CreatedBy:         payload.CreatedBy,
		ProjectionVersion: deref(e.SequenceNum),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		// Stale AssignmentCreated replay against a row whose
		// projection_version has already moved past this event. The
		// PL/pgSQL projector's ON CONFLICT DO UPDATE would have
		// silently overwritten the fresher row; we reject it via the
		// guard. Skipping the compliance cascade is mandatory:
		// re-evaluating against a row this listener didn't write would
		// leave compliance_policy_evaluation_projection inconsistent
		// with the actual assignment state.
		return nil
	}
	return cascadeComplianceForAssignment(ctx, q, payload.SourceType, payload.SourceID, payload.TargetType, payload.TargetID, false)
}

func applyAssignmentModeChanged(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := AssignmentModeChangedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	if _, err := q.UpdateAssignmentModeProjection(ctx, db.UpdateAssignmentModeProjectionParams{
		ID:                payload.ID,
		Mode:              payload.Mode,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyAssignmentSortOrderChanged(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := AssignmentSortOrderChangedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	if _, err := q.UpdateAssignmentSortOrderProjection(ctx, db.UpdateAssignmentSortOrderProjectionParams{
		ID:                payload.ID,
		SortOrder:         payload.SortOrder,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyAssignmentDeleted(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	row, err := q.SoftDeleteAssignmentProjection(ctx, db.SoftDeleteAssignmentProjectionParams{
		ID:                e.StreamID,
		ProjectionVersion: deref(e.SequenceNum),
	})
	if err != nil {
		if store.IsNotFound(err) {
			// Stale AssignmentDeleted replay against a row whose
			// projection_version has moved past this event, OR a
			// deletion of a row that no longer exists. Skipping the
			// compliance cascade is mandatory: the source/target tuple
			// the cascade needs lives in the row we didn't read, and
			// re-evaluating against a row this listener didn't write
			// would leave compliance state drifted.
			return nil
		}
		return err
	}
	return cascadeComplianceForAssignment(ctx, q, row.SourceType, row.SourceID, row.TargetType, row.TargetID, true)
}

// cascadeComplianceForAssignment mirrors the PL/pgSQL projector's
// post-write compliance fan-out for source_type == "compliance_policy"
// assignments. When `cleanup` is true (the AssignmentDeleted path) the
// compliance_policy_evaluation_projection rows for the (device,
// policy) pair are wiped BEFORE the re-evaluation so the recompute
// sees a clean slate for the unassigned policy.
//
// Non-compliance assignments early-return; the cascade is only
// meaningful for the compliance_policy source type, matching the
// PL/pgSQL `IF event.data->>'source_type' = 'compliance_policy'`
// outer guard.
func cascadeComplianceForAssignment(ctx context.Context, q *store.Queries, sourceType, sourceID, targetType, targetID string, cleanup bool) error {
	if sourceType != "compliance_policy" {
		return nil
	}
	switch targetType {
	case "device":
		if cleanup {
			if err := q.DeleteCompliancePolicyEvaluationsForDevicePolicy(ctx, db.DeleteCompliancePolicyEvaluationsForDevicePolicyParams{
				DeviceID: targetID,
				PolicyID: sourceID,
			}); err != nil {
				return err
			}
		}
		return q.EvaluateDeviceCompliancePolicies(ctx, targetID)
	case "device_group":
		deviceIDs, err := q.ListDeviceGroupMemberDeviceIDs(ctx, targetID)
		if err != nil {
			return err
		}
		for _, deviceID := range deviceIDs {
			if cleanup {
				if err := q.DeleteCompliancePolicyEvaluationsForDevicePolicy(ctx, db.DeleteCompliancePolicyEvaluationsForDevicePolicyParams{
					DeviceID: deviceID,
					PolicyID: sourceID,
				}); err != nil {
					return err
				}
			}
			if err := q.EvaluateDeviceCompliancePolicies(ctx, deviceID); err != nil {
				return err
			}
		}
	}
	return nil
}
