package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/compliance"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// ActionListener returns a store.EventListener that applies BOTH the
// action-stream events the deleted PL/pgSQL project_action_event
// handled (5 ActionXxx + 4 DefinitionXxx for the synthesised-action
// path) AND the definition-stream events the deleted PL/pgSQL
// project_definition_event handled (8 DefinitionXxx for the
// definitions_projection path). One listener owns both because
// DefinitionCreated dispatches across two projections — synthesise an
// actions_projection row (when payload carries `action_type`) OR insert
// a definitions_projection row (otherwise) — and splitting would race
// the two branches against each other.
//
// Event-type families:
//
//   - Action CRUD (action stream): Created (INSERT), Renamed (UPDATE +
//     cross-stream UPDATE on compliance_policy_rules.action_name),
//     DescriptionUpdated / ParamsUpdated (single guarded UPDATE),
//     Deleted (soft-delete + 4-table cascade + per-affected-device
//     reevaluate loop, wrapped in store.WithTx).
//   - Action-side Definition events (action stream — synthesised
//     actions only): DefinitionCreated (INSERT into actions_projection
//     IFF payload carries action_type), DefinitionRenamed /
//     DescriptionUpdated / Deleted (single guarded UPDATE / soft-delete
//     on actions_projection — these mirror the action variants for the
//     synthesised-action row).
//   - Definition CRUD (definition stream): Created (INSERT into
//     definitions_projection IFF payload OMITS action_type), Renamed /
//     DescriptionUpdated / ScheduleUpdated (single guarded UPDATE),
//     Deleted (soft-delete on definitions_projection).
//   - Definition-member edits (definition stream): MemberAdded /
//     MemberRemoved (Claim guard + INSERT|DELETE + recount, wrapped in
//     store.WithTx), MemberReordered (Claim guard + per-row UPDATE,
//     wrapped in store.WithTx).
//
// Multi-write listeners (ActionDeleted, DefinitionDeleted on the
// action-stream branch when the row is the synthesised-action variant,
// DefinitionMemberAdded / MemberRemoved / MemberReordered) follow the
// asymmetric-guard discipline:
//
//   - ActionDeleted: the guarded SoftDelete uses :execrows. When n==0
//     EVERY downstream cascade is skipped — action_set_member decrement,
//     compliance_policy_rules delete + recount, compliance_policy_evaluation
//     delete, compliance_results delete, AND the per-affected-device
//     reevaluate loop. Otherwise a stale ActionDeleted re-applied later
//     against a freshly-restored action would silently nuke its
//     compliance footprint.
//   - DefinitionMemberAdded / MemberRemoved / MemberReordered: Claim-
//     first guard against definitions_projection. Mirrors the
//     user_group / action_set / compliance_policy member ports
//     (PR #174's CR catch).
//
// Compliance reevaluation engine scope: the
// evaluate_device_compliance_policies(p_device_id) function STAYS in
// PL/pgSQL until a later phase (per #136). The Go listener calls into
// the existing shim (q.EvaluateDeviceCompliancePolicies, defined for
// the assignment port) so device compliance status reflects every
// action deletion; the eval engine itself runs unchanged inside
// Postgres.
//
// Wired in projectors.WireAll. Refs #136, tracker #107 (Phase 2).
func ActionListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		// Owns both action and definition stream types — see the
		// header comment for why splitting breaks DefinitionCreated.
		if e.StreamType != "action" && e.StreamType != "definition" {
			return
		}
		// Multi-write events route through ApplyAction via WithTx so
		// the cascade stays atomic; single-statement events go on the
		// autocommit pool. ApplyAction handles every event type when
		// called with tx-bound queries (the rebuild path), so we share
		// its body here for the multi-write cases via WithTx and
		// short-circuit the simple cases through the pool.
		needsTx := false
		switch e.EventType {
		case string(eventtypes.ActionDeleted),
			string(eventtypes.DefinitionMemberAdded),
			string(eventtypes.DefinitionMemberRemoved),
			string(eventtypes.DefinitionMemberReordered):
			needsTx = true
		case string(eventtypes.DefinitionCreated):
			// DefinitionCreated on the action stream that carries
			// action_type is a single INSERT (no cascade). On the
			// definition stream the same event is also a single INSERT
			// (definitions_projection). Neither needs tx wrapping.
			needsTx = false
		}
		if needsTx {
			if err := st.WithTx(ctx, func(q *store.Queries) error {
				return ApplyAction(ctx, q, e)
			}); err != nil {
				logger.Warn("action projector: failed to apply event",
					"event_id", e.ID, "event_type", e.EventType, "stream_type", e.StreamType, "stream_id", e.StreamID, "error", err)
			}
			return
		}
		if err := ApplyAction(ctx, st.Queries(), e); err != nil {
			logger.Warn("action projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "stream_type", e.StreamType, "stream_id", e.StreamID, "error", err)
		}
	}
}

// ApplyAction is the transactional core of the action projector. The
// listener wraps it for live-event dispatch (using WithTx for the
// multi-write event types); the rebuild path
// (manchtools/power-manage-server#125) registers it twice — once for
// the "actions" target (StreamTypes: ["action", "definition"]) and
// once for the "definitions" target (StreamTypes: ["definition"]).
// Both targets share this dispatch body; the per-event StreamType
// gate inside the function makes the dual-registration safe.
//
// Asymmetric-guard discipline is preserved across every multi-write
// event: when the version-guarded UPDATE on the parent row affects
// zero rows, every cascading INSERT/DELETE/loop downstream is skipped.
func ApplyAction(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "action" && e.StreamType != "definition" {
		return nil
	}
	switch {
	case e.StreamType == "action" && e.EventType == string(eventtypes.ActionCreated):
		return applyActionCreated(ctx, q, e)
	case e.StreamType == "action" && e.EventType == string(eventtypes.ActionRenamed):
		return applyActionRenamed(ctx, q, e)
	case e.StreamType == "action" && e.EventType == string(eventtypes.ActionDescriptionUpdated):
		return applyActionDescriptionUpdated(ctx, q, e)
	case e.StreamType == "action" && e.EventType == string(eventtypes.ActionParamsUpdated):
		return applyActionParamsUpdated(ctx, q, e)
	case e.StreamType == "action" && e.EventType == string(eventtypes.ActionDeleted):
		return applyActionDeleted(ctx, q, e)
	case e.EventType == string(eventtypes.DefinitionCreated):
		// Both stream types route through the same handler; the
		// payload's `action_type` presence picks the branch.
		return applyDefinitionCreated(ctx, q, e)
	case e.EventType == string(eventtypes.DefinitionRenamed):
		return applyDefinitionRenamed(ctx, q, e)
	case e.EventType == string(eventtypes.DefinitionDescriptionUpdated):
		return applyDefinitionDescriptionUpdated(ctx, q, e)
	case e.EventType == string(eventtypes.DefinitionDeleted):
		return applyDefinitionDeleted(ctx, q, e)
	case e.StreamType == "definition" && e.EventType == string(eventtypes.DefinitionScheduleUpdated):
		return applyDefinitionScheduleUpdated(ctx, q, e)
	case e.StreamType == "definition" && e.EventType == string(eventtypes.DefinitionMemberAdded):
		return applyDefinitionMemberAdded(ctx, q, e)
	case e.StreamType == "definition" && e.EventType == string(eventtypes.DefinitionMemberRemoved):
		return applyDefinitionMemberRemoved(ctx, q, e)
	case e.StreamType == "definition" && e.EventType == string(eventtypes.DefinitionMemberReordered):
		return applyDefinitionMemberReordered(ctx, q, e)
	}
	return nil
}

// ApplyDefinition is a thin alias to ApplyAction so the rebuild
// registration for the "definitions" target reads naturally
// (RegisterRebuildApply("definitions", ApplyDefinition)). Both
// rebuild targets ("actions" with StreamTypes ["action","definition"]
// and "definitions" with StreamTypes ["definition"]) share the same
// body — the per-event StreamType gate inside ApplyAction makes the
// dual registration safe (a definition event replayed under the
// "actions" rebuild lands on the synthesised-action branches; the
// same event replayed under the "definitions" rebuild lands on the
// definitions_projection branches).
func ApplyDefinition(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	return ApplyAction(ctx, q, e)
}

func applyActionCreated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ActionCreatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	occurredAt := e.OccurredAt
	return q.InsertActionProjection(ctx, db.InsertActionProjectionParams{
		ID:                payload.ID,
		Name:              payload.Name,
		Description:       payload.Description,
		ActionType:        payload.ActionType,
		DesiredState:      payload.DesiredState,
		Params:            payload.Params,
		TimeoutSeconds:    payload.TimeoutSeconds,
		CreatedAt:         &occurredAt,
		UpdatedAt:         &occurredAt,
		CreatedBy:         payload.CreatedBy,
		ProjectionVersion: deref(e.SequenceNum),
		IsSystem:          payload.IsSystem,
		Schedule:          payload.Schedule,
	})
}

func applyActionRenamed(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ActionRenamedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	n, err := q.RenameActionProjection(ctx, db.RenameActionProjectionParams{
		ID:                payload.ID,
		Name:              payload.Name,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		// Stale rename: skip the cross-stream cascade into
		// compliance_policy_rules.action_name. Otherwise a stale rename
		// re-applied after a fresher rename would push the old name
		// into the compliance projection rows.
		return nil
	}
	return q.RenameComplianceRuleActionName(ctx, db.RenameComplianceRuleActionNameParams{
		ActionID:   payload.ID,
		ActionName: payload.Name,
	})
}

func applyActionDescriptionUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ActionDescriptionUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	if _, err := q.UpdateActionDescriptionProjection(ctx, db.UpdateActionDescriptionProjectionParams{
		ID:                payload.ID,
		Description:       payload.Description,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyActionParamsUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ActionParamsUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	if _, err := q.UpdateActionParamsProjection(ctx, db.UpdateActionParamsProjectionParams{
		ID:                payload.ID,
		Params:            payload.Params,
		TimeoutSeconds:    payload.TimeoutSeconds,
		DesiredState:      payload.DesiredState,
		Schedule:          payload.Schedule,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyActionDeleted(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	streamID, err := ActionDeletedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	n, err := q.SoftDeleteActionProjection(ctx, db.SoftDeleteActionProjectionParams{
		ID:                streamID,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		// Stale ActionDeleted replay: every downstream cascade MUST be
		// skipped. Otherwise an old delete re-applied by the reconciler
		// against a freshly-restored action would silently:
		//   - decrement member_count on every action_set that contains it
		//   - delete every compliance_policy_rules row referencing it
		//     (and decrement rule_count on those policies)
		//   - delete every compliance_policy_evaluation row for it
		//   - delete every compliance_results row for it
		//   - trigger a needless reevaluate pass on every device that
		//     was assigned a policy that used to reference it
		return nil
	}
	// Cascade order matches the PL/pgSQL projector verbatim.
	if err := q.DecrementActionSetMemberCountByAction(ctx, streamID); err != nil {
		return err
	}
	if err := q.DeleteActionSetMembersByAction(ctx, streamID); err != nil {
		return err
	}
	// Capture affected policies BEFORE deleting their rules — the
	// follow-up reevaluate loop iterates devices assigned to those
	// policies and the policy ids would be unrecoverable otherwise.
	affectedPolicies, err := q.ListCompliancePolicyIDsByAction(ctx, streamID)
	if err != nil {
		return err
	}
	if len(affectedPolicies) == 0 {
		// No compliance footprint — done. Matches the PL/pgSQL
		// projector's `IF v_affected_policies IS NOT NULL THEN ... END IF;`
		// short-circuit.
		return nil
	}
	if err := q.DecrementCompliancePolicyRuleCountByPolicies(ctx, affectedPolicies); err != nil {
		return err
	}
	if err := q.DeleteCompliancePolicyRulesByAction(ctx, streamID); err != nil {
		return err
	}
	if err := q.DeleteCompliancePolicyEvaluationsByAction(ctx, streamID); err != nil {
		return err
	}
	if err := q.DeleteComplianceResultsByAction(ctx, streamID); err != nil {
		return err
	}
	// Walk every device whose assignment surface includes one of the
	// affected policies (direct or via device_group) and trigger a
	// re-evaluation. Mirrors the PL/pgSQL `FOR v_device_id IN ... LOOP
	// PERFORM evaluate_device_compliance_policies(v_device_id); END
	// LOOP;` shape.
	deviceIDs, err := q.ListDeviceIDsForCompliancePolicies(ctx, affectedPolicies)
	if err != nil {
		return err
	}
	for _, deviceID := range deviceIDs {
		// Bail out on context cancellation so a SIGTERM mid-deletion
		// doesn't keep evaluating against an already-cancelled tx.
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := compliance.EvaluateInTx(ctx, q, deviceID); err != nil {
			return err
		}
	}
	return nil
}

func applyDefinitionCreated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DefinitionCreatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	// The event arrives on BOTH stream types via project_event() —
	// `action` and `definition` — so the listener fires twice. The
	// payload's action_type discriminator picks which projection gets
	// the row, and the OTHER stream's invocation no-ops. We mirror that
	// dispatch here to stay bit-identical with the PL/pgSQL projectors.
	//
	// The (StreamType, SynthesisedAction) truth table:
	//   (action, true)        → INSERT into actions_projection
	//   (action, false)       → no-op (project_action_event branch)
	//   (definition, true)    → no-op (project_definition_event branch)
	//   (definition, false)   → INSERT into definitions_projection
	if e.StreamType == "action" {
		if !payload.SynthesisedAction {
			return nil
		}
		occurredAt := e.OccurredAt
		return q.InsertSynthesisedActionProjection(ctx, db.InsertSynthesisedActionProjectionParams{
			ID:                payload.ID,
			Name:              payload.Name,
			Description:       payload.ActionDescription,
			ActionType:        payload.ActionType,
			DesiredState:      payload.DesiredState,
			Params:            payload.Params,
			TimeoutSeconds:    payload.TimeoutSeconds,
			CreatedAt:         &occurredAt,
			UpdatedAt:         &occurredAt,
			CreatedBy:         payload.CreatedBy,
			ProjectionVersion: deref(e.SequenceNum),
		})
	}
	// e.StreamType == "definition"
	if payload.SynthesisedAction {
		return nil
	}
	occurredAt := e.OccurredAt
	return q.InsertDefinitionProjection(ctx, db.InsertDefinitionProjectionParams{
		ID:                payload.ID,
		Name:              payload.Name,
		Description:       payload.Description,
		Schedule:          payload.Schedule,
		CreatedAt:         &occurredAt,
		UpdatedAt:         &occurredAt,
		CreatedBy:         payload.CreatedBy,
		ProjectionVersion: deref(e.SequenceNum),
	})
}

func applyDefinitionRenamed(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DefinitionRenamedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	// Action-stream invocation of DefinitionRenamed targets the
	// synthesised-action row in actions_projection (PL/pgSQL
	// project_action_event branch). Definition-stream invocation
	// targets definitions_projection. Both UPDATE paths carry the
	// projection_version guard; either silently no-ops when the row
	// doesn't exist (e.g. a synthesised-action rename arriving on the
	// definition stream lands on the no-target branch).
	if e.StreamType == "action" {
		if _, err := q.RenameActionProjection(ctx, db.RenameActionProjectionParams{
			ID:                payload.ID,
			Name:              payload.Name,
			UpdatedAt:         &updatedAt,
			ProjectionVersion: deref(e.SequenceNum),
		}); err != nil {
			return err
		}
		return nil
	}
	if _, err := q.RenameDefinitionProjection(ctx, db.RenameDefinitionProjectionParams{
		ID:                payload.ID,
		Name:              payload.Name,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyDefinitionDescriptionUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DefinitionDescriptionUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	if e.StreamType == "action" {
		// Action-stream branch writes to actions_projection. The
		// PL/pgSQL projector wrote `event.data->>'description'`
		// directly (NULL on absence, "" on explicit empty). The
		// decoder preserves that distinction in DescriptionPtr so
		// the absent-vs-explicit-empty difference reaches the column.
		if _, err := q.UpdateActionDescriptionProjection(ctx, db.UpdateActionDescriptionProjectionParams{
			ID:                payload.ID,
			Description:       payload.DescriptionPtr,
			UpdatedAt:         &updatedAt,
			ProjectionVersion: deref(e.SequenceNum),
		}); err != nil {
			return err
		}
		return nil
	}
	if _, err := q.UpdateDefinitionDescriptionProjection(ctx, db.UpdateDefinitionDescriptionProjectionParams{
		ID:                payload.ID,
		Description:       payload.Description,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyDefinitionScheduleUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DefinitionScheduleUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	if _, err := q.UpdateDefinitionScheduleProjection(ctx, db.UpdateDefinitionScheduleProjectionParams{
		ID:                payload.ID,
		Schedule:          payload.Schedule,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyDefinitionDeleted(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	streamID, err := DefinitionDeletedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	if e.StreamType == "action" {
		// Targets the synthesised-action row in actions_projection.
		// No further cascade — the synthesised action lives only in
		// actions_projection, with no action_set / compliance_rule
		// references owned by the synthesis path.
		if _, err := q.SoftDeleteActionProjection(ctx, db.SoftDeleteActionProjectionParams{
			ID:                streamID,
			UpdatedAt:         &updatedAt,
			ProjectionVersion: deref(e.SequenceNum),
		}); err != nil {
			return err
		}
		return nil
	}
	if _, err := q.SoftDeleteDefinitionProjection(ctx, db.SoftDeleteDefinitionProjectionParams{
		ID:                streamID,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}

func applyDefinitionMemberAdded(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DefinitionMemberAddedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	// Claim-first guard against definitions_projection. Mirrors the
	// user_group / action_set / compliance_policy member ports
	// (PR #174's CR catch). Doing the version check BEFORE the INSERT
	// closes the stale-replay hole that would otherwise let a stale
	// MemberAdded recreate a previously-removed membership row, even
	// though InsertDefinitionMember is idempotent (ON CONFLICT DO
	// NOTHING).
	updatedAt := e.OccurredAt
	n, err := q.ClaimDefinitionForMembership(ctx, db.ClaimDefinitionForMembershipParams{
		ID:                payload.DefinitionID,
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
	if err := q.InsertDefinitionMember(ctx, db.InsertDefinitionMemberParams{
		DefinitionID:      payload.DefinitionID,
		ActionSetID:       payload.ActionSetID,
		SortOrder:         payload.SortOrder,
		AddedAt:           &addedAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return q.RecountDefinitionMembers(ctx, payload.DefinitionID)
}

func applyDefinitionMemberRemoved(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DefinitionMemberRemovedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	n, err := q.ClaimDefinitionForMembership(ctx, db.ClaimDefinitionForMembershipParams{
		ID:                payload.DefinitionID,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: deref(e.SequenceNum),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if err := q.DeleteDefinitionMember(ctx, db.DeleteDefinitionMemberParams{
		DefinitionID: payload.DefinitionID,
		ActionSetID:  payload.ActionSetID,
	}); err != nil {
		return err
	}
	return q.RecountDefinitionMembers(ctx, payload.DefinitionID)
}

func applyDefinitionMemberReordered(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DefinitionMemberReorderedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	updatedAt := e.OccurredAt
	n, err := q.ClaimDefinitionForMembership(ctx, db.ClaimDefinitionForMembershipParams{
		ID:                payload.DefinitionID,
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
	if _, err := q.UpdateDefinitionMemberSortOrder(ctx, db.UpdateDefinitionMemberSortOrderParams{
		DefinitionID:      payload.DefinitionID,
		ActionSetID:       payload.ActionSetID,
		SortOrder:         payload.SortOrder,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		return err
	}
	return nil
}
