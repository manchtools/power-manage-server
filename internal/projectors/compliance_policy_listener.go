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

// CompliancePolicyListener returns a store.EventListener that applies
// every compliance_policy stream event the deleted PL/pgSQL
// project_compliance_policy_event handled. Seven event types: Created,
// Renamed, DescriptionUpdated, Deleted, RuleAdded, RuleRemoved,
// RuleUpdated.
//
// Event-type families:
//   - Policy CRUD: Created (INSERT), Renamed / DescriptionUpdated
//     (single guarded UPDATE), Deleted (soft-delete + cascade DELETE on
//     rules + DELETE on evaluations + reevaluate-devices shim, wrapped
//     in store.WithTx).
//   - Rule edits: RuleAdded (Claim guard + UPSERT + recount, wrapped in
//     store.WithTx), RuleRemoved (Claim guard + DELETE rule + recount +
//     DELETE evaluations + reevaluate-devices shim, wrapped in
//     store.WithTx), RuleUpdated (Claim guard + per-row UPDATE,
//     wrapped in store.WithTx).
//
// Multi-write listeners (Deleted, RuleAdded, RuleRemoved, RuleUpdated)
// follow the asymmetric-guard discipline:
//
//   - Deleted: the guarded UPDATE (SoftDelete) is :execrows, and the
//     listener short-circuits the cascade (rule wipe, evaluation wipe,
//     reevaluate) when n == 0.
//   - RuleAdded / RuleRemoved / RuleUpdated: the Claim-first guard
//     (ClaimCompliancePolicyForRuleMutation, :execrows) bumps the parent's
//     projection_version BEFORE any rule-table mutation, and the
//     listener short-circuits when n == 0. This is the lesson from
//     PR #174's CR review: the prior insert-then-recount shape let
//     stale replays silently resurrect removed rules or rewind a
//     fresher RuleUpdated, because the version check was downstream of
//     the child-row mutation.
//
// Reevaluation engine scope: per #136 the
// reevaluate_compliance_policy_devices(p_policy_id) function — and the
// evaluate_device_compliance_policies family it calls — STAY in
// PL/pgSQL until a later phase. The Go listener calls into the shim
// (sqlc-generated ReevaluateCompliancePolicyDevices) so device
// compliance status reflects rule mutations; the eval engine itself
// runs unchanged inside Postgres.
//
// Wired in projectors.WireAll. Refs #136 (Phase 2 of tracker #107).
func CompliancePolicyListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "compliance_policy" {
			return
		}
		// Multi-write events route through ApplyCompliancePolicy via
		// WithTx so the cascade stays atomic; single-statement events
		// (Created, Renamed, DescriptionUpdated) go on the autocommit
		// pool. ApplyCompliancePolicy handles all seven event types
		// when called with tx-bound queries (the rebuild path), so
		// we share its body here for the multi-write cases via WithTx
		// and short-circuit the simple cases through the pool.
		switch e.EventType {
		case string(eventtypes.CompliancePolicyDeleted),
			string(eventtypes.CompliancePolicyRuleAdded),
			string(eventtypes.CompliancePolicyRuleRemoved),
			string(eventtypes.CompliancePolicyRuleUpdated):
			if err := st.WithTx(ctx, func(q *store.Queries) error {
				return ApplyCompliancePolicy(ctx, q, e)
			}); err != nil {
				logger.Warn("compliance_policy projector: failed to apply event",
					"event_id", e.ID, "event_type", e.EventType, "policy_id", e.StreamID, "error", err)
			}
			return
		}
		if err := ApplyCompliancePolicy(ctx, st.Queries(), e); err != nil {
			logger.Warn("compliance_policy projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "policy_id", e.StreamID, "error", err)
		}
	}
}

// ApplyCompliancePolicy is the transactional core of the
// compliance_policy projector. The listener wraps it for live-event
// dispatch (using WithTx for the multi-write event types); future
// rebuild wiring would register it via RegisterRebuildApply so
// RebuildAll re-derives the projection from the event store instead
// of dispatching to the no-op PL/pgSQL stub
// (manchtools/power-manage-server#125 + #136).
//
// Asymmetric-guard discipline is preserved across every multi-write
// event: when the version-guarded UPDATE on the parent row affects
// zero rows, every cascading INSERT/DELETE downstream is skipped —
// otherwise a stale event re-applied later would leak rule_count
// drift, dangling rules, dangling evaluations, or removed rules
// reappearing.
func ApplyCompliancePolicy(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "compliance_policy" {
		return nil
	}
	switch e.EventType {
	case string(eventtypes.CompliancePolicyCreated):
		return applyCompliancePolicyCreated(ctx, q, e)
	case string(eventtypes.CompliancePolicyRenamed):
		return applyCompliancePolicyRenamed(ctx, q, e)
	case string(eventtypes.CompliancePolicyDescriptionUpdated):
		return applyCompliancePolicyDescriptionUpdated(ctx, q, e)
	case string(eventtypes.CompliancePolicyDeleted):
		return applyCompliancePolicyDeleted(ctx, q, e)
	case string(eventtypes.CompliancePolicyRuleAdded):
		return applyCompliancePolicyRuleAdded(ctx, q, e)
	case string(eventtypes.CompliancePolicyRuleRemoved):
		return applyCompliancePolicyRuleRemoved(ctx, q, e)
	case string(eventtypes.CompliancePolicyRuleUpdated):
		return applyCompliancePolicyRuleUpdated(ctx, q, e)
	}
	return nil
}

func applyCompliancePolicyCreated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := CompliancePolicyCreatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	createdAt := e.OccurredAt
	return q.InsertCompliancePolicyProjection(ctx, db.InsertCompliancePolicyProjectionParams{
		ID:                payload.ID,
		Name:              payload.Name,
		Description:       payload.Description,
		CreatedAt:         &createdAt,
		CreatedBy:         payload.CreatedBy,
		ProjectionVersion: e.SequenceNum,
	})
}

func applyCompliancePolicyRenamed(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := CompliancePolicyRenamedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	if _, err := q.RenameCompliancePolicyProjection(ctx, db.RenameCompliancePolicyProjectionParams{
		ID:                payload.ID,
		Name:              payload.Name,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		return err
	}
	return nil
}

func applyCompliancePolicyDescriptionUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := CompliancePolicyDescriptionUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	if _, err := q.UpdateCompliancePolicyDescriptionProjection(ctx, db.UpdateCompliancePolicyDescriptionProjectionParams{
		ID:                payload.ID,
		Description:       payload.Description,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		return err
	}
	return nil
}

func applyCompliancePolicyDeleted(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	n, err := q.SoftDeleteCompliancePolicyProjection(ctx, db.SoftDeleteCompliancePolicyProjectionParams{
		ID:                e.StreamID,
		ProjectionVersion: e.SequenceNum,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		// Stale CompliancePolicyDeleted replay against a row whose
		// projection_version has moved past this event. Skipping the
		// cascade (rule wipe, evaluation wipe, reevaluate shim) is
		// mandatory: otherwise an old delete re-applied by the
		// reconciler against a freshly-restored policy would silently
		// nuke its rules and evaluations and trigger a needless
		// device re-evaluation pass.
		return nil
	}
	if err := q.DeleteCompliancePolicyRulesByPolicy(ctx, e.StreamID); err != nil {
		return err
	}
	if err := q.DeleteCompliancePolicyEvaluationsByPolicy(ctx, e.StreamID); err != nil {
		return err
	}
	// reevaluate_compliance_policy_devices is the still-PL/pgSQL eval
	// engine's entry point per #136. Calling it here keeps device
	// compliance status in sync with the policy deletion (devices
	// whose only failing rule lived under the now-deleted policy
	// flip back to compliant on the next read).
	return compliance.ReevaluatePolicyInTx(ctx, q, e.StreamID)
}

func applyCompliancePolicyRuleAdded(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := CompliancePolicyRuleAddedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	// Claim-first guard: the Claim query bumps projection_version only
	// when the policy exists, is alive, and the event is newer.
	// n==0 means one of those preconditions failed — skip the rule
	// mutation entirely. Doing the version check AFTER the UPSERT
	// (the prior insert-then-recount shape used by other ports before
	// PR #174's CR review) let stale events resurrect removed rules
	// even when the parent guard would have rejected the version bump.
	n, err := q.ClaimCompliancePolicyForRuleMutation(ctx, db.ClaimCompliancePolicyForRuleMutationParams{
		ID:                payload.PolicyID,
		ProjectionVersion: e.SequenceNum,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	addedAt := e.OccurredAt
	if err := q.UpsertCompliancePolicyRule(ctx, db.UpsertCompliancePolicyRuleParams{
		PolicyID:          payload.PolicyID,
		ActionID:          payload.ActionID,
		ActionName:        payload.ActionName,
		GracePeriodHours:  payload.GracePeriodHours,
		AddedAt:           &addedAt,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		return err
	}
	// Recount after mutate (live COUNT(*)) so the UPSERT half (which
	// either inserts or updates in-place) does not drift rule_count:
	// a re-emitted RuleAdded for the same (policy, action) pair must
	// not increment the count.
	return q.RecountCompliancePolicyRules(ctx, payload.PolicyID)
}

func applyCompliancePolicyRuleRemoved(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := CompliancePolicyRuleRemovedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	n, err := q.ClaimCompliancePolicyForRuleMutation(ctx, db.ClaimCompliancePolicyForRuleMutationParams{
		ID:                payload.PolicyID,
		ProjectionVersion: e.SequenceNum,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if err := q.DeleteCompliancePolicyRule(ctx, db.DeleteCompliancePolicyRuleParams{
		PolicyID: payload.PolicyID,
		ActionID: payload.ActionID,
	}); err != nil {
		return err
	}
	if err := q.RecountCompliancePolicyRules(ctx, payload.PolicyID); err != nil {
		return err
	}
	if err := q.DeleteCompliancePolicyEvaluationsByRule(ctx, db.DeleteCompliancePolicyEvaluationsByRuleParams{
		PolicyID: payload.PolicyID,
		ActionID: payload.ActionID,
	}); err != nil {
		return err
	}
	return compliance.ReevaluatePolicyInTx(ctx, q, payload.PolicyID)
}

func applyCompliancePolicyRuleUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := CompliancePolicyRuleUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	n, err := q.ClaimCompliancePolicyForRuleMutation(ctx, db.ClaimCompliancePolicyForRuleMutationParams{
		ID:                payload.PolicyID,
		ProjectionVersion: e.SequenceNum,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	return q.UpdateCompliancePolicyRuleGracePeriod(ctx, db.UpdateCompliancePolicyRuleGracePeriodParams{
		PolicyID:          payload.PolicyID,
		ActionID:          payload.ActionID,
		GracePeriodHours:  payload.GracePeriodHours,
		ProjectionVersion: e.SequenceNum,
	})
}
