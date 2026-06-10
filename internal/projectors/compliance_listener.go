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

// ComplianceListener returns a store.EventListener that applies every
// compliance stream event the deleted PL/pgSQL project_compliance_event
// handled. Two event types: ComplianceResultUpdated, ComplianceResultRemoved.
//
// Both event types are multi-write — the projection mutation is paired
// with a call into the still-PL/pgSQL evaluate_device_compliance_policies
// reevaluator so the cascade matches PL/pgSQL behaviour. Wrapping in
// store.WithTx keeps the cascade atomic with itself (the projection
// write and the reevaluate run inside one transaction); the cascade is
// not atomic with the event commit because the listener fires post-
// commit, but the read-after-write paths (handlers reading
// compliance_results_projection back after an AppendEvent) still see
// the projection because fireListeners is synchronous — the listener
// has already run by the time AppendEvent returns.
//
// Stale-replay guard: ComplianceResultUpdated routes through an
// UPSERT whose UPDATE branch carries an explicit
// `WHERE projection_version < EXCLUDED.projection_version` predicate
// (mirrors the role + identity_provider + action_set + assignment +
// user_group + device_group + compliance_policy ports). There is no
// parent table to Claim against here — compliance_results_projection
// is the only projection in the cascade — so the guard lives directly
// on the UPSERT rather than upstream.
//
// Reevaluation engine scope: per #136 the
// evaluate_device_compliance_policies(p_device_id) function — and the
// per-policy evaluator family it dispatches to — STAY in PL/pgSQL
// until a later phase. The Go listener calls into the existing shim
// (EvaluateDeviceCompliancePolicies, defined in assignments.sql for
// the assignment port) so device compliance status reflects every
// result mutation; the eval engine itself runs unchanged inside
// Postgres.
//
// Wired in projectors.WireAll. Refs #136 (Phase 2 of tracker #107).
func ComplianceListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "compliance" {
			return
		}
		// Both event types do a projection write + a reevaluator call,
		// so they always go through WithTx for cascade atomicity.
		if err := st.WithTx(ctx, func(q *store.Queries) error {
			return ApplyCompliance(ctx, q, e)
		}); err != nil {
			logger.Warn("compliance projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "stream_id", e.StreamID, "error", err)
		}
	}
}

// ApplyCompliance is the transactional core of the compliance
// projector. The listener wraps it for live-event dispatch (using
// WithTx for the multi-write event types). compliance_results is not
// in store.AllRebuildTargets — there is no operator-facing rebuild
// for it — so this isn't registered via RegisterRebuildApply. If a
// rebuild target is ever added, this signature is the standard
// RebuildApply shape and can be wired in projectors.WireAll without
// changing the body.
func ApplyCompliance(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "compliance" {
		return nil
	}
	switch e.EventType {
	case string(eventtypes.ComplianceResultUpdated):
		return applyComplianceResultUpdated(ctx, q, e)
	case string(eventtypes.ComplianceResultRemoved):
		return applyComplianceResultRemoved(ctx, q, e)
	}
	return nil
}

func applyComplianceResultUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ComplianceResultUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	checkedAt := e.OccurredAt
	if err := q.UpsertComplianceResultProjection(ctx, db.UpsertComplianceResultProjectionParams{
		DeviceID:          payload.DeviceID,
		ActionID:          payload.ActionID,
		ActionName:        payload.ActionName,
		Compliant:         payload.Compliant,
		DetectionOutput:   []byte(payload.DetectionOutput),
		CheckedAt:         checkedAt,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		return err
	}
	// evaluate_device_compliance_policies is the still-PL/pgSQL eval
	// engine's entry point per #136. Calling it here keeps device-
	// level compliance_status (devices_projection) in sync with the
	// per-action result mutation: the PL/pgSQL function recomputes
	// the device's pass/fail/grace verdict by aggregating across
	// every result + every assigned policy's grace window.
	return compliance.EvaluateInTx(ctx, q, payload.DeviceID)
}

func applyComplianceResultRemoved(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := ComplianceResultRemovedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	// Stale-replay guard: the DELETE only removes a row whose
	// projection_version is at-or-older than this event's
	// SequenceNum. n == 0 means either the row is already gone
	// (replayed Removed against an unrelated state) OR a newer
	// Updated has stamped a higher projection_version on the
	// (device, action) pair. In both cases, skipping the
	// reevaluate cascade is correct: nothing changed, so device
	// compliance doesn't need recomputing (CR catch on PR #179).
	n, err := q.DeleteComplianceResultProjection(ctx, db.DeleteComplianceResultProjectionParams{
		DeviceID:          payload.DeviceID,
		ActionID:          payload.ActionID,
		ProjectionVersion: e.SequenceNum,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	return compliance.EvaluateInTx(ctx, q, payload.DeviceID)
}
