// Package compliance implements the in-process replacement for the
// PL/pgSQL evaluate_device_compliance_policies / recalculate_device_compliance
// / reevaluate_compliance_policy_devices functions from migration 003.
// Same pattern as internal/dyngroupeval — listeners call into an
// Evaluator that consumes repo methods instead of dispatching to
// SELECT plpgsql_function($1) shims.
//
// Shape vs. internal/dyngroupeval (audit N034). compliance runs from
// inside projector listener WithTx blocks (after device-inventory /
// policy-rule events have applied), so its public API is *InTx-suffixed
// and takes the caller's *store.Queries — the surrounding transaction
// must commit atomically. dyngroupeval, by contrast, is invoked as a
// top-level operation, so its API takes a *store.Store and opens its
// own transactions. The asymmetry is intentional, not a naming gap.
//
// Part of Wave D of the storage-abstraction roadmap (tracker
// manchtools/power-manage-server#242).
package compliance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// Compliance status codes mirror the PL/pgSQL integer values, which
// also match the proto enum on the wire. Keep these constants in sync
// with sdk/proto/pm/v1/compliance.proto.
const (
	StatusUnknown       int32 = 0
	StatusCompliant     int32 = 1
	StatusNonCompliant  int32 = 2
	StatusInGracePeriod int32 = 3
)

// Evaluator is the in-process per-device compliance recomputer.
// Listener callers wrap the per-event flow in a transaction and pass
// the bound *store.Queries to EvaluateInTx / ReevaluatePolicyInTx so
// the recomputation commits atomically with the listener's other
// writes.
type Evaluator struct {
	logger *slog.Logger
	now    func() time.Time
}

// New returns an Evaluator. The now closure stays injectable so unit
// tests can pin grace-period boundaries without sleeping the test
// goroutine.
func New(lg *slog.Logger) *Evaluator {
	if lg == nil {
		lg = slog.Default()
	}
	return &Evaluator{logger: lg, now: time.Now}
}

// SetClock swaps the time source. Test-only; production callers leave
// the default time.Now.
func (e *Evaluator) SetClock(now func() time.Time) { e.now = now }

// defaultEvaluator is the package-level instance the projector
// listeners use through the EvaluateInTx / ReevaluatePolicyInTx
// package-level shims. Tests that need clock injection construct
// their own *Evaluator and call its methods directly.
var defaultEvaluator = New(nil)

// EvaluateInTx is the package-level convenience wrapper around
// defaultEvaluator.EvaluateInTx. Projector listeners call it inside
// their WithTx blocks so the compliance recompute commits atomically
// with the listener's own writes.
func EvaluateInTx(ctx context.Context, q *store.Queries, deviceID string) error {
	return defaultEvaluator.EvaluateInTx(ctx, q, deviceID)
}

// ReevaluatePolicyInTx is the package-level convenience wrapper
// around defaultEvaluator.ReevaluatePolicyInTx.
func ReevaluatePolicyInTx(ctx context.Context, q *store.Queries, policyID string) error {
	return defaultEvaluator.ReevaluatePolicyInTx(ctx, q, policyID)
}

// EvaluateInTx re-computes compliance for one device against the
// supplied tx-bound *store.Queries. Same semantic as the PL/pgSQL
// evaluate_device_compliance_policies(deviceID):
//
//   - No policies assigned → recalculate-only fallback (count results,
//     roll up to device status).
//   - Otherwise iterate every rule, look up the latest result, write
//     a per-rule evaluation row, and finalise the device's denormalized
//     compliance quadruple.
//
// Grace-period handling: a freshly-failing rule records the current
// time as first_failed_at; subsequent failing evaluations preserve
// that timestamp. A rule older than grace_period_hours past
// first_failed_at graduates from IN_GRACE_PERIOD to NON_COMPLIANT.
func (e *Evaluator) EvaluateInTx(ctx context.Context, q *store.Queries, deviceID string) error {
	rules, err := q.ListComplianceRulesForDevice(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("compliance: list rules for device %s: %w", deviceID, err)
	}
	if len(rules) == 0 {
		return e.recalculateOnly(ctx, q, deviceID)
	}

	now := e.now().UTC()
	var (
		anyNonCompliant bool
		anyInGrace      bool
		allCompliant    = true
		total           = int32(len(rules))
		passing         int32
	)

	for _, rule := range rules {
		ruleStatus, err := e.evalOne(ctx, q, deviceID, rule, now)
		if err != nil {
			return err
		}
		switch ruleStatus {
		case StatusCompliant:
			passing++
		case StatusInGracePeriod:
			anyInGrace = true
			allCompliant = false
		case StatusNonCompliant:
			anyNonCompliant = true
			allCompliant = false
		case StatusUnknown:
			allCompliant = false
		}
	}

	overall := StatusUnknown
	switch {
	case anyNonCompliant:
		overall = StatusNonCompliant
	case anyInGrace:
		overall = StatusInGracePeriod
	case allCompliant && total > 0:
		overall = StatusCompliant
	}

	return q.UpdateDeviceComplianceSummary(ctx, db.UpdateDeviceComplianceSummaryParams{
		ID:                  deviceID,
		ComplianceStatus:    overall,
		ComplianceCheckedAt: &now,
		ComplianceTotal:     total,
		CompliancePassing:   passing,
	})
}

// evalOne resolves the per-rule status the same way the PL/pgSQL
// evaluator did: no result yet → UNKNOWN, compliant → COMPLIANT,
// failing within grace → IN_GRACE_PERIOD, failing past grace → NON_COMPLIANT.
func (e *Evaluator) evalOne(ctx context.Context, q *store.Queries, deviceID string, rule db.ListComplianceRulesForDeviceRow, now time.Time) (int32, error) {
	result, err := q.GetLatestComplianceResultForAction(ctx, db.GetLatestComplianceResultForActionParams{
		DeviceID: deviceID,
		ActionID: rule.ActionID,
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		// No result yet — UNKNOWN. Persist a placeholder row so the
		// device-list UI can surface "waiting for first check" per
		// rule.
		if err := q.UpsertComplianceEvaluation(ctx, db.UpsertComplianceEvaluationParams{
			DeviceID:      deviceID,
			PolicyID:      rule.PolicyID,
			ActionID:      rule.ActionID,
			Compliant:     false,
			FirstFailedAt: nil,
			Status:        StatusUnknown,
			CheckedAt:     nil,
		}); err != nil {
			return 0, fmt.Errorf("compliance: write unknown eval for %s/%s/%s: %w", deviceID, rule.PolicyID, rule.ActionID, err)
		}
		return StatusUnknown, nil

	case err != nil:
		return 0, fmt.Errorf("compliance: load result for %s/%s: %w", deviceID, rule.ActionID, err)
	}

	if result.Compliant {
		if err := q.UpsertComplianceEvaluation(ctx, db.UpsertComplianceEvaluationParams{
			DeviceID:      deviceID,
			PolicyID:      rule.PolicyID,
			ActionID:      rule.ActionID,
			Compliant:     true,
			FirstFailedAt: nil,
			Status:        StatusCompliant,
			CheckedAt:     &result.CheckedAt,
		}); err != nil {
			return 0, fmt.Errorf("compliance: write compliant eval for %s/%s/%s: %w", deviceID, rule.PolicyID, rule.ActionID, err)
		}
		return StatusCompliant, nil
	}

	// Non-compliant: load existing first_failed_at (preserve across
	// repeated failures), or seed with `now` on first transition.
	existingFailedAt, err := q.GetComplianceEvaluationFirstFailedAt(ctx, db.GetComplianceEvaluationFirstFailedAtParams{
		DeviceID: deviceID,
		PolicyID: rule.PolicyID,
		ActionID: rule.ActionID,
	})
	firstFailedAt := now
	switch {
	case errors.Is(err, store.ErrNotFound):
		// First-ever non-compliant state for this rule.
	case err != nil:
		return 0, fmt.Errorf("compliance: read first_failed_at for %s/%s/%s: %w", deviceID, rule.PolicyID, rule.ActionID, err)
	case existingFailedAt != nil:
		firstFailedAt = *existingFailedAt
	}

	status := StatusNonCompliant
	if rule.GracePeriodHours > 0 {
		graceUntil := firstFailedAt.Add(time.Duration(rule.GracePeriodHours) * time.Hour)
		if now.Before(graceUntil) {
			status = StatusInGracePeriod
		}
	}

	if err := q.UpsertComplianceEvaluation(ctx, db.UpsertComplianceEvaluationParams{
		DeviceID:      deviceID,
		PolicyID:      rule.PolicyID,
		ActionID:      rule.ActionID,
		Compliant:     false,
		FirstFailedAt: &firstFailedAt,
		Status:        status,
		CheckedAt:     &result.CheckedAt,
	}); err != nil {
		return 0, fmt.Errorf("compliance: write non-compliant eval for %s/%s/%s: %w", deviceID, rule.PolicyID, rule.ActionID, err)
	}
	return status, nil
}

// recalculateOnly is the no-policies fallback that mirrors the PL/pgSQL
// recalculate_device_compliance function: count compliance_results and
// roll up to the device's denormalized status.
func (e *Evaluator) recalculateOnly(ctx context.Context, q *store.Queries, deviceID string) error {
	counts, err := q.ComplianceResultCounts(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("compliance: count results for %s: %w", deviceID, err)
	}

	status := StatusUnknown
	switch {
	case counts.Total == 0:
		status = StatusUnknown
	case counts.Passing == counts.Total:
		status = StatusCompliant
	default:
		status = StatusNonCompliant
	}

	now := e.now().UTC()
	return q.UpdateDeviceComplianceSummary(ctx, db.UpdateDeviceComplianceSummaryParams{
		ID:                  deviceID,
		ComplianceStatus:    status,
		ComplianceCheckedAt: &now,
		ComplianceTotal:     counts.Total,
		CompliancePassing:   counts.Passing,
	})
}

// ReevaluatePolicyInTx fans out across every device touched by a policy
// (direct + via device groups) and re-runs EvaluateInTx on each within
// the supplied transaction. Per-device errors are logged + skipped —
// the cascade should be best-effort so a single broken device doesn't
// block the rest of the recompute.
func (e *Evaluator) ReevaluatePolicyInTx(ctx context.Context, q *store.Queries, policyID string) error {
	deviceIDs, err := q.ListDevicesForCompliancePolicy(ctx, policyID)
	if err != nil {
		return fmt.Errorf("compliance: list devices for policy %s: %w", policyID, err)
	}
	for _, id := range deviceIDs {
		if err := e.EvaluateInTx(ctx, q, id); err != nil {
			e.logger.Warn("compliance: failed to re-evaluate device for policy; skipping",
				"policy_id", policyID, "device_id", id, "error", err)
		}
	}
	return nil
}
