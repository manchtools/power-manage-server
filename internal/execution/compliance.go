package execution

import (
	"context"
	"fmt"
	"time"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/compliance"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// complianceFinding is one terminal agent result seen as compliance evidence.
type complianceFinding struct {
	deviceID string
	// actionID is the catalogue action the occurrence carried. An ad-hoc
	// dispatch has none, and a finding with no authored action has nothing a
	// policy could reference.
	actionID *string
	// status is the stored execution status, not the agent's compliant flag.
	// Compliance checks are detection-only, so only a detection script that
	// ran and passed is evidence of compliance; everything else fails closed.
	status          string
	compliant       bool
	detectionOutput []byte
	checkedAt       time.Time
}

// recordComplianceFinding writes the compliance state a detection-only action
// just produced. It runs inside the execution result's own transaction and
// records its own effect, so the compliance surface and the execution evidence
// it is derived from commit together or not at all.
func recordComplianceFinding(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder, finding complianceFinding) error {
	if finding.actionID == nil {
		return nil
	}
	actionID := *finding.actionID
	action, err := tx.GetManifestAction(ctx, actionID)
	if err != nil {
		if store.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("read compliance action: %w", err)
	}
	if !compliance.IsComplianceAction(action) {
		return nil
	}

	compliant := finding.compliant && finding.status == "success"
	checkedAt := finding.checkedAt
	n, err := tx.UpsertDeviceComplianceResult(ctx, db.UpsertDeviceComplianceResultParams{
		DeviceID: finding.deviceID, ActionID: actionID, Compliant: compliant,
		DetectionOutput: finding.detectionOutput, CheckedAt: checkedAt,
	})
	if err != nil {
		return fmt.Errorf("record compliance result: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("record compliance result: action %s is not live", actionID)
	}

	targets, err := tx.ListComplianceRuleEvaluationTargets(ctx, db.ListComplianceRuleEvaluationTargetsParams{
		DeviceID: finding.deviceID, ActionID: actionID,
	})
	if err != nil {
		return fmt.Errorf("list compliance rules: %w", err)
	}
	for _, target := range targets {
		firstFailedAt := target.FirstFailedAt
		switch {
		case compliant:
			firstFailedAt = nil
		case firstFailedAt == nil:
			firstFailedAt = &checkedAt
		}
		if err := tx.UpsertCompliancePolicyEvaluation(ctx, db.UpsertCompliancePolicyEvaluationParams{
			DeviceID: finding.deviceID, PolicyID: target.PolicyID, ActionID: actionID,
			Compliant: compliant, FirstFailedAt: firstFailedAt,
			Status:    ruleStatus(compliant, firstFailedAt, target.GracePeriodHours, checkedAt),
			CheckedAt: &checkedAt,
		}); err != nil {
			return fmt.Errorf("record compliance evaluation: %w", err)
		}
	}

	if _, err := tx.RefreshDeviceComplianceStatus(ctx, db.RefreshDeviceComplianceStatusParams{
		DeviceID: finding.deviceID, CheckedAt: &checkedAt,
	}); err != nil {
		return fmt.Errorf("refresh device compliance status: %w", err)
	}

	// A device effect is what the audit log owes a state change here, and it is
	// also what refreshes the device search document in this transaction — the
	// fleet list reads compliance_status from there.
	rec.Effect(store.AuditEffect{
		ResourceType: "device", ResourceID: finding.deviceID, Action: "COMPLIANCE",
		Outcome:  store.EffectApplied,
		AfterRef: &actionID, AfterFlag: &compliant,
		ChangedFields: []string{
			"compliance_status", "compliance_checked_at",
			"compliance_total", "compliance_passing",
		},
	})
	return nil
}

// ruleStatus places one rule on the lifecycle: a failing check enters its
// grace period from the first failure and stays there until the period is
// spent, measured against the check that produced the finding.
func ruleStatus(compliant bool, firstFailedAt *time.Time, graceHours int32, checkedAt time.Time) int32 {
	if compliant {
		return int32(pmv1.ComplianceStatus_COMPLIANCE_STATUS_COMPLIANT)
	}
	if firstFailedAt != nil && graceHours > 0 &&
		checkedAt.Before(firstFailedAt.Add(time.Duration(graceHours)*time.Hour)) {
		return int32(pmv1.ComplianceStatus_COMPLIANCE_STATUS_IN_GRACE_PERIOD)
	}
	return int32(pmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT)
}
