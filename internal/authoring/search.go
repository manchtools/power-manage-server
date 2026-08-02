package authoring

import (
	"context"

	"github.com/manchtools/power-manage/server/internal/store"
)

// refreshActionDependents records the fixed cross-row documents that embed an
// action's current name or description. Call it before deleting composition
// edges so the former parents are not lost.
func refreshActionDependents(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder, actionID string, executions bool) error {
	setIDs, err := tx.ListContainingActionSetIDs(ctx, actionID)
	if err != nil {
		return err
	}
	for _, setID := range setIDs {
		rec.RefreshSearch("action_set", setID)
		if err := refreshActionSetDependents(ctx, tx, rec, setID); err != nil {
			return err
		}
	}
	policyIDs, err := tx.ListContainingCompliancePolicyIDs(ctx, actionID)
	if err != nil {
		return err
	}
	for _, policyID := range policyIDs {
		rec.RefreshSearch("compliance_policy", policyID)
	}
	if !executions {
		return nil
	}
	executionIDs, err := tx.ListExecutionIDsForAction(ctx, &actionID)
	if err != nil {
		return err
	}
	for _, executionID := range executionIDs {
		rec.RefreshSearch("execution", executionID)
	}
	return nil
}

func refreshActionSetDependents(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder, setID string) error {
	definitionIDs, err := tx.ListContainingDefinitionIDs(ctx, setID)
	if err != nil {
		return err
	}
	for _, definitionID := range definitionIDs {
		rec.RefreshSearch("definition", definitionID)
	}
	return nil
}
