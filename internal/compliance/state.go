// Package compliance owns direct compliance-policy state and read handlers.
package compliance

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/oklog/ulid/v2"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

const maxGracePeriodHours = int32(8760)

var (
	ErrInvalidInput        = errors.New("invalid compliance policy input")
	ErrRuleExists          = errors.New("compliance policy rule already exists")
	ErrRuleNotFound        = errors.New("compliance policy rule not found")
	ErrActionNotCompliance = errors.New("action is not a compliance action")
)

// StateConfig supplies the direct store and clock.
type StateConfig struct {
	Store *store.Store
	Now   func() time.Time
}

// State applies compliance-policy mutations through audited transactions.
type State struct {
	store *store.Store
	now   func() time.Time
}

// NewState constructs direct compliance-policy state.
func NewState(cfg StateConfig) *State {
	if cfg.Store == nil {
		panic("compliance: store is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &State{store: cfg.Store, now: cfg.Now}
}

// CreateParams is the complete stored shape of a new policy.
type CreateParams struct {
	Name        string
	Description string
	CreatedBy   string
}

// Create inserts one compliance policy.
func (s *State) Create(ctx context.Context, op store.AuditOperation, p CreateParams) (store.CompliancePolicyRow, error) {
	if ctx == nil || !validID(p.CreatedBy) || (op.ActorID != "" && op.ActorID != p.CreatedBy) ||
		p.Name == "" || utf8.RuneCountInString(p.Name) > 255 || utf8.RuneCountInString(p.Description) > 1024 {
		return store.CompliancePolicyRow{}, ErrInvalidInput
	}
	id := ulid.Make().String()
	now := s.now().UTC()
	var out store.CompliancePolicyRow
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		row, err := tx.InsertAuthoringCompliancePolicy(ctx, db.InsertAuthoringCompliancePolicyParams{
			ID: id, Name: p.Name, Description: p.Description, CreatedAt: &now, CreatedBy: p.CreatedBy,
		})
		if err != nil {
			return fmt.Errorf("compliance: insert policy: %w", err)
		}
		out = row
		rec.Effect(policyEffect(id, "CREATE", "name", "description"))
		return nil
	})
	if err != nil {
		return store.CompliancePolicyRow{}, err
	}
	return out, nil
}

// Rename replaces a policy name.
func (s *State) Rename(ctx context.Context, op store.AuditOperation, id, name string) (store.CompliancePolicyRow, error) {
	if ctx == nil || !validID(id) || name == "" || utf8.RuneCountInString(name) > 255 {
		return store.CompliancePolicyRow{}, ErrInvalidInput
	}
	var out store.CompliancePolicyRow
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		row, err := tx.RenameAuthoringCompliancePolicy(ctx, db.RenameAuthoringCompliancePolicyParams{Name: name, ID: id})
		if err != nil {
			return err
		}
		out = row
		rec.Effect(policyEffect(id, "UPDATE", "name"))
		return nil
	})
	return out, translateNotFound(err)
}

// UpdateDescription replaces a policy description.
func (s *State) UpdateDescription(ctx context.Context, op store.AuditOperation, id, description string) (store.CompliancePolicyRow, error) {
	if ctx == nil || !validID(id) || utf8.RuneCountInString(description) > 1024 {
		return store.CompliancePolicyRow{}, ErrInvalidInput
	}
	var out store.CompliancePolicyRow
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		row, err := tx.UpdateAuthoringCompliancePolicyDescription(ctx, db.UpdateAuthoringCompliancePolicyDescriptionParams{
			Description: description, ID: id,
		})
		if err != nil {
			return err
		}
		out = row
		rec.Effect(policyEffect(id, "UPDATE", "description"))
		return nil
	})
	return out, translateNotFound(err)
}

// AddRule inserts one compliance Action edge.
func (s *State) AddRule(ctx context.Context, op store.AuditOperation, policyID, actionID string, graceHours int32) error {
	if ctx == nil || !validID(policyID) || !validID(actionID) || graceHours < 0 || graceHours > maxGracePeriodHours {
		return ErrInvalidInput
	}
	if _, err := s.store.GetAuthoringCompliancePolicy(ctx, policyID); err != nil {
		return err
	}
	action, err := s.store.GetManifestAction(ctx, actionID)
	if err != nil {
		return err
	}
	if err := validateComplianceAction(action); err != nil {
		return err
	}
	now := s.now().UTC()
	_, err = s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.AddAuthoringCompliancePolicyRule(ctx, db.AddAuthoringCompliancePolicyRuleParams{
			PolicyID: policyID, ActionID: actionID, ActionName: action.Name,
			GracePeriodHours: graceHours, AddedAt: &now,
		}); err != nil {
			return err
		}
		after := actionID
		effect := policyEffect(policyID, "UPDATE", "rules")
		effect.AfterRef = &after
		rec.Effect(effect)
		rec.RefreshSearch("action", actionID)
		return nil
	})
	if store.IsNotFound(err) {
		if _, readErr := s.store.GetAuthoringCompliancePolicy(ctx, policyID); readErr != nil {
			return readErr
		}
		if _, readErr := s.store.GetManifestAction(ctx, actionID); readErr != nil {
			return readErr
		}
		return ErrRuleExists
	}
	return err
}

// RemoveRule removes one policy Action edge.
func (s *State) RemoveRule(ctx context.Context, op store.AuditOperation, policyID, actionID string) error {
	if ctx == nil || !validID(policyID) || !validID(actionID) {
		return ErrInvalidInput
	}
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.RemoveAuthoringCompliancePolicyRule(ctx, db.RemoveAuthoringCompliancePolicyRuleParams{
			PolicyID: policyID, ActionID: actionID,
		}); err != nil {
			return err
		}
		before := actionID
		effect := policyEffect(policyID, "UPDATE", "rules")
		effect.BeforeRef = &before
		rec.Effect(effect)
		rec.RefreshSearch("action", actionID)
		return nil
	})
	if store.IsNotFound(err) {
		return ErrRuleNotFound
	}
	return err
}

// UpdateRule replaces a rule's grace period.
func (s *State) UpdateRule(ctx context.Context, op store.AuditOperation, policyID, actionID string, graceHours int32) error {
	if ctx == nil || !validID(policyID) || !validID(actionID) || graceHours < 0 || graceHours > maxGracePeriodHours {
		return ErrInvalidInput
	}
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.UpdateAuthoringCompliancePolicyRule(ctx, db.UpdateAuthoringCompliancePolicyRuleParams{
			GracePeriodHours: graceHours, PolicyID: policyID, ActionID: actionID,
		}); err != nil {
			return err
		}
		rec.Effect(policyEffect(policyID, "UPDATE", "rule_grace_period"))
		return nil
	})
	if store.IsNotFound(err) {
		return ErrRuleNotFound
	}
	return err
}

// Delete soft-deletes a policy and removes its rules, evaluations and
// assignments in the same transaction.
func (s *State) Delete(ctx context.Context, op store.AuditOperation, id string) error {
	if ctx == nil || !validID(id) {
		return ErrInvalidInput
	}
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		actionIDs, err := tx.DeleteAuthoringCompliancePolicyRules(ctx, id)
		if err != nil {
			return fmt.Errorf("compliance: delete policy rules: %w", err)
		}
		for _, actionID := range actionIDs {
			rec.RefreshSearch("action", actionID)
		}
		if _, err := tx.DeleteCompliancePolicyEvaluations(ctx, id); err != nil {
			return fmt.Errorf("compliance: delete policy evaluations: %w", err)
		}
		if _, err := tx.DeleteCompliancePolicyAssignments(ctx, id); err != nil {
			return fmt.Errorf("compliance: delete policy assignments: %w", err)
		}
		if _, err := tx.SoftDeleteAuthoringCompliancePolicy(ctx, id); err != nil {
			return err
		}
		rec.Effect(policyEffect(id, "DELETE", "is_deleted", "rules", "assignments"))
		return nil
	})
	return translateNotFound(err)
}

func validateComplianceAction(row store.ActionRow) error {
	if pmv1.ActionType(row.ActionType) != pmv1.ActionType_ACTION_TYPE_SHELL {
		return ErrActionNotCompliance
	}
	action := &pmv1.ManagedAction{Type: pmv1.ActionType(row.ActionType)}
	if err := actionparams.PopulateManagedAction(action, action.Type, row.Params); err != nil {
		return fmt.Errorf("compliance: decode action params: %w", err)
	}
	if action.GetShell() == nil || !action.GetShell().IsCompliance {
		return ErrActionNotCompliance
	}
	return nil
}

func validID(id string) bool {
	_, err := ulid.ParseStrict(id)
	return err == nil
}

func translateNotFound(err error) error {
	if store.IsNotFound(err) {
		return store.ErrNotFound
	}
	return err
}

func policyEffect(id, action string, fields ...string) store.AuditEffect {
	return store.AuditEffect{
		ResourceType: "compliance_policy", ResourceID: id, Action: action,
		Outcome: store.EffectApplied, ChangedFields: fields,
	}
}
