package authoring

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/oklog/ulid/v2"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

var (
	ErrAlreadyMember  = errors.New("action is already a member of the set")
	ErrMemberNotFound = errors.New("action set member not found")
)

// CreateActionSetParams is the complete stored shape of a new ActionSet.
type CreateActionSetParams struct {
	Name        string
	Description string
	CreatedBy   string
	Schedule    *pmv1.ActionSchedule
	OnFailure   pmv1.OnFailure
}


// CreateActionSet inserts one set with an independent schedule and failure
// policy.
func (s *Service) CreateActionSet(ctx context.Context, op store.AuditOperation, p CreateActionSetParams) (store.ActionSetRow, error) {
	if ctx == nil || !validID(p.CreatedBy) || (op.ActorID != "" && op.ActorID != p.CreatedBy) ||
		p.Name == "" || utf8.RuneCountInString(p.Name) > 255 || utf8.RuneCountInString(p.Description) > 1024 {
		return store.ActionSetRow{}, ErrInvalidInput
	}
	schedule, err := actionSetSchedule(p.Schedule)
	if err != nil || !validFailurePolicy(p.OnFailure) {
		return store.ActionSetRow{}, ErrInvalidInput
	}
	id := ulid.Make().String()
	now := s.now().UTC()
	var out store.ActionSetRow
	_, err = s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		row, err := tx.InsertAuthoringActionSet(ctx, db.InsertAuthoringActionSetParams{
			ID: id, Name: p.Name, Description: p.Description, Schedule: schedule,
			OnFailure: int32(p.OnFailure), CreatedAt: &now, CreatedBy: p.CreatedBy,
		})
		if err != nil {
			return fmt.Errorf("authoring: insert action set: %w", err)
		}
		out = row
		rec.Effect(actionSetEffect(id, "CREATE", "name", "description", "schedule", "on_failure"))
		return nil
	})
	if err != nil {
		return store.ActionSetRow{}, err
	}
	return out, nil
}

// RenameActionSet replaces a set name.
func (s *Service) RenameActionSet(ctx context.Context, op store.AuditOperation, id, name string) (store.ActionSetRow, error) {
	if ctx == nil || !validID(id) || name == "" || utf8.RuneCountInString(name) > 255 {
		return store.ActionSetRow{}, ErrInvalidInput
	}
	now := s.now().UTC()
	var out store.ActionSetRow
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		row, err := tx.RenameAuthoringActionSet(ctx, db.RenameAuthoringActionSetParams{ID: id, Name: name, UpdatedAt: &now})
		if err != nil {
			return err
		}
		out = row
		rec.Effect(actionSetEffect(id, "UPDATE", "name"))
		return nil
	})
	return out, translateNotFound(err)
}

// UpdateActionSetDescription replaces a set description.
func (s *Service) UpdateActionSetDescription(ctx context.Context, op store.AuditOperation, id, description string) (store.ActionSetRow, error) {
	if ctx == nil || !validID(id) || utf8.RuneCountInString(description) > 1024 {
		return store.ActionSetRow{}, ErrInvalidInput
	}
	now := s.now().UTC()
	var out store.ActionSetRow
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		row, err := tx.UpdateAuthoringActionSetDescription(ctx, db.UpdateAuthoringActionSetDescriptionParams{
			ID: id, Description: description, UpdatedAt: &now,
		})
		if err != nil {
			return err
		}
		out = row
		rec.Effect(actionSetEffect(id, "UPDATE", "description"))
		return nil
	})
	return out, translateNotFound(err)
}

// UpdateActionSetPolicy replaces the schedule and failure policy together.
func (s *Service) UpdateActionSetPolicy(ctx context.Context, op store.AuditOperation, id string, schedule *pmv1.ActionSchedule, policy pmv1.OnFailure) (store.ActionSetRow, error) {
	if ctx == nil || !validID(id) || !validFailurePolicy(policy) {
		return store.ActionSetRow{}, ErrInvalidInput
	}
	raw, err := actionSetSchedule(schedule)
	if err != nil {
		return store.ActionSetRow{}, ErrInvalidInput
	}
	now := s.now().UTC()
	var out store.ActionSetRow
	_, err = s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		row, err := tx.UpdateAuthoringActionSetPolicy(ctx, db.UpdateAuthoringActionSetPolicyParams{
			ID: id, Schedule: raw, OnFailure: int32(policy), UpdatedAt: &now,
		})
		if err != nil {
			return err
		}
		out = row
		rec.Effect(actionSetEffect(id, "UPDATE", "schedule", "on_failure"))
		return nil
	})
	return out, translateNotFound(err)
}

// AddActionToSet inserts one authored occurrence edge. System-managed actions
// never become reachable through an operator-controlled set.
func (s *Service) AddActionToSet(ctx context.Context, op store.AuditOperation, setID, actionID string, sortOrder int32) error {
	if ctx == nil || !validID(setID) || !validID(actionID) || sortOrder < 0 {
		return ErrInvalidInput
	}
	if _, err := s.store.GetManifestActionSet(ctx, setID); err != nil {
		return err
	}
	action, err := s.store.GetManifestAction(ctx, actionID)
	if err != nil {
		return err
	}
	if action.IsSystem {
		return ErrSystemAction
	}
	now := s.now().UTC()
	_, err = s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.AddAuthoringActionSetMember(ctx, db.AddAuthoringActionSetMemberParams{
			SetID: setID, ActionID: actionID, SortOrder: sortOrder, AddedAt: &now,
		}); err != nil {
			return err
		}
		after := actionID
		effect := actionSetEffect(setID, "UPDATE", "memberships")
		effect.AfterRef = &after
		rec.Effect(effect)
		return nil
	})
	if store.IsNotFound(err) {
		if _, readErr := s.store.GetManifestActionSet(ctx, setID); readErr != nil {
			return readErr
		}
		if _, readErr := s.store.GetManifestAction(ctx, actionID); readErr != nil {
			return readErr
		}
		return ErrAlreadyMember
	}
	return err
}

// RemoveActionFromSet removes one authored occurrence edge.
func (s *Service) RemoveActionFromSet(ctx context.Context, op store.AuditOperation, setID, actionID string) error {
	if ctx == nil || !validID(setID) || !validID(actionID) {
		return ErrInvalidInput
	}
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.RemoveAuthoringActionSetMember(ctx, db.RemoveAuthoringActionSetMemberParams{
			SetID: setID, ActionID: actionID,
		}); err != nil {
			return err
		}
		before := actionID
		effect := actionSetEffect(setID, "UPDATE", "memberships")
		effect.BeforeRef = &before
		rec.Effect(effect)
		return nil
	})
	if store.IsNotFound(err) {
		return ErrMemberNotFound
	}
	return err
}

// ReorderActionInSet changes one edge's authored sort position.
func (s *Service) ReorderActionInSet(ctx context.Context, op store.AuditOperation, setID, actionID string, sortOrder int32) error {
	if ctx == nil || !validID(setID) || !validID(actionID) || sortOrder < 0 {
		return ErrInvalidInput
	}
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.ReorderAuthoringActionSetMember(ctx, db.ReorderAuthoringActionSetMemberParams{
			SetID: setID, ActionID: actionID, SortOrder: sortOrder,
		}); err != nil {
			return err
		}
		rec.Effect(actionSetEffect(setID, "UPDATE", "member_order"))
		return nil
	})
	if store.IsNotFound(err) {
		return ErrMemberNotFound
	}
	return err
}

// DeleteActionSet soft-deletes the set and removes all composition edges in
// the same transaction.
func (s *Service) DeleteActionSet(ctx context.Context, op store.AuditOperation, id string) error {
	if ctx == nil || !validID(id) {
		return ErrInvalidInput
	}
	now := s.now().UTC()
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.DeleteAuthoringActionSetMembers(ctx, id); err != nil {
			return fmt.Errorf("authoring: delete action set members: %w", err)
		}
		if _, err := tx.DeleteDefinitionMembershipsForActionSet(ctx, id); err != nil {
			return fmt.Errorf("authoring: delete definition memberships: %w", err)
		}
		if _, err := tx.SoftDeleteAuthoringActionSet(ctx, db.SoftDeleteAuthoringActionSetParams{ID: id, UpdatedAt: &now}); err != nil {
			return err
		}
		rec.Effect(actionSetEffect(id, "DELETE", "is_deleted", "memberships"))
		return nil
	})
	return translateNotFound(err)
}


func actionSetSchedule(schedule *pmv1.ActionSchedule) ([]byte, error) {
	if schedule == nil {
		return nil, ErrInvalidInput
	}
	if detail, ok := sdkvalidate.Struct(actionValidator, schedule); !ok {
		return nil, fmt.Errorf("%w: %s", ErrInvalidInput, detail)
	}
	raw, err := actionparams.ScheduleToRaw(schedule)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return actionparams.ScheduleToRaw(&pmv1.ActionSchedule{IntervalHours: 8})
	}
	return raw, nil
}

func validFailurePolicy(policy pmv1.OnFailure) bool {
	return policy == pmv1.OnFailure_ON_FAILURE_CONTINUE || policy == pmv1.OnFailure_ON_FAILURE_STOP
}

func actionSetEffect(id, action string, fields ...string) store.AuditEffect {
	return store.AuditEffect{
		ResourceType: "action_set", ResourceID: id, Action: action,
		Outcome: store.EffectApplied, ChangedFields: fields,
	}
}

func translateNotFound(err error) error {
	if store.IsNotFound(err) {
		return store.ErrNotFound
	}
	return err
}
