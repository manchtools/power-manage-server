package authoring

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/oklog/ulid/v2"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

var (
	ErrDefinitionAlreadyMember = errors.New("action set is already a member of the definition")
	ErrDefinitionMemberMissing = errors.New("definition member not found")
)

// CreateDefinitionParams is the complete stored shape of a new Definition.
type CreateDefinitionParams struct {
	Name        string
	Description string
	CreatedBy   string
	Schedule    *pmv1.ActionSchedule
}


// CreateDefinition inserts one independently scheduled authored definition.
func (s *Service) CreateDefinition(ctx context.Context, op store.AuditOperation, p CreateDefinitionParams) (store.DefinitionRow, error) {
	if ctx == nil || !validID(p.CreatedBy) || (op.ActorID != "" && op.ActorID != p.CreatedBy) ||
		p.Name == "" || utf8.RuneCountInString(p.Name) > 255 || utf8.RuneCountInString(p.Description) > 1024 {
		return store.DefinitionRow{}, ErrInvalidInput
	}
	schedule, err := actionSetSchedule(p.Schedule)
	if err != nil {
		return store.DefinitionRow{}, ErrInvalidInput
	}
	id := ulid.Make().String()
	now := s.now().UTC()
	var out store.DefinitionRow
	_, err = s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		row, err := tx.InsertAuthoringDefinition(ctx, db.InsertAuthoringDefinitionParams{
			ID: id, Name: p.Name, Description: p.Description, Schedule: schedule,
			CreatedAt: &now, CreatedBy: p.CreatedBy,
		})
		if err != nil {
			return fmt.Errorf("authoring: insert definition: %w", err)
		}
		out = row
		rec.Effect(definitionEffect(id, "CREATE", "name", "description", "schedule"))
		return nil
	})
	if err != nil {
		return store.DefinitionRow{}, err
	}
	return out, nil
}

// RenameDefinition replaces a definition name.
func (s *Service) RenameDefinition(ctx context.Context, op store.AuditOperation, id, name string) (store.DefinitionRow, error) {
	if ctx == nil || !validID(id) || name == "" || utf8.RuneCountInString(name) > 255 {
		return store.DefinitionRow{}, ErrInvalidInput
	}
	now := s.now().UTC()
	var out store.DefinitionRow
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		row, err := tx.RenameAuthoringDefinition(ctx, db.RenameAuthoringDefinitionParams{ID: id, Name: name, UpdatedAt: &now})
		if err != nil {
			return err
		}
		out = row
		rec.Effect(definitionEffect(id, "UPDATE", "name"))
		return nil
	})
	return out, translateNotFound(err)
}

// UpdateDefinitionDescription replaces a definition description.
func (s *Service) UpdateDefinitionDescription(ctx context.Context, op store.AuditOperation, id, description string) (store.DefinitionRow, error) {
	if ctx == nil || !validID(id) || utf8.RuneCountInString(description) > 1024 {
		return store.DefinitionRow{}, ErrInvalidInput
	}
	now := s.now().UTC()
	var out store.DefinitionRow
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		row, err := tx.UpdateAuthoringDefinitionDescription(ctx, db.UpdateAuthoringDefinitionDescriptionParams{
			ID: id, Description: description, UpdatedAt: &now,
		})
		if err != nil {
			return err
		}
		out = row
		rec.Effect(definitionEffect(id, "UPDATE", "description"))
		return nil
	})
	return out, translateNotFound(err)
}

// UpdateDefinitionSchedule replaces only the schedule used during Definition
// manifest compilation. It does not mutate any member ActionSet.
func (s *Service) UpdateDefinitionSchedule(ctx context.Context, op store.AuditOperation, id string, schedule *pmv1.ActionSchedule) (store.DefinitionRow, error) {
	if ctx == nil || !validID(id) {
		return store.DefinitionRow{}, ErrInvalidInput
	}
	raw, err := actionSetSchedule(schedule)
	if err != nil {
		return store.DefinitionRow{}, ErrInvalidInput
	}
	now := s.now().UTC()
	var out store.DefinitionRow
	_, err = s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		row, err := tx.UpdateAuthoringDefinitionSchedule(ctx, db.UpdateAuthoringDefinitionScheduleParams{
			ID: id, Schedule: raw, UpdatedAt: &now,
		})
		if err != nil {
			return err
		}
		out = row
		rec.Effect(definitionEffect(id, "UPDATE", "schedule"))
		return nil
	})
	return out, translateNotFound(err)
}

// AddActionSetToDefinition inserts one authored ActionSet edge.
func (s *Service) AddActionSetToDefinition(ctx context.Context, op store.AuditOperation, definitionID, actionSetID string, sortOrder int32) error {
	if ctx == nil || !validID(definitionID) || !validID(actionSetID) || sortOrder < 0 {
		return ErrInvalidInput
	}
	if _, err := s.store.GetManifestDefinition(ctx, definitionID); err != nil {
		return err
	}
	if _, err := s.store.GetManifestActionSet(ctx, actionSetID); err != nil {
		return err
	}
	now := s.now().UTC()
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.AddAuthoringDefinitionMember(ctx, db.AddAuthoringDefinitionMemberParams{
			DefinitionID: definitionID, ActionSetID: actionSetID, SortOrder: sortOrder, AddedAt: &now,
		}); err != nil {
			return err
		}
		after := actionSetID
		effect := definitionEffect(definitionID, "UPDATE", "memberships")
		effect.AfterRef = &after
		rec.Effect(effect)
		return nil
	})
	if store.IsNotFound(err) {
		if _, readErr := s.store.GetManifestDefinition(ctx, definitionID); readErr != nil {
			return readErr
		}
		if _, readErr := s.store.GetManifestActionSet(ctx, actionSetID); readErr != nil {
			return readErr
		}
		return ErrDefinitionAlreadyMember
	}
	return err
}

// RemoveActionSetFromDefinition removes one authored ActionSet edge.
func (s *Service) RemoveActionSetFromDefinition(ctx context.Context, op store.AuditOperation, definitionID, actionSetID string) error {
	if ctx == nil || !validID(definitionID) || !validID(actionSetID) {
		return ErrInvalidInput
	}
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.RemoveAuthoringDefinitionMember(ctx, db.RemoveAuthoringDefinitionMemberParams{
			DefinitionID: definitionID, ActionSetID: actionSetID,
		}); err != nil {
			return err
		}
		before := actionSetID
		effect := definitionEffect(definitionID, "UPDATE", "memberships")
		effect.BeforeRef = &before
		rec.Effect(effect)
		return nil
	})
	if store.IsNotFound(err) {
		return ErrDefinitionMemberMissing
	}
	return err
}

// ReorderActionSetInDefinition changes one edge's authored sort position.
func (s *Service) ReorderActionSetInDefinition(ctx context.Context, op store.AuditOperation, definitionID, actionSetID string, sortOrder int32) error {
	if ctx == nil || !validID(definitionID) || !validID(actionSetID) || sortOrder < 0 {
		return ErrInvalidInput
	}
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.ReorderAuthoringDefinitionMember(ctx, db.ReorderAuthoringDefinitionMemberParams{
			DefinitionID: definitionID, ActionSetID: actionSetID, SortOrder: sortOrder,
		}); err != nil {
			return err
		}
		rec.Effect(definitionEffect(definitionID, "UPDATE", "member_order"))
		return nil
	})
	if store.IsNotFound(err) {
		return ErrDefinitionMemberMissing
	}
	return err
}

// DeleteDefinition soft-deletes a definition and removes its composition
// edges in the same audited transaction.
func (s *Service) DeleteDefinition(ctx context.Context, op store.AuditOperation, id string) error {
	if ctx == nil || !validID(id) {
		return ErrInvalidInput
	}
	now := s.now().UTC()
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.DeleteAuthoringDefinitionMembers(ctx, id); err != nil {
			return fmt.Errorf("authoring: delete definition members: %w", err)
		}
		if _, err := tx.SoftDeleteAuthoringDefinition(ctx, db.SoftDeleteAuthoringDefinitionParams{ID: id, UpdatedAt: &now}); err != nil {
			return err
		}
		rec.Effect(definitionEffect(id, "DELETE", "is_deleted", "memberships"))
		return nil
	})
	return translateNotFound(err)
}


func definitionEffect(id, action string, fields ...string) store.AuditEffect {
	return store.AuditEffect{
		ResourceType: "definition", ResourceID: id, Action: action,
		Outcome: store.EffectApplied, ChangedFields: fields,
	}
}
