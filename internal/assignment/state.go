// Package assignment owns direct source-to-target assignment state.
package assignment

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/oklog/ulid/v2"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

var (
	ErrInvalidInput          = errors.New("invalid assignment input")
	ErrSourceNotFound        = errors.New("assignment source not found")
	ErrTargetNotFound        = errors.New("assignment target not found")
	ErrNotFound              = errors.New("assignment not found")
	ErrSystemAction          = errors.New("system action cannot be assigned directly")
	ErrNoAvailableAssignment = errors.New("no available assignment")
	errAlreadyActive         = errors.New("assignment already active")
)

// Config supplies the direct store and clock.
type Config struct {
	Store  *store.Store
	Logger *slog.Logger
	Now    func() time.Time
}

// State applies assignment mutations through audited transactions.
type State struct {
	store *store.Store
	now   func() time.Time
}

// NewState constructs direct assignment state.
func NewState(cfg Config) *State {
	if cfg.Store == nil {
		panic("assignment: store is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &State{store: cfg.Store, now: cfg.Now}
}

// CreateParams is one complete assignment edge.
type CreateParams struct {
	SourceType pmv1.AssignmentSourceType
	SourceID   string
	TargetType pmv1.AssignmentTargetType
	TargetID   string
	Mode       pmv1.AssignmentMode
	CreatedBy  string
}

// Create inserts or reactivates one edge. Repeating an active tuple is
// idempotent and returns its existing row without manufacturing a mutation.
func (s *State) Create(ctx context.Context, op store.AuditOperation, p CreateParams) (store.AssignmentView, error) {
	sourceType, sourceOK := sourceTypeName(p.SourceType)
	targetType, targetOK := targetTypeName(p.TargetType)
	if ctx == nil || !sourceOK || !targetOK || !validID(p.SourceID) || !validID(p.TargetID) ||
		!validID(p.CreatedBy) || (op.ActorID != "" && op.ActorID != p.CreatedBy) || !validMode(p.Mode) {
		return store.AssignmentView{}, ErrInvalidInput
	}
	if err := s.validateReferences(ctx, s.store, p); err != nil {
		return store.AssignmentView{}, err
	}
	if existing, err := s.store.FindAssignment(ctx, sourceType, p.SourceID, targetType, p.TargetID); err == nil {
		return existing, nil
	} else if !store.IsNotFound(err) {
		return store.AssignmentView{}, err
	}

	id, now := ulid.Make().String(), s.now().UTC()
	var stored db.Assignment
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if err := s.validateReferences(ctx, tx, p); err != nil {
			return err
		}
		row, err := tx.UpsertAssignment(ctx, db.UpsertAssignmentParams{
			ID: id, SourceType: sourceType, SourceID: p.SourceID,
			TargetType: targetType, TargetID: p.TargetID, Mode: int32(p.Mode),
			CreatedAt: &now, CreatedBy: p.CreatedBy,
		})
		if store.IsNotFound(err) {
			return errAlreadyActive
		}
		if err != nil {
			return fmt.Errorf("assignment: upsert: %w", err)
		}
		stored = row
		after := p.TargetID
		rec.Effect(store.AuditEffect{
			ResourceType: "assignment", ResourceID: row.ID, Action: "CREATE",
			Outcome: store.EffectApplied, ChangedFields: []string{"source", "target", "mode", "is_deleted"},
			AfterRef: &after,
		})
		return nil
	})
	if errors.Is(err, errAlreadyActive) {
		return s.store.FindAssignment(ctx, sourceType, p.SourceID, targetType, p.TargetID)
	}
	if err != nil {
		return store.AssignmentView{}, err
	}
	return s.store.GetAssignment(ctx, stored.ID)
}

// Delete soft-deletes one ordinary assignment.
func (s *State) Delete(ctx context.Context, op store.AuditOperation, id string) error {
	if ctx == nil || !validID(id) {
		return ErrInvalidInput
	}
	row, err := s.store.GetAssignment(ctx, id)
	if err != nil {
		if store.IsNotFound(err) {
			return ErrNotFound
		}
		return err
	}
	if row.SourceType == "action" {
		action, err := s.store.GetManifestAction(ctx, row.SourceID)
		if err != nil {
			return err
		}
		if action.IsSystem {
			return ErrSystemAction
		}
	}
	_, err = s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.SoftDeleteAssignment(ctx, id); err != nil {
			return err
		}
		before := row.TargetID
		rec.Effect(store.AuditEffect{
			ResourceType: "assignment", ResourceID: id, Action: "DELETE",
			Outcome: store.EffectApplied, ChangedFields: []string{"is_deleted"}, BeforeRef: &before,
		})
		return nil
	})
	if store.IsNotFound(err) {
		return ErrNotFound
	}
	return err
}

// SetUserSelection upserts one device/source choice only while a live
// AVAILABLE assignment resolves to that device. The eligibility check, row
// write and effect commit together.
func (s *State) SetUserSelection(
	ctx context.Context,
	op store.AuditOperation,
	deviceID string,
	sourceType pmv1.AssignmentSourceType,
	sourceID string,
	selected bool,
	actorID string,
) (store.UserSelectionRow, error) {
	typeName, ok := sourceTypeName(sourceType)
	if ctx == nil || !ok || !validID(deviceID) || !validID(sourceID) || !validID(actorID) ||
		(op.ActorID != "" && op.ActorID != actorID) {
		return store.UserSelectionRow{}, ErrInvalidInput
	}

	var selection store.UserSelectionRow
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		available, err := tx.AvailableAssignmentExistsForDevice(ctx, db.AvailableAssignmentExistsForDeviceParams{
			DeviceID: deviceID, SourceType: typeName, SourceID: sourceID,
		})
		if err != nil {
			return fmt.Errorf("assignment: check available selection: %w", err)
		}
		if !available {
			return ErrNoAvailableAssignment
		}

		selection, err = tx.UpsertUserSelection(ctx, db.UpsertUserSelectionParams{
			ID: ulid.Make().String(), DeviceID: deviceID, SourceType: typeName, SourceID: sourceID,
			Selected: selected, UpdatedAt: s.now().UTC(), CreatedBy: actorID,
		})
		if err != nil {
			return fmt.Errorf("assignment: upsert selection: %w", err)
		}
		after := selected
		action := "DESELECT"
		if selected {
			action = "SELECT"
		}
		rec.Effect(store.AuditEffect{
			ResourceType: "user_selection", ResourceID: selection.ID,
			Action: action, Outcome: store.EffectApplied,
			ChangedFields: []string{"selected"}, AfterFlag: &after,
		})
		return nil
	})
	if err != nil {
		return store.UserSelectionRow{}, err
	}
	return selection, nil
}

type referenceQueries interface {
	GetManifestAction(context.Context, string) (db.Action, error)
	GetManifestActionSet(context.Context, string) (db.ActionSet, error)
	GetManifestDefinition(context.Context, string) (db.Definition, error)
	GetAuthoringCompliancePolicy(context.Context, string) (db.CompliancePolicy, error)
	GetDevice(context.Context, string) (db.Device, error)
	GetDeviceGroupID(context.Context, string) (string, error)
	GetUser(context.Context, string) (db.User, error)
	GetUserGroup(context.Context, string) (db.UserGroup, error)
}

func (s *State) validateReferences(ctx context.Context, q referenceQueries, p CreateParams) error {
	var err error
	switch p.SourceType {
	case pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION:
		var action db.Action
		action, err = q.GetManifestAction(ctx, p.SourceID)
		if err == nil && action.IsSystem {
			return ErrSystemAction
		}
	case pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION_SET:
		_, err = q.GetManifestActionSet(ctx, p.SourceID)
	case pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_DEFINITION:
		_, err = q.GetManifestDefinition(ctx, p.SourceID)
	case pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_COMPLIANCE_POLICY:
		_, err = q.GetAuthoringCompliancePolicy(ctx, p.SourceID)
	default:
		return ErrInvalidInput
	}
	if store.IsNotFound(err) {
		return ErrSourceNotFound
	}
	if err != nil {
		return fmt.Errorf("assignment: validate source: %w", err)
	}

	switch p.TargetType {
	case pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE:
		_, err = q.GetDevice(ctx, p.TargetID)
	case pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE_GROUP:
		_, err = q.GetDeviceGroupID(ctx, p.TargetID)
	case pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER:
		_, err = q.GetUser(ctx, p.TargetID)
	case pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER_GROUP:
		_, err = q.GetUserGroup(ctx, p.TargetID)
	default:
		return ErrInvalidInput
	}
	if store.IsNotFound(err) {
		return ErrTargetNotFound
	}
	if err != nil {
		return fmt.Errorf("assignment: validate target: %w", err)
	}
	return nil
}

func sourceTypeName(value pmv1.AssignmentSourceType) (string, bool) {
	switch value {
	case pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION:
		return "action", true
	case pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION_SET:
		return "action_set", true
	case pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_DEFINITION:
		return "definition", true
	case pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_COMPLIANCE_POLICY:
		return "compliance_policy", true
	default:
		return "", false
	}
}

func targetTypeName(value pmv1.AssignmentTargetType) (string, bool) {
	switch value {
	case pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE:
		return "device", true
	case pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE_GROUP:
		return "device_group", true
	case pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER:
		return "user", true
	case pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER_GROUP:
		return "user_group", true
	default:
		return "", false
	}
}

func validMode(value pmv1.AssignmentMode) bool {
	_, ok := pmv1.AssignmentMode_name[int32(value)]
	return ok
}

func validID(value string) bool {
	_, err := ulid.ParseStrict(value)
	return err == nil
}
