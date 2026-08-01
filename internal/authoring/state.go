// Package authoring owns direct CRUD state transitions for Actions,
// ActionSets and Definitions. It does not append domain events or maintain
// projections; every mutation commits through the Store audit primitive.
package authoring

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf8"

	"github.com/oklog/ulid/v2"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	defaultActionTimeout = int32(300)
	maxParamsBytes       = 2 << 20
)

var (
	ErrInvalidInput = errors.New("invalid authoring input")
	ErrSystemAction = errors.New("system action cannot be changed by an operator")
	actionValidator = sdkvalidate.NewValidator()
)

// Config supplies the direct store and the clock used for authored rows.
type Config struct {
	Store *store.Store
	Now   func() time.Time
}

// Service changes authored state in audited PostgreSQL transactions.
type Service struct {
	store *store.Store
	now   func() time.Time
}

// New constructs the authoring state service.
func New(cfg Config) *Service {
	if cfg.Store == nil {
		panic("authoring: store is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{store: cfg.Store, now: cfg.Now}
}

// CreateActionParams is the complete stored shape of a new Action.
type CreateActionParams struct {
	Name           string
	Description    string
	CreatedBy      string
	Type           pmv1.ActionType
	DesiredState   pmv1.DesiredState
	Params         []byte
	TimeoutSeconds int32
	Schedule       *pmv1.ActionSchedule
	System         bool
}

// UpdateActionParams replaces the mutable execution fields of an Action.
// Zero timeout and nil schedule preserve their current stored values, matching
// the existing explicit RPC contract.
type UpdateActionParams struct {
	ID             string
	DesiredState   pmv1.DesiredState
	Params         []byte
	TimeoutSeconds int32
	Schedule       *pmv1.ActionSchedule
	AllowSystem    bool
}

// docref: begin audited-action-crud

// CreateAction inserts one ordinary authored row and its audit effect.
func (s *Service) CreateAction(ctx context.Context, op store.AuditOperation, p CreateActionParams) (store.ActionRow, error) {
	if ctx == nil || !validID(p.CreatedBy) || (op.ActorID != "" && op.ActorID != p.CreatedBy) ||
		p.Name == "" || utf8.RuneCountInString(p.Name) > 255 || utf8.RuneCountInString(p.Description) > 1024 {
		return store.ActionRow{}, ErrInvalidInput
	}
	timeout := p.TimeoutSeconds
	if timeout == 0 {
		timeout = defaultActionTimeout
	}
	params, err := validateActionData("pending", p.Type, p.DesiredState, timeout, p.Schedule, p.Params)
	if err != nil {
		return store.ActionRow{}, err
	}
	schedule, err := actionparams.ScheduleToRaw(p.Schedule)
	if err != nil {
		return store.ActionRow{}, fmt.Errorf("authoring: encode action schedule: %w", err)
	}

	id := ulid.Make().String()
	now := s.now().UTC()
	var out store.ActionRow
	_, err = s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		row, err := tx.InsertAuthoringAction(ctx, db.InsertAuthoringActionParams{
			ID: id, Name: p.Name, Description: p.Description,
			ActionType: int32(p.Type), DesiredState: int32(p.DesiredState),
			Params: params, ParamsCanonical: params, TimeoutSeconds: timeout,
			Schedule: schedule, IsSystem: p.System, CreatedAt: &now, CreatedBy: p.CreatedBy,
		})
		if err != nil {
			return fmt.Errorf("authoring: insert action: %w", err)
		}
		out = row
		rec.Effect(actionEffect(id, "CREATE",
			"name", "description", "action_type", "desired_state", "params", "timeout_seconds", "schedule"))
		return nil
	})
	if err != nil {
		return store.ActionRow{}, err
	}
	return out, nil
}

// RenameAction replaces an Action name with last-write-wins semantics.
func (s *Service) RenameAction(ctx context.Context, op store.AuditOperation, id, name string, allowSystem bool) (store.ActionRow, error) {
	if ctx == nil || !validID(id) || name == "" || utf8.RuneCountInString(name) > 255 {
		return store.ActionRow{}, ErrInvalidInput
	}
	now := s.now().UTC()
	var out store.ActionRow
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		row, err := tx.RenameAuthoringAction(ctx, db.RenameAuthoringActionParams{
			ID: id, Name: name, UpdatedAt: &now, AllowSystem: allowSystem,
		})
		if err != nil {
			return err
		}
		out = row
		rec.Effect(actionEffect(id, "UPDATE", "name"))
		return nil
	})
	return out, s.classifyWriteError(ctx, id, allowSystem, err)
}

// UpdateActionDescription replaces an Action description.
func (s *Service) UpdateActionDescription(ctx context.Context, op store.AuditOperation, id, description string, allowSystem bool) (store.ActionRow, error) {
	if ctx == nil || !validID(id) || utf8.RuneCountInString(description) > 1024 {
		return store.ActionRow{}, ErrInvalidInput
	}
	now := s.now().UTC()
	var out store.ActionRow
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		row, err := tx.UpdateAuthoringActionDescription(ctx, db.UpdateAuthoringActionDescriptionParams{
			ID: id, Description: description, UpdatedAt: &now, AllowSystem: allowSystem,
		})
		if err != nil {
			return err
		}
		out = row
		rec.Effect(actionEffect(id, "UPDATE", "description"))
		return nil
	})
	return out, s.classifyWriteError(ctx, id, allowSystem, err)
}

// UpdateActionParams replaces params and desired state and, when present,
// timeout and schedule. Action type remains immutable.
func (s *Service) UpdateActionParams(ctx context.Context, op store.AuditOperation, p UpdateActionParams) (store.ActionRow, error) {
	if ctx == nil || !validID(p.ID) {
		return store.ActionRow{}, ErrInvalidInput
	}
	existing, err := s.store.GetManifestAction(ctx, p.ID)
	if err != nil {
		return store.ActionRow{}, err
	}
	if existing.IsSystem && !p.AllowSystem {
		return store.ActionRow{}, ErrSystemAction
	}
	timeout := p.TimeoutSeconds
	if timeout == 0 {
		timeout = existing.TimeoutSeconds
	}
	scheduleForValidation := p.Schedule
	if scheduleForValidation == nil {
		scheduleForValidation, err = actionparams.ParseSchedule(existing.Schedule)
		if err != nil {
			return store.ActionRow{}, fmt.Errorf("authoring: stored action schedule: %w", err)
		}
	}
	params, err := validateActionData(p.ID, pmv1.ActionType(existing.ActionType), p.DesiredState, timeout, scheduleForValidation, p.Params)
	if err != nil {
		return store.ActionRow{}, err
	}
	var schedule []byte
	if p.Schedule != nil {
		schedule, err = actionparams.ScheduleToRaw(p.Schedule)
		if err != nil {
			return store.ActionRow{}, fmt.Errorf("authoring: encode action schedule: %w", err)
		}
	}

	now := s.now().UTC()
	var out store.ActionRow
	_, err = s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		row, err := tx.UpdateAuthoringActionParams(ctx, db.UpdateAuthoringActionParamsParams{
			ID: p.ID, DesiredState: int32(p.DesiredState), Params: params, ParamsCanonical: params,
			TimeoutSet: p.TimeoutSeconds > 0, TimeoutSeconds: p.TimeoutSeconds,
			ScheduleSet: p.Schedule != nil, Schedule: schedule,
			UpdatedAt: &now, AllowSystem: p.AllowSystem,
		})
		if err != nil {
			return err
		}
		out = row
		changed := []string{"desired_state", "params"}
		if p.TimeoutSeconds > 0 {
			changed = append(changed, "timeout_seconds")
		}
		if p.Schedule != nil {
			changed = append(changed, "schedule")
		}
		rec.Effect(actionEffect(p.ID, "UPDATE", changed...))
		return nil
	})
	return out, s.classifyWriteError(ctx, p.ID, p.AllowSystem, err)
}

// DeleteAction soft-deletes the authored row and removes composition edges in
// the same audited transaction.
func (s *Service) DeleteAction(ctx context.Context, op store.AuditOperation, id string, allowSystem bool) error {
	if ctx == nil || !validID(id) {
		return ErrInvalidInput
	}
	now := s.now().UTC()
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.DeleteActionMemberships(ctx, id); err != nil {
			return fmt.Errorf("authoring: delete action memberships: %w", err)
		}
		if _, err := tx.SoftDeleteAuthoringAction(ctx, db.SoftDeleteAuthoringActionParams{
			ID: id, UpdatedAt: &now, AllowSystem: allowSystem,
		}); err != nil {
			return err
		}
		rec.Effect(actionEffect(id, "DELETE", "is_deleted", "memberships"))
		return nil
	})
	return s.classifyWriteError(ctx, id, allowSystem, err)
}

// docref: end audited-action-crud

func validateActionData(id string, actionType pmv1.ActionType, desired pmv1.DesiredState, timeout int32, schedule *pmv1.ActionSchedule, raw []byte) ([]byte, error) {
	if _, ok := pmv1.ActionType_name[int32(actionType)]; !ok || actionType == pmv1.ActionType_ACTION_TYPE_UNSPECIFIED {
		return nil, ErrInvalidInput
	}
	if _, ok := pmv1.DesiredState_name[int32(desired)]; !ok || timeout < 0 || timeout > 3600 {
		return nil, ErrInvalidInput
	}
	canonical, err := canonicalJSONObject(raw)
	if err != nil {
		return nil, err
	}
	actionID := id
	if !validID(actionID) {
		actionID = ulid.Make().String()
	}
	action := &pmv1.Action{
		Id: &pmv1.ActionId{Value: actionID}, Type: actionType,
		DesiredState: desired, TimeoutSeconds: timeout, Schedule: schedule,
	}
	if err := actionparams.PopulateAction(action, int32(actionType), canonical); err != nil {
		return nil, fmt.Errorf("authoring: validate action params: %w", err)
	}
	if actionparams.ExtractParamsMsg(action) == nil && !bytes.Equal(canonical, []byte("{}")) {
		return nil, ErrInvalidInput
	}
	if detail, ok := sdkvalidate.Struct(actionValidator, action); !ok {
		return nil, fmt.Errorf("%w: %s", ErrInvalidInput, detail)
	}
	return canonical, nil
}

func canonicalJSONObject(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if len(raw) > maxParamsBytes {
		return nil, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil || value == nil {
		return nil, ErrInvalidInput
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidInput
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("authoring: canonicalize params: %w", err)
	}
	return canonical, nil
}

func (s *Service) classifyWriteError(ctx context.Context, id string, allowSystem bool, err error) error {
	if err == nil || !store.IsNotFound(err) {
		return err
	}
	row, readErr := s.store.GetManifestAction(ctx, id)
	if readErr == nil && row.IsSystem && !allowSystem {
		return ErrSystemAction
	}
	return store.ErrNotFound
}

func actionEffect(id, action string, fields ...string) store.AuditEffect {
	return store.AuditEffect{
		ResourceType: "action", ResourceID: id, Action: action,
		Outcome: store.EffectApplied, ChangedFields: fields,
	}
}

func validID(id string) bool {
	_, err := ulid.ParseStrict(id)
	return err == nil
}
