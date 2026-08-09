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
	"strings"
	"time"
	"unicode/utf8"

	"github.com/oklog/ulid/v2"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	pmcrypto "github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/store/sqlitetype"
	"google.golang.org/protobuf/proto"
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

// Service changes authored state in audited SQLite transactions.
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
	ID             string
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
	id := p.ID
	if id == "" {
		id = ulid.Make().String()
	} else if !validID(id) {
		return store.ActionRow{}, ErrInvalidInput
	}
	params, err := validateActionData(id, p.Type, p.DesiredState, timeout, p.Schedule, p.Params)
	if err != nil {
		return store.ActionRow{}, err
	}
	schedule, err := actionparams.ScheduleToRaw(p.Schedule)
	if err != nil {
		return store.ActionRow{}, fmt.Errorf("authoring: encode action schedule: %w", err)
	}

	now := s.now().UTC()
	var out store.ActionRow
	_, err = s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		row, err := tx.InsertAuthoringAction(ctx, db.InsertAuthoringActionParams{
			ID: id, Name: p.Name, Description: p.Description,
			ActionType: int32(p.Type), DesiredState: int32(p.DesiredState),
			Params: params, ParamsCanonical: params, TimeoutSeconds: timeout,
			Schedule: sqlitetype.JSON(schedule), IsSystem: p.System, CreatedAt: &now, CreatedBy: p.CreatedBy,
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
		return refreshActionDependents(ctx, tx, rec, id, true)
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
		return refreshActionDependents(ctx, tx, rec, id, false)
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
			HasTimeout: boolInt32(p.TimeoutSeconds > 0), TimeoutSeconds: p.TimeoutSeconds,
			HasSchedule: p.Schedule != nil, Schedule: sqlitetype.JSON(schedule),
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

func boolInt32(value bool) int32 {
	if value {
		return 1
	}
	return 0
}

// DeleteAction soft-deletes the authored row and removes composition edges in
// the same audited transaction.
func (s *Service) DeleteAction(ctx context.Context, op store.AuditOperation, id string, allowSystem bool) error {
	if ctx == nil || !validID(id) {
		return ErrInvalidInput
	}
	now := s.now().UTC()
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if err := refreshActionDependents(ctx, tx, rec, id, false); err != nil {
			return err
		}
		if _, err := tx.DeleteActionMemberships(ctx, id); err != nil {
			return fmt.Errorf("authoring: delete action memberships: %w", err)
		}
		if _, err := tx.DeleteCompliancePolicyRulesForAction(ctx, id); err != nil {
			return fmt.Errorf("authoring: delete compliance policy rules: %w", err)
		}
		evaluationDevices, err := tx.DeleteCompliancePolicyEvaluationsForAction(ctx, id)
		if err != nil {
			return fmt.Errorf("authoring: delete compliance policy evaluations: %w", err)
		}
		resultDevices, err := tx.DeleteComplianceResultsForAction(ctx, id)
		if err != nil {
			return fmt.Errorf("authoring: delete compliance results: %w", err)
		}
		if err := store.RefreshDeviceCompliance(ctx, tx, rec, evaluationDevices, resultDevices); err != nil {
			return err
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
	request := &pmv1.UpdateActionParamsRequest{
		Id: actionID, DesiredState: desired, TimeoutSeconds: timeout, Schedule: schedule,
	}
	if err := actionparams.PopulateUpdateActionParams(request, actionType, canonical); err != nil {
		return nil, fmt.Errorf("authoring: validate action params: %w", err)
	}
	params := actionparams.ExtractParamsMsg(request)
	if params == nil && !bytes.Equal(canonical, []byte("{}")) {
		return nil, ErrInvalidInput
	}
	if err := normalizeStoredSecretsForValidation(params); err != nil {
		return nil, err
	}
	if detail, ok := sdkvalidate.Struct(actionValidator, request); !ok {
		return nil, fmt.Errorf("%w: %s", ErrInvalidInput, detail)
	}
	if err := validateActionSafety(params); err != nil {
		return nil, err
	}
	return canonical, nil
}

func normalizeStoredSecretsForValidation(params proto.Message) error {
	switch value := params.(type) {
	case *pmv1.EncryptionAuthoringParams:
		if value.PresharedKey == nil || !pmcrypto.IsEncryptedValue(value.GetPresharedKey()) {
			return ErrInvalidInput
		}
		value.PresharedKey = stringPointer("configured")
	case *pmv1.WifiAuthoringParams:
		switch value.AuthType {
		case pmv1.WifiAuthType_WIFI_AUTH_TYPE_PSK:
			if value.Psk == nil || !pmcrypto.IsEncryptedValue(value.GetPsk()) || value.ClientKey != nil {
				return ErrInvalidInput
			}
			value.Psk = stringPointer("configured")
		case pmv1.WifiAuthType_WIFI_AUTH_TYPE_EAP_TLS:
			if value.ClientKey == nil || !pmcrypto.IsEncryptedValue(value.GetClientKey()) || value.Psk != nil {
				return ErrInvalidInput
			}
			value.ClientKey = stringPointer("configured")
		default:
			return ErrInvalidInput
		}
	}
	return nil
}

// ValidateExecutableAction applies the same type, parameter, and safety rules
// used by persisted Actions to an inline Action before it enters a manifest.
func ValidateExecutableAction(action *pmv1.Action) error {
	if action == nil || !validID(action.GetId().GetValue()) {
		return ErrInvalidInput
	}
	params := actionparams.ExtractParamsMsg(action)
	if params == nil {
		// UPDATE is the only ordinary action whose empty params oneof is
		// meaningful. REBOOT and SYNC use DispatchInstantAction instead.
		if action.Type != pmv1.ActionType_ACTION_TYPE_UPDATE {
			return ErrInvalidInput
		}
	} else if !actionparams.ParamsMatchType(action, action.Type) {
		return ErrInvalidInput
	}
	raw := []byte("{}")
	if params != nil {
		var err error
		raw, err = actionparams.MarshalActionParams(params)
		if err != nil {
			return ErrInvalidInput
		}
	}
	_, err := validateActionData(action.Id.Value, action.Type, action.DesiredState,
		action.TimeoutSeconds, action.Schedule, raw)
	return err
}

func validateActionSafety(params proto.Message) error {
	switch p := params.(type) {
	case *pmv1.ShellParams:
		if p.Script == "" && p.DetectionScript == "" {
			return fmt.Errorf("%w: shell action needs a script or detection script", ErrInvalidInput)
		}
		if p.IsCompliance && strings.TrimSpace(p.DetectionScript) == "" {
			return fmt.Errorf("%w: compliance shell action is detection-only and needs a detection script", ErrInvalidInput)
		}
	case *pmv1.AppInstallParams:
		if !strings.HasPrefix(strings.ToLower(p.Url), "https://") || !isLowerHex64(p.ChecksumSha256) {
			return fmt.Errorf("%w: application install requires HTTPS and a lowercase SHA-256", ErrInvalidInput)
		}
	case *pmv1.AgentUpdateParams:
		if p.Amd64 == nil && p.Arm64 == nil {
			return fmt.Errorf("%w: agent update needs at least one architecture", ErrInvalidInput)
		}
		for _, arch := range []*pmv1.AgentUpdateArch{p.Amd64, p.Arm64} {
			if arch == nil {
				continue
			}
			if !strings.HasPrefix(strings.ToLower(arch.BinaryUrl), "https://") ||
				arch.ChecksumUrl == "" ||
				!strings.HasPrefix(strings.ToLower(arch.ChecksumUrl), "https://") {
				return fmt.Errorf("%w: unsafe agent update source", ErrInvalidInput)
			}
		}
	}
	return nil
}

func isLowerHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
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
