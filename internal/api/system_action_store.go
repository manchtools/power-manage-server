package api

// systemActionStore owns the event-shape construction for the six
// CRUD operations the SystemActionManager fans out across the
// system-action lifecycle: create, update, delete, assign, link,
// sign. Extracted from system_actions.go so the manager focuses on
// policy ("when a user gets a role, sync their system actions")
// without owning the bespoke event payloads each operation emits.
//
// Keeps the manager's tests focused on policy decisions and the
// store's tests focused on event-shape determinism. See
// manchtools/power-manage-server#154 (audit F033).

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
)

// systemActionStore is the collaborator that owns event-shape
// construction for system-managed actions. The manager calls into
// it for every event emission; the store is the single point at
// which a system-action event's payload is assembled.
type systemActionStore struct {
	store  *store.Store
	signer ca.ActionSigner
}

// newSystemActionStore wires the store + signer. Callers (currently
// only NewSystemActionManager) instantiate one of these and embed it
// in the manager.
func newSystemActionStore(st *store.Store, signer ca.ActionSigner) *systemActionStore {
	return &systemActionStore{store: st, signer: signer}
}

// CreateAction emits an ActionCreated event with is_system=true.
// Returns the new action ID.
func (s *systemActionStore) CreateAction(ctx context.Context, name string, actionType, desiredState int32, paramsJSON []byte) (string, error) {
	id := newULID()

	// Validate the params byte slice is well-formed JSON before
	// embedding it as RawMessage in the typed payload — silently
	// emitting malformed JSONB would only surface at projector time.
	if !json.Valid(paramsJSON) {
		return "", fmt.Errorf("createSystemAction: paramsJSON is not valid JSON")
	}

	desc := "System-managed action"
	timeoutSec := int32(300)
	isSystem := true
	if err := s.store.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   id,
		EventType:  string(eventtypes.ActionCreated),
		Data: payloads.ActionCreated{
			Name:           name,
			Description:    &desc,
			ActionType:     &actionType,
			DesiredState:   &desiredState,
			Params:         paramsJSON,
			TimeoutSeconds: &timeoutSec,
			IsSystem:       &isSystem,
		},
		ActorType: "system",
		ActorID:   "system",
	}); err != nil {
		return "", fmt.Errorf("append ActionCreated: %w", err)
	}

	return id, nil
}

// AssignActionToUser emits an AssignmentCreated event.
func (s *systemActionStore) AssignActionToUser(ctx context.Context, actionID, userID string) error {
	assignmentID := newULID()
	mode := int32(0) // REQUIRED
	sortOrder := int32(0)
	return s.store.AppendEvent(ctx, store.Event{
		StreamType: "assignment",
		StreamID:   assignmentID,
		EventType:  string(eventtypes.AssignmentCreated),
		Data: payloads.AssignmentCreated{
			SourceType: "action",
			SourceID:   actionID,
			TargetType: "user",
			TargetID:   userID,
			Mode:       &mode,
			SortOrder:  &sortOrder,
		},
		ActorType: "system",
		ActorID:   "system",
	})
}

// UpdateAction emits an ActionParamsUpdated event.
func (s *systemActionStore) UpdateAction(ctx context.Context, actionID string, desiredState int32, paramsJSON []byte) error {
	if !json.Valid(paramsJSON) {
		return fmt.Errorf("updateSystemAction: paramsJSON is not valid JSON")
	}

	return s.store.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   actionID,
		EventType:  string(eventtypes.ActionParamsUpdated),
		Data: payloads.ActionParamsUpdated{
			Params:       paramsJSON,
			DesiredState: &desiredState,
		},
		ActorType: "system",
		ActorID:   "system",
	})
}

// DeleteAction emits an ActionDeleted event.
func (s *systemActionStore) DeleteAction(ctx context.Context, actionID string) error {
	return s.store.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   actionID,
		EventType:  string(eventtypes.ActionDeleted),
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "system",
	})
}

// LinkAction emits a UserSystemActionLinked event to record the
// system action ID on the user projection.
func (s *systemActionStore) LinkAction(ctx context.Context, userID, field, actionID string) error {
	return s.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  string(eventtypes.UserSystemActionLinked),
		Data: payloads.UserSystemActionLinked{
			Field:    &field,
			ActionID: &actionID,
		},
		ActorType: "system",
		ActorID:   "system",
	})
}

// SignActionByID NO LONGER persists a dispatch-grade signature.
//
// Action-signing rewrite: a system action is signed at DISPATCH, over the
// full SignedActionEnvelope bound to the execution id and target device —
// not at sync time. Persisting a create/sign-time signature here was
// misleading: it covered a different pre-image (the action id, not the
// execution id) and could never verify against a dispatch envelope.
//
// What this method still does — and why it is NOT a pure no-op — is pin
// the action's params blob into the params_canonical column so there is an
// immutable record of exactly what JSON the system action carries. It keeps
// its fail-closed contract on a missing/unloadable action so the callers
// (syncUserProvisionAction, syncSshAccessAction, syncTtyUserAction) still
// surface a sync failure rather than leaving a half-provisioned row.
//
// The signature column is written nil (the projection column stays; no
// migration). No signer is required any more.
func (s *systemActionStore) SignActionByID(ctx context.Context, actionID string) error {
	action, err := s.store.Repos().Action.Get(ctx, actionID)
	if err != nil {
		return fmt.Errorf("load system action %s for params pinning: %w", actionID, err)
	}

	paramsJSON := action.Params
	if paramsJSON == nil {
		paramsJSON = []byte("{}")
	}

	// Signature intentionally nil: signing happens at dispatch, never here.
	if err := s.store.Repos().Action.UpdateSignature(ctx, store.UpdateActionSignatureParams{ID: action.ID, Signature: nil, ParamsCanonical: paramsJSON}); err != nil {
		return fmt.Errorf("store system action %s params blob: %w", actionID, err)
	}

	return nil
}
