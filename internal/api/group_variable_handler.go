// Group-variable handler — implementation of the #59 group-based
// variables design, ticket B (#195). Foundation (migration + queries
// + per-type validator + stubs) landed in commit 9fec2bb; this file
// replaces the stubs with the real Set / Delete / Get / List logic
// plus event emission and the 10-permission RBAC split.
//
// Trust model: variable-write is itself a privileged operation
// (Set*Variable + secret variant). The renderer (#196) does no
// shell-quoting at render time — every value flows in literally —
// so the protection lives at the SET-time gate. Secret-typed values
// are encrypted via internal/crypto on the way IN and decrypted by
// the renderer on the way OUT; the audit log scrubs the ciphertext
// via the schema-aware redactor in audit_handler.go.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// GroupVariableHandler implements the device-group / user-group
// variable RPCs introduced by the #59 design. It owns the
// secret-encryption pathway via *crypto.Encryptor; non-secret
// variables flow through unchanged.
type GroupVariableHandler struct {
	store     *store.Store
	logger    *slog.Logger
	encryptor *crypto.Encryptor
}

// NewGroupVariableHandler constructs the handler. The encryptor is
// the same one wired into the rest of ControlService — it shares the
// AES-GCM key with LpsPasswordRotated / LuksKeyRotated.
func NewGroupVariableHandler(st *store.Store, enc *crypto.Encryptor, logger *slog.Logger) *GroupVariableHandler {
	return &GroupVariableHandler{store: st, logger: logger, encryptor: enc}
}

// storedVariable is the on-disk shape of a group-scoped variable. The
// JSONB column on device_groups_projection / user_groups_projection
// holds an array of these. Secret-typed entries store the AES-GCM
// ciphertext in Value; non-secret types store the raw value as the
// per-type validator accepted it.
//
// Mirrored (intentionally duplicated) by the unexported storedVariable
// in internal/api/template/resolver.go — the renderer can't import
// this package without a cycle. Any field changes must land in both
// places or the renderer will silently drop the new field on read.
type storedVariable struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Value        string   `json:"value"`
	Description  string   `json:"description,omitempty"`
	IntMin       int64    `json:"int_min,omitempty"`
	IntMax       int64    `json:"int_max,omitempty"`
	ChoiceValues []string `json:"choice_values,omitempty"`
}

// =============================================================================
// Device-group variables
// =============================================================================

// SetDeviceGroupVariable creates or updates a device-group variable.
// Full-replace semantics: if a variable with the same name already
// exists it is overwritten. Secret-typed values are AES-GCM encrypted
// before persistence; the SetDeviceGroupSecretVariable permission is
// required for those (the non-secret SetDeviceGroupVariable
// permission is required for everything else).
func (h *GroupVariableHandler) SetDeviceGroupVariable(ctx context.Context, req *connect.Request[pm.SetDeviceGroupVariableRequest]) (*connect.Response[pm.SetDeviceGroupVariableResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}
	if req.Msg.Variable == nil {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "variable is required")
	}
	if err := h.requireWritePerm(ctx, "DeviceGroup", req.Msg.Variable.Type); err != nil {
		return nil, err
	}
	if err := ValidateVariable(ctx, req.Msg.Variable); err != nil {
		return nil, err
	}

	stored, err := h.encodeForStorage(ctx, req.Msg.Variable)
	if err != nil {
		return nil, err
	}

	if err := h.upsertDeviceGroupVariable(ctx, req.Msg.DeviceGroupId, stored, req.Msg.Variable.Type, userCtx.ID); err != nil {
		return nil, err
	}

	return connect.NewResponse(&pm.SetDeviceGroupVariableResponse{
		Variable: redactSecretValue(req.Msg.Variable),
	}), nil
}

// DeleteDeviceGroupVariable removes a single named variable from the
// device group. Idempotent — succeeds even if the variable is already
// absent (the operator's intent is captured either way via the
// emitted event). The required permission depends on whether the
// soon-to-be-removed variable is secret-typed; we look it up before
// dispatch.
func (h *GroupVariableHandler) DeleteDeviceGroupVariable(ctx context.Context, req *connect.Request[pm.DeleteDeviceGroupVariableRequest]) (*connect.Response[pm.DeleteDeviceGroupVariableResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	existing, err := h.loadDeviceGroupVariables(ctx, req.Msg.DeviceGroupId)
	if err != nil {
		return nil, err
	}
	target, found := findStored(existing, req.Msg.Name)
	if !found {
		// No-op delete (variable already absent). Return success
		// without emitting an event AND without consulting the
		// :secret permission — there's no operator intent to gate
		// because there's nothing to remove. The previous shape
		// defaulted varType to STRING and silently bypassed the
		// :secret check on a then-existing-now-missing race.
		return connect.NewResponse(&pm.DeleteDeviceGroupVariableResponse{}), nil
	}
	varType := parseVariableType(target.Type)
	if err := h.requireDeletePerm(ctx, "DeviceGroup", varType); err != nil {
		return nil, err
	}

	if err := h.removeDeviceGroupVariable(ctx, req.Msg.DeviceGroupId, existing, req.Msg.Name, varType, userCtx.ID); err != nil {
		return nil, err
	}
	return connect.NewResponse(&pm.DeleteDeviceGroupVariableResponse{}), nil
}

// GetDeviceGroupVariables returns every variable defined on the
// device group. Secret-typed entries have Value="***REDACTED***"; the
// plaintext is only ever materialised inside the renderer at action
// dispatch time.
func (h *GroupVariableHandler) GetDeviceGroupVariables(ctx context.Context, req *connect.Request[pm.GetDeviceGroupVariablesRequest]) (*connect.Response[pm.GetDeviceGroupVariablesResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if _, err := requireAuth(ctx); err != nil {
		return nil, err
	}
	stored, err := h.loadDeviceGroupVariables(ctx, req.Msg.DeviceGroupId)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pm.GetDeviceGroupVariablesResponse{
		Variables: storedToProto(stored),
	}), nil
}

// =============================================================================
// User-group variables
// =============================================================================

// SetUserGroupVariable mirrors SetDeviceGroupVariable for user groups.
func (h *GroupVariableHandler) SetUserGroupVariable(ctx context.Context, req *connect.Request[pm.SetUserGroupVariableRequest]) (*connect.Response[pm.SetUserGroupVariableResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}
	if req.Msg.Variable == nil {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "variable is required")
	}
	if err := h.requireWritePerm(ctx, "UserGroup", req.Msg.Variable.Type); err != nil {
		return nil, err
	}
	if err := ValidateVariable(ctx, req.Msg.Variable); err != nil {
		return nil, err
	}

	stored, err := h.encodeForStorage(ctx, req.Msg.Variable)
	if err != nil {
		return nil, err
	}

	if err := h.upsertUserGroupVariable(ctx, req.Msg.UserGroupId, stored, req.Msg.Variable.Type, userCtx.ID); err != nil {
		return nil, err
	}

	return connect.NewResponse(&pm.SetUserGroupVariableResponse{
		Variable: redactSecretValue(req.Msg.Variable),
	}), nil
}

// DeleteUserGroupVariable mirrors DeleteDeviceGroupVariable.
func (h *GroupVariableHandler) DeleteUserGroupVariable(ctx context.Context, req *connect.Request[pm.DeleteUserGroupVariableRequest]) (*connect.Response[pm.DeleteUserGroupVariableResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	existing, err := h.loadUserGroupVariables(ctx, req.Msg.UserGroupId)
	if err != nil {
		return nil, err
	}
	target, found := findStored(existing, req.Msg.Name)
	if !found {
		// No-op delete — see DeleteDeviceGroupVariable for the
		// :secret bypass rationale.
		return connect.NewResponse(&pm.DeleteUserGroupVariableResponse{}), nil
	}
	varType := parseVariableType(target.Type)
	if err := h.requireDeletePerm(ctx, "UserGroup", varType); err != nil {
		return nil, err
	}

	if err := h.removeUserGroupVariable(ctx, req.Msg.UserGroupId, existing, req.Msg.Name, varType, userCtx.ID); err != nil {
		return nil, err
	}
	return connect.NewResponse(&pm.DeleteUserGroupVariableResponse{}), nil
}

// GetUserGroupVariables mirrors GetDeviceGroupVariables.
func (h *GroupVariableHandler) GetUserGroupVariables(ctx context.Context, req *connect.Request[pm.GetUserGroupVariablesRequest]) (*connect.Response[pm.GetUserGroupVariablesResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if _, err := requireAuth(ctx); err != nil {
		return nil, err
	}
	stored, err := h.loadUserGroupVariables(ctx, req.Msg.UserGroupId)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pm.GetUserGroupVariablesResponse{
		Variables: storedToProto(stored),
	}), nil
}

// =============================================================================
// ListAvailableVariables (for web autocomplete)
// =============================================================================

// ListAvailableVariables returns the union of variables defined on
// the named device-groups + user-groups. Variables are exclusively a
// group concept (device labels do NOT participate in resolution), so
// the picker queries by groups directly. Values are intentionally
// omitted; the picker only needs name + type + description.
//
// At least one of device_group_ids / user_group_ids MUST be provided.
// Per-group access is gated by GetDeviceGroup / GetUserGroup so an
// operator can't enumerate variables on groups they can't see.
func (h *GroupVariableHandler) ListAvailableVariables(ctx context.Context, req *connect.Request[pm.ListAvailableVariablesRequest]) (*connect.Response[pm.ListAvailableVariablesResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if _, err := requireAuth(ctx); err != nil {
		return nil, err
	}
	if len(req.Msg.DeviceGroupIds) == 0 && len(req.Msg.UserGroupIds) == 0 {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "at least one of device_group_ids or user_group_ids is required")
	}

	available := map[string]*pm.AvailableVariable{}

	// Device groups: gate on the unscoped GetDeviceGroup permission.
	// We deliberately do NOT accept GetDeviceGroup:assigned here —
	// per-group membership enforcement helpers don't exist in the
	// codebase yet, and accepting the assigned scope without per-group
	// checks would let an operator with :assigned-only access read
	// variables on arbitrary group IDs they pass in. Autocomplete is
	// an operator-facing tool that's typically used by users with
	// unrestricted group visibility anyway. If/when the autocomplete
	// is opened up to :assigned operators, add a per-group membership
	// check inside the loop.
	if len(req.Msg.DeviceGroupIds) > 0 {
		if !auth.HasPermission(ctx, "GetDeviceGroup") {
			return nil, apiErrorCtx(ctx, "permission_denied", connect.CodePermissionDenied, "permission denied: GetDeviceGroup required to list device-group variables")
		}
		for _, groupID := range req.Msg.DeviceGroupIds {
			raw, err := h.store.Queries().GetDeviceGroupVariables(ctx, groupID)
			if err != nil {
				h.logger.Warn("failed to load device-group variables for autocomplete", "group_id", groupID, "error", err)
				continue
			}
			stored, err := decodeStored(raw)
			if err != nil {
				h.logger.Warn("failed to decode device-group variables", "group_id", groupID, "error", err)
				continue
			}
			for _, v := range stored {
				entry, ok := available[v.Name]
				if !ok {
					entry = &pm.AvailableVariable{
						Name:        v.Name,
						Type:        parseVariableType(v.Type),
						Description: v.Description,
					}
					available[v.Name] = entry
				}
				entry.DefinedInGroupIds = append(entry.DefinedInGroupIds, groupID)
			}
		}
	}

	// User groups: same rationale as the device-group block above.
	if len(req.Msg.UserGroupIds) > 0 {
		if !auth.HasPermission(ctx, "GetUserGroup") {
			return nil, apiErrorCtx(ctx, "permission_denied", connect.CodePermissionDenied, "permission denied: GetUserGroup required to list user-group variables")
		}
		for _, groupID := range req.Msg.UserGroupIds {
			raw, err := h.store.Queries().GetUserGroupVariables(ctx, groupID)
			if err != nil {
				h.logger.Warn("failed to load user-group variables for autocomplete", "group_id", groupID, "error", err)
				continue
			}
			stored, err := decodeStored(raw)
			if err != nil {
				h.logger.Warn("failed to decode user-group variables", "group_id", groupID, "error", err)
				continue
			}
			for _, v := range stored {
				entry, ok := available[v.Name]
				if !ok {
					entry = &pm.AvailableVariable{
						Name:        v.Name,
						Type:        parseVariableType(v.Type),
						Description: v.Description,
					}
					available[v.Name] = entry
				}
				entry.DefinedInGroupIds = append(entry.DefinedInGroupIds, groupID)
			}
		}
	}

	out := make([]*pm.AvailableVariable, 0, len(available))
	for _, v := range available {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return connect.NewResponse(&pm.ListAvailableVariablesResponse{
		Variables: out,
	}), nil
}

// =============================================================================
// Internal helpers
// =============================================================================

// requireWritePerm gates the secret variant. The non-secret base
// permission (Set<Scope>Variable) was already enforced by the auth
// interceptor on the RPC name; we only need an extra check when the
// payload says SECRET. The :secret scope suffix follows the existing
// :self / :assigned convention and lets the parity test bind back to
// the same base RPC name.
func (h *GroupVariableHandler) requireWritePerm(ctx context.Context, scope string, t pm.VariableType) error {
	if t != pm.VariableType_VARIABLE_TYPE_SECRET {
		return nil
	}
	perm := "Set" + scope + "Variable:secret"
	if !auth.HasPermission(ctx, perm) {
		return apiErrorCtx(ctx, "permission_denied", connect.CodePermissionDenied, "permission denied: "+perm+" required for secret variables")
	}
	return nil
}

func (h *GroupVariableHandler) requireDeletePerm(ctx context.Context, scope string, t pm.VariableType) error {
	if t != pm.VariableType_VARIABLE_TYPE_SECRET {
		return nil
	}
	perm := "Delete" + scope + "Variable:secret"
	if !auth.HasPermission(ctx, perm) {
		return apiErrorCtx(ctx, "permission_denied", connect.CodePermissionDenied, "permission denied: "+perm+" required for secret variables")
	}
	return nil
}

func (h *GroupVariableHandler) encodeForStorage(ctx context.Context, v *pm.Variable) (storedVariable, error) {
	stored := storedVariable{
		Name:         v.Name,
		Type:         variableTypeToString(v.Type),
		Value:        v.Value,
		Description:  v.Description,
		IntMin:       v.IntMin,
		IntMax:       v.IntMax,
		ChoiceValues: append([]string(nil), v.ChoiceValues...),
	}
	if v.Type == pm.VariableType_VARIABLE_TYPE_SECRET {
		ciphertext, err := h.encryptor.Encrypt(v.Value)
		if err != nil {
			return storedVariable{}, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, fmt.Sprintf("failed to encrypt secret value: %v", err))
		}
		stored.Value = ciphertext
	}
	return stored, nil
}

func (h *GroupVariableHandler) loadDeviceGroupVariables(ctx context.Context, id string) ([]storedVariable, error) {
	raw, err := h.store.Queries().GetDeviceGroupVariables(ctx, id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceGroupNotFound, "device group not found")
	}
	stored, err := decodeStored(raw)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, fmt.Sprintf("failed to decode device-group variables: %v", err))
	}
	return stored, nil
}

func (h *GroupVariableHandler) loadUserGroupVariables(ctx context.Context, id string) ([]storedVariable, error) {
	raw, err := h.store.Queries().GetUserGroupVariables(ctx, id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserGroupNotFound, "user group not found")
	}
	stored, err := decodeStored(raw)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, fmt.Sprintf("failed to decode user-group variables: %v", err))
	}
	return stored, nil
}

func (h *GroupVariableHandler) upsertDeviceGroupVariable(ctx context.Context, groupID string, stored storedVariable, varType pm.VariableType, actorID string) error {
	existing, err := h.loadDeviceGroupVariables(ctx, groupID)
	if err != nil {
		return err
	}
	updated := upsertByName(existing, stored)
	encoded, err := json.Marshal(updated)
	if err != nil {
		return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, fmt.Sprintf("failed to encode variables: %v", err))
	}
	if err := h.store.Queries().SetDeviceGroupVariables(ctx, db.SetDeviceGroupVariablesParams{ID: groupID, Variables: encoded}); err != nil {
		return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, fmt.Sprintf("failed to persist variables: %v", err))
	}
	return h.emitVariableSet(ctx, "device", groupID, stored, varType, actorID)
}

func (h *GroupVariableHandler) upsertUserGroupVariable(ctx context.Context, groupID string, stored storedVariable, varType pm.VariableType, actorID string) error {
	existing, err := h.loadUserGroupVariables(ctx, groupID)
	if err != nil {
		return err
	}
	updated := upsertByName(existing, stored)
	encoded, err := json.Marshal(updated)
	if err != nil {
		return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, fmt.Sprintf("failed to encode variables: %v", err))
	}
	if err := h.store.Queries().SetUserGroupVariables(ctx, db.SetUserGroupVariablesParams{ID: groupID, Variables: encoded}); err != nil {
		return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, fmt.Sprintf("failed to persist variables: %v", err))
	}
	return h.emitVariableSet(ctx, "user", groupID, stored, varType, actorID)
}

func (h *GroupVariableHandler) removeDeviceGroupVariable(ctx context.Context, groupID string, existing []storedVariable, name string, varType pm.VariableType, actorID string) error {
	updated := removeByName(existing, name)
	encoded, err := json.Marshal(updated)
	if err != nil {
		return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, fmt.Sprintf("failed to encode variables: %v", err))
	}
	if err := h.store.Queries().SetDeviceGroupVariables(ctx, db.SetDeviceGroupVariablesParams{ID: groupID, Variables: encoded}); err != nil {
		return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, fmt.Sprintf("failed to persist variables: %v", err))
	}
	return h.emitVariableDeleted(ctx, "device", groupID, name, varType, actorID)
}

func (h *GroupVariableHandler) removeUserGroupVariable(ctx context.Context, groupID string, existing []storedVariable, name string, varType pm.VariableType, actorID string) error {
	updated := removeByName(existing, name)
	encoded, err := json.Marshal(updated)
	if err != nil {
		return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, fmt.Sprintf("failed to encode variables: %v", err))
	}
	if err := h.store.Queries().SetUserGroupVariables(ctx, db.SetUserGroupVariablesParams{ID: groupID, Variables: encoded}); err != nil {
		return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, fmt.Sprintf("failed to persist variables: %v", err))
	}
	return h.emitVariableDeleted(ctx, "user", groupID, name, varType, actorID)
}

func (h *GroupVariableHandler) emitVariableSet(ctx context.Context, groupType, groupID string, stored storedVariable, varType pm.VariableType, actorID string) error {
	streamType := groupType + "_group_variable"
	if varType == pm.VariableType_VARIABLE_TYPE_SECRET {
		evt := store.Event{
			StreamType: streamType,
			StreamID:   groupID,
			EventType:  string(eventtypes.GroupSecretVariableSet),
			Data: payloads.GroupSecretVariableSet{
				GroupType:   groupType,
				GroupID:     groupID,
				Name:        stored.Name,
				Ciphertext:  stored.Value,
				Description: stored.Description,
			},
			ActorType: "user",
			ActorID:   actorID,
		}
		return appendEvent(ctx, h.store, h.logger, evt, "failed to record secret variable set")
	}
	evt := store.Event{
		StreamType: streamType,
		StreamID:   groupID,
		EventType:  string(eventtypes.GroupVariableSet),
		Data: payloads.GroupVariableSet{
			GroupType:    groupType,
			GroupID:      groupID,
			Name:         stored.Name,
			Type:         stored.Type,
			Value:        stored.Value,
			Description:  stored.Description,
			IntMin:       stored.IntMin,
			IntMax:       stored.IntMax,
			ChoiceValues: stored.ChoiceValues,
		},
		ActorType: "user",
		ActorID:   actorID,
	}
	return appendEvent(ctx, h.store, h.logger, evt, "failed to record variable set")
}

func (h *GroupVariableHandler) emitVariableDeleted(ctx context.Context, groupType, groupID, name string, varType pm.VariableType, actorID string) error {
	streamType := groupType + "_group_variable"
	if varType == pm.VariableType_VARIABLE_TYPE_SECRET {
		evt := store.Event{
			StreamType: streamType,
			StreamID:   groupID,
			EventType:  string(eventtypes.GroupSecretVariableDeleted),
			Data: payloads.GroupSecretVariableDeleted{
				GroupType: groupType,
				GroupID:   groupID,
				Name:      name,
			},
			ActorType: "user",
			ActorID:   actorID,
		}
		return appendEvent(ctx, h.store, h.logger, evt, "failed to record secret variable deletion")
	}
	evt := store.Event{
		StreamType: streamType,
		StreamID:   groupID,
		EventType:  string(eventtypes.GroupVariableDeleted),
		Data: payloads.GroupVariableDeleted{
			GroupType: groupType,
			GroupID:   groupID,
			Name:      name,
		},
		ActorType: "user",
		ActorID:   actorID,
	}
	return appendEvent(ctx, h.store, h.logger, evt, "failed to record variable deletion")
}

// decodeStored unmarshals the JSONB column into the in-memory shape.
// An empty / null column decodes as the empty slice (the projection
// default is `'[]'::jsonb`).
func decodeStored(raw []byte) ([]storedVariable, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var out []storedVariable
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode group variables: %w", err)
	}
	return out, nil
}

// upsertByName replaces any existing entry with the same name and
// returns the new slice. A new entry is appended at the end.
func upsertByName(existing []storedVariable, v storedVariable) []storedVariable {
	for i := range existing {
		if existing[i].Name == v.Name {
			existing[i] = v
			return existing
		}
	}
	return append(existing, v)
}

// removeByName removes any entry with the given name. Idempotent —
// returns the input slice unchanged if no match.
func removeByName(existing []storedVariable, name string) []storedVariable {
	out := make([]storedVariable, 0, len(existing))
	for _, v := range existing {
		if v.Name == name {
			continue
		}
		out = append(out, v)
	}
	return out
}

func findStored(existing []storedVariable, name string) (storedVariable, bool) {
	for _, v := range existing {
		if v.Name == name {
			return v, true
		}
	}
	return storedVariable{}, false
}

// storedToProto converts the on-disk shape into the wire response,
// redacting the value of any secret-typed entry.
func storedToProto(stored []storedVariable) []*pm.Variable {
	out := make([]*pm.Variable, 0, len(stored))
	for _, v := range stored {
		t := parseVariableType(v.Type)
		value := v.Value
		if t == pm.VariableType_VARIABLE_TYPE_SECRET {
			value = "***REDACTED***"
		}
		out = append(out, &pm.Variable{
			Name:         v.Name,
			Type:         t,
			Value:        value,
			Description:  v.Description,
			IntMin:       v.IntMin,
			IntMax:       v.IntMax,
			ChoiceValues: append([]string(nil), v.ChoiceValues...),
		})
	}
	return out
}

// redactSecretValue returns a copy of v with the value scrubbed when
// the type is SECRET. Used in the Set response so the operator never
// sees the encrypted value reflected back.
func redactSecretValue(v *pm.Variable) *pm.Variable {
	if v == nil {
		return nil
	}
	out := &pm.Variable{
		Name:         v.Name,
		Type:         v.Type,
		Value:        v.Value,
		Description:  v.Description,
		IntMin:       v.IntMin,
		IntMax:       v.IntMax,
		ChoiceValues: append([]string(nil), v.ChoiceValues...),
	}
	if v.Type == pm.VariableType_VARIABLE_TYPE_SECRET {
		out.Value = "***REDACTED***"
	}
	return out
}

// variableTypeToString reduces the proto enum to the lowercase wire
// string used in storedVariable.Type and the audit-log payload's
// `type` field.
func variableTypeToString(t pm.VariableType) string {
	switch t {
	case pm.VariableType_VARIABLE_TYPE_STRING:
		return "string"
	case pm.VariableType_VARIABLE_TYPE_INT:
		return "int"
	case pm.VariableType_VARIABLE_TYPE_BOOL:
		return "bool"
	case pm.VariableType_VARIABLE_TYPE_HOSTNAME:
		return "hostname"
	case pm.VariableType_VARIABLE_TYPE_PATH:
		return "path"
	case pm.VariableType_VARIABLE_TYPE_CHOICE:
		return "choice"
	case pm.VariableType_VARIABLE_TYPE_SECRET:
		return "secret"
	default:
		return "unspecified"
	}
}

// parseVariableType is the reverse — used on the read path when the
// JSONB row is decoded back into storedVariable.
func parseVariableType(s string) pm.VariableType {
	switch s {
	case "string":
		return pm.VariableType_VARIABLE_TYPE_STRING
	case "int":
		return pm.VariableType_VARIABLE_TYPE_INT
	case "bool":
		return pm.VariableType_VARIABLE_TYPE_BOOL
	case "hostname":
		return pm.VariableType_VARIABLE_TYPE_HOSTNAME
	case "path":
		return pm.VariableType_VARIABLE_TYPE_PATH
	case "choice":
		return pm.VariableType_VARIABLE_TYPE_CHOICE
	case "secret":
		return pm.VariableType_VARIABLE_TYPE_SECRET
	default:
		return pm.VariableType_VARIABLE_TYPE_UNSPECIFIED
	}
}
