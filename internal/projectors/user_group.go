package projectors

import (
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// defaultUserGroupMaintenanceWindow mirrors the PL/pgSQL projector's
// COALESCE fallback against `'{}'::JSONB` for missing maintenance_window
// payloads. Held as a byte slice so the listener can pass it straight to
// the JSONB column without an extra marshal step.
var defaultUserGroupMaintenanceWindow = []byte(`{}`)

// UserGroupCreatedPayload mirrors the fields the deleted PL/pgSQL
// project_user_group_event() read out of a UserGroupCreated event:
//
//   - name (required, NOT NULL column)
//   - description (defaults to "" to match the PL/pgSQL
//     `COALESCE(payload, "")` behaviour)
//   - is_dynamic (defaults to FALSE to match the PL/pgSQL COALESCE
//     fallback against the BOOLEAN column default)
//   - dynamic_query (nullable; nil when the payload omits the key, or
//     when the value is JSON null — matches the PL/pgSQL
//     `event.data->>'dynamic_query'` which yields SQL NULL for both)
type UserGroupCreatedPayload struct {
	ID           string
	Name         string
	Description  string
	IsDynamic    bool
	DynamicQuery *string
	CreatedBy    string
}

type userGroupCreatedRaw struct {
	Name         string  `json:"name"`
	Description  *string `json:"description,omitempty"`
	IsDynamic    *bool   `json:"is_dynamic,omitempty"`
	DynamicQuery *string `json:"dynamic_query,omitempty"`
}

// UserGroupCreatedFromEvent decodes UserGroupCreated. Returns
// ErrIgnoredEvent for any other (stream, event_type) so the listener
// wrapper can silently no-op.
//
// name is required because the underlying NOT NULL column would
// otherwise fail the INSERT, surfacing as a Postgres constraint
// violation rather than a projector-level validation error.
func UserGroupCreatedFromEvent(e store.PersistedEvent) (UserGroupCreatedPayload, error) {
	raw, err := decodePayload[userGroupCreatedRaw](e, "user_group", eventtypes.UserGroupCreated)
	if err != nil {
		return UserGroupCreatedPayload{}, err
	}
	if raw.Name == "" {
		return UserGroupCreatedPayload{}, fmt.Errorf("projector: UserGroupCreated requires name")
	}
	out := UserGroupCreatedPayload{
		ID:           e.StreamID,
		Name:         raw.Name,
		DynamicQuery: raw.DynamicQuery,
		CreatedBy:    e.ActorID,
	}
	if raw.Description != nil {
		out.Description = *raw.Description
	}
	if raw.IsDynamic != nil {
		out.IsDynamic = *raw.IsDynamic
	}
	return out, nil
}

// UserGroupUpdatedPayload distinguishes "field present" from "field
// omitted" via a pointer for Description, mirroring the PL/pgSQL
// COALESCE semantics:
//
//   - Name: always present and required (matches the PL/pgSQL
//     `name = event.data->>'name'` direct assignment, which would NULL
//     the column on a missing key — we surface that as a validation
//     error one layer earlier).
//   - Description: present (incl. empty string) → update; missing →
//     keep existing (PL/pgSQL `COALESCE(payload, description)`).
type UserGroupUpdatedPayload struct {
	ID          string
	Name        string
	Description *string
}

type userGroupUpdatedRaw struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

// UserGroupUpdatedFromEvent decodes UserGroupUpdated. The pointer
// Description signals "update" vs "preserve": non-nil = update with
// the value (incl. empty string); nil = preserve.
func UserGroupUpdatedFromEvent(e store.PersistedEvent) (UserGroupUpdatedPayload, error) {
	raw, err := decodePayload[userGroupUpdatedRaw](e, "user_group", eventtypes.UserGroupUpdated)
	if err != nil {
		return UserGroupUpdatedPayload{}, err
	}
	if raw.Name == "" {
		return UserGroupUpdatedPayload{}, fmt.Errorf("projector: UserGroupUpdated requires name")
	}
	return UserGroupUpdatedPayload{
		ID:          e.StreamID,
		Name:        raw.Name,
		Description: raw.Description,
	}, nil
}

// UserGroupQueryUpdatedPayload mirrors the PL/pgSQL projector's
// dynamic-query toggle. is_dynamic defaults to FALSE when missing
// (matches `COALESCE((event.data->>'is_dynamic')::BOOLEAN, FALSE)`);
// dynamic_query is nullable.
type UserGroupQueryUpdatedPayload struct {
	ID           string
	IsDynamic    bool
	DynamicQuery *string
}

type userGroupQueryUpdatedRaw struct {
	IsDynamic    *bool   `json:"is_dynamic,omitempty"`
	DynamicQuery *string `json:"dynamic_query,omitempty"`
}

// UserGroupQueryUpdatedFromEvent decodes UserGroupQueryUpdated.
func UserGroupQueryUpdatedFromEvent(e store.PersistedEvent) (UserGroupQueryUpdatedPayload, error) {
	if e.StreamType != "user_group" || e.EventType != string(eventtypes.UserGroupQueryUpdated) {
		return UserGroupQueryUpdatedPayload{}, ErrIgnoredEvent
	}
	out := UserGroupQueryUpdatedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw userGroupQueryUpdatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return UserGroupQueryUpdatedPayload{}, fmt.Errorf("projector: invalid UserGroupQueryUpdated payload: %w", err)
	}
	if raw.IsDynamic != nil {
		out.IsDynamic = *raw.IsDynamic
	}
	out.DynamicQuery = raw.DynamicQuery
	return out, nil
}

// UserGroupMaintenanceWindowSetPayload mirrors the PL/pgSQL
// projector's `COALESCE(event.data->'maintenance_window', '{}'::JSONB)`
// fallback. A missing key collapses to '{}' (held as raw bytes so the
// listener writes the same JSONB shape the PL/pgSQL projector would
// have produced).
type UserGroupMaintenanceWindowSetPayload struct {
	ID                string
	MaintenanceWindow []byte
}

type userGroupMaintenanceWindowSetRaw struct {
	MaintenanceWindow json.RawMessage `json:"maintenance_window,omitempty"`
}

// UserGroupMaintenanceWindowSetFromEvent decodes
// UserGroupMaintenanceWindowSet.
func UserGroupMaintenanceWindowSetFromEvent(e store.PersistedEvent) (UserGroupMaintenanceWindowSetPayload, error) {
	if e.StreamType != "user_group" || e.EventType != string(eventtypes.UserGroupMaintenanceWindowSet) {
		return UserGroupMaintenanceWindowSetPayload{}, ErrIgnoredEvent
	}
	out := UserGroupMaintenanceWindowSetPayload{
		ID:                e.StreamID,
		MaintenanceWindow: defaultUserGroupMaintenanceWindow,
	}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw userGroupMaintenanceWindowSetRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return UserGroupMaintenanceWindowSetPayload{}, fmt.Errorf("projector: invalid UserGroupMaintenanceWindowSet payload: %w", err)
	}
	if len(raw.MaintenanceWindow) > 0 {
		// Preserve the wire bytes verbatim so the listener writes the
		// same JSONB the emitter sent (matches the PL/pgSQL projector's
		// `(event.data->'maintenance_window')::JSONB` cast).
		out.MaintenanceWindow = []byte(raw.MaintenanceWindow)
	}
	return out, nil
}

// UserGroupMemberPayload covers UserGroupMemberAdded and
// UserGroupMemberRemoved. Both events carry the same (group_id, user_id)
// pair; the listener distinguishes the two by event_type at dispatch.
//
// The group_id payload field exists because the PL/pgSQL projector
// indexed off `event.data->>'group_id'` instead of the stream id —
// preserve that semantics here. group_id and user_id are required
// because the underlying NOT NULL columns would otherwise fail the
// INSERT (or no-op the DELETE silently in a misleading way).
type UserGroupMemberPayload struct {
	GroupID string
	UserID  string
}

type userGroupMemberRaw struct {
	GroupID string `json:"group_id"`
	UserID  string `json:"user_id"`
}

// UserGroupMemberAddedFromEvent decodes UserGroupMemberAdded.
func UserGroupMemberAddedFromEvent(e store.PersistedEvent) (UserGroupMemberPayload, error) {
	if e.StreamType != "user_group" || e.EventType != string(eventtypes.UserGroupMemberAdded) {
		return UserGroupMemberPayload{}, ErrIgnoredEvent
	}
	return decodeUserGroupMember(e, "UserGroupMemberAdded")
}

// UserGroupMemberRemovedFromEvent decodes UserGroupMemberRemoved.
func UserGroupMemberRemovedFromEvent(e store.PersistedEvent) (UserGroupMemberPayload, error) {
	if e.StreamType != "user_group" || e.EventType != string(eventtypes.UserGroupMemberRemoved) {
		return UserGroupMemberPayload{}, ErrIgnoredEvent
	}
	return decodeUserGroupMember(e, "UserGroupMemberRemoved")
}

func decodeUserGroupMember(e store.PersistedEvent, eventName string) (UserGroupMemberPayload, error) {
	if len(e.Data) == 0 {
		return UserGroupMemberPayload{}, fmt.Errorf("projector: empty %s payload", eventName)
	}
	var raw userGroupMemberRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return UserGroupMemberPayload{}, fmt.Errorf("projector: invalid %s payload: %w", eventName, err)
	}
	switch {
	case raw.GroupID == "":
		return UserGroupMemberPayload{}, fmt.Errorf("projector: %s requires group_id", eventName)
	case raw.UserID == "":
		return UserGroupMemberPayload{}, fmt.Errorf("projector: %s requires user_id", eventName)
	}
	return UserGroupMemberPayload(raw), nil
}

// UserGroupRolePayload covers UserGroupRoleAssigned and
// UserGroupRoleRevoked. Both events carry the same (group_id, role_id)
// pair from the payload, plus the optional (ScopeKind, ScopeID)
// tuple from server #7 S2 / S5 for scoped grants and the 4-tuple
// revoke grammar.
type UserGroupRolePayload struct {
	GroupID   string
	RoleID    string
	ScopeKind *string
	ScopeID   *string
}

type userGroupRoleRaw struct {
	GroupID   string  `json:"group_id"`
	RoleID    string  `json:"role_id"`
	ScopeKind *string `json:"scope_kind,omitempty"`
	ScopeID   *string `json:"scope_id,omitempty"`
}

// UserGroupRoleAssignedFromEvent decodes UserGroupRoleAssigned.
func UserGroupRoleAssignedFromEvent(e store.PersistedEvent) (UserGroupRolePayload, error) {
	if e.StreamType != "user_group" || e.EventType != string(eventtypes.UserGroupRoleAssigned) {
		return UserGroupRolePayload{}, ErrIgnoredEvent
	}
	return decodeUserGroupRole(e, "UserGroupRoleAssigned")
}

// UserGroupRoleRevokedFromEvent decodes UserGroupRoleRevoked.
func UserGroupRoleRevokedFromEvent(e store.PersistedEvent) (UserGroupRolePayload, error) {
	if e.StreamType != "user_group" || e.EventType != string(eventtypes.UserGroupRoleRevoked) {
		return UserGroupRolePayload{}, ErrIgnoredEvent
	}
	return decodeUserGroupRole(e, "UserGroupRoleRevoked")
}

func decodeUserGroupRole(e store.PersistedEvent, eventName string) (UserGroupRolePayload, error) {
	if len(e.Data) == 0 {
		return UserGroupRolePayload{}, fmt.Errorf("projector: empty %s payload", eventName)
	}
	var raw userGroupRoleRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return UserGroupRolePayload{}, fmt.Errorf("projector: invalid %s payload: %w", eventName, err)
	}
	switch {
	case raw.GroupID == "":
		return UserGroupRolePayload{}, fmt.Errorf("projector: %s requires group_id", eventName)
	case raw.RoleID == "":
		return UserGroupRolePayload{}, fmt.Errorf("projector: %s requires role_id", eventName)
	}
	if err := validateScopePair(raw.ScopeKind, raw.ScopeID, eventName); err != nil {
		return UserGroupRolePayload{}, err
	}
	return UserGroupRolePayload(raw), nil
}

// UserGroupMembersRebuiltPayload mirrors the PL/pgSQL projector's
// jsonb-array-to-rows expansion of `event.data->'user_ids'`. Missing
// or empty user_ids collapses to an empty slice (the projector's
// `jsonb_array_length(... 'user_ids') -> 0` fallback). UserGroupMembersRebuilt
// is not currently emitted (no caller in api/ or scim/) but the
// PL/pgSQL projector handled it; the Go listener keeps parity so any
// historical events in production event stores still replay cleanly
// during a rebuild.
type UserGroupMembersRebuiltPayload struct {
	GroupID string
	UserIDs []string
}

type userGroupMembersRebuiltRaw struct {
	UserIDs []string `json:"user_ids,omitempty"`
}

// UserGroupMembersRebuiltFromEvent decodes UserGroupMembersRebuilt.
func UserGroupMembersRebuiltFromEvent(e store.PersistedEvent) (UserGroupMembersRebuiltPayload, error) {
	if e.StreamType != "user_group" || e.EventType != string(eventtypes.UserGroupMembersRebuilt) {
		return UserGroupMembersRebuiltPayload{}, ErrIgnoredEvent
	}
	out := UserGroupMembersRebuiltPayload{GroupID: e.StreamID, UserIDs: []string{}}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw userGroupMembersRebuiltRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return UserGroupMembersRebuiltPayload{}, fmt.Errorf("projector: invalid UserGroupMembersRebuilt payload: %w", err)
	}
	if raw.UserIDs != nil {
		out.UserIDs = raw.UserIDs
	}
	return out, nil
}
