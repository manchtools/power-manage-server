package projectors

import (
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// RoleCreatedPayload represents the decoded shape of a RoleCreated
// event. The deleted PL/pgSQL projector applied COALESCE defaults
// for description (""), permissions ('{}'), and is_system (FALSE);
// the Go decoder mirrors via zero values + an explicit empty slice
// so the listener can pass them through unchanged.
type RoleCreatedPayload struct {
	ID          string
	Name        string
	Description string
	Permissions []string
	IsSystem    bool
	CreatedBy   string
}

// RoleUpdatedPayload distinguishes "field present" from "field
// omitted" via pointers, mirroring the PL/pgSQL COALESCE/NULLIF
// semantics:
//
//   - Name: present-with-value → update; missing OR empty-string →
//     keep existing (PL/pgSQL `COALESCE(NULLIF(payload, ""), existing)`).
//   - Description: present (incl. empty string) → update; missing →
//     keep (PL/pgSQL `COALESCE(payload, existing)`).
//   - Permissions: present (incl. empty array) → update; missing →
//     keep (PL/pgSQL array COALESCE).
//
// The decoder collapses an empty Name to nil so the listener can
// treat both "missing" and "explicit empty" as "no update" at the
// SQL layer with a single `COALESCE($name, name)` call.
type RoleUpdatedPayload struct {
	ID          string
	Name        *string
	Description *string
	Permissions *[]string
}

// roleCreatedRaw mirrors the JSON shape; conversion to the typed
// payload below applies the COALESCE defaults so callers get a
// fully-populated struct.
type roleCreatedRaw struct {
	Name        string    `json:"name"`
	Description *string   `json:"description,omitempty"`
	Permissions *[]string `json:"permissions,omitempty"`
	IsSystem    *bool     `json:"is_system,omitempty"`
}

// RoleCreatedFromEvent decodes RoleCreated. Returns ErrIgnoredEvent
// for any other (stream, event_type) so the listener wrapper can
// silently no-op.
//
// Defaults match the PL/pgSQL projector: missing description → "";
// missing permissions → empty slice; missing is_system → false.
func RoleCreatedFromEvent(e store.PersistedEvent) (RoleCreatedPayload, error) {
	if e.StreamType != "role" || e.EventType != string(eventtypes.RoleCreated) {
		return RoleCreatedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return RoleCreatedPayload{}, fmt.Errorf("projector: empty RoleCreated payload")
	}
	var raw roleCreatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return RoleCreatedPayload{}, fmt.Errorf("projector: invalid RoleCreated payload: %w", err)
	}
	if raw.Name == "" {
		return RoleCreatedPayload{}, fmt.Errorf("projector: RoleCreated requires name")
	}
	out := RoleCreatedPayload{
		ID:          e.StreamID,
		Name:        raw.Name,
		Permissions: []string{},
		CreatedBy:   e.ActorID,
	}
	if raw.Description != nil {
		out.Description = *raw.Description
	}
	if raw.Permissions != nil {
		out.Permissions = *raw.Permissions
	}
	if raw.IsSystem != nil {
		out.IsSystem = *raw.IsSystem
	}
	return out, nil
}

// roleUpdatedRaw uses pointer fields so json.Unmarshal records
// "field present" vs "field omitted" — the difference matters because
// PL/pgSQL `COALESCE(payload, existing)` treats SQL NULL as missing
// (preserve existing), but treats explicit empty-string / empty-array
// as updates.
type roleUpdatedRaw struct {
	Name        *string   `json:"name,omitempty"`
	Description *string   `json:"description,omitempty"`
	Permissions *[]string `json:"permissions,omitempty"`
}

// RoleUpdatedFromEvent decodes RoleUpdated. The pointer fields on
// the returned payload signal "update" vs "preserve":
// non-nil = update; nil = preserve.
//
// Empty-string Name is collapsed to nil (preserve) to match the
// PL/pgSQL `NULLIF(name, "")` semantics — a UI that sends "" for
// the name field doesn't blank the role.
func RoleUpdatedFromEvent(e store.PersistedEvent) (RoleUpdatedPayload, error) {
	if e.StreamType != "role" || e.EventType != string(eventtypes.RoleUpdated) {
		return RoleUpdatedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return RoleUpdatedPayload{ID: e.StreamID}, nil
	}
	var raw roleUpdatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return RoleUpdatedPayload{}, fmt.Errorf("projector: invalid RoleUpdated payload: %w", err)
	}
	out := RoleUpdatedPayload{ID: e.StreamID}
	if raw.Name != nil && *raw.Name != "" {
		out.Name = raw.Name
	}
	out.Description = raw.Description
	out.Permissions = raw.Permissions
	return out, nil
}
