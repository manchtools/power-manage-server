package projectors

import (
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// defaultDeviceGroupMaintenanceWindow mirrors the PL/pgSQL projector's
// COALESCE fallback against `'{}'::JSONB` for missing maintenance_window
// payloads. Held as a byte slice so the listener can pass it straight to
// the JSONB column without an extra marshal step.
var defaultDeviceGroupMaintenanceWindow = []byte(`{}`)

// DeviceGroupCreatedPayload mirrors the fields the deleted PL/pgSQL
// project_device_group_event() read out of a DeviceGroupCreated event:
//
//   - name (required, NOT NULL column)
//   - description (defaults to "" to match the PL/pgSQL
//     `COALESCE(payload, "")` behaviour)
//   - is_dynamic (defaults to FALSE to match the PL/pgSQL COALESCE
//     fallback against the BOOLEAN column default)
//   - dynamic_query (nullable; nil when the payload omits the key, or
//     when the value is JSON null — matches the PL/pgSQL
//     `event.data->>'dynamic_query'` which yields SQL NULL for both)
type DeviceGroupCreatedPayload struct {
	ID           string
	Name         string
	Description  string
	IsDynamic    bool
	DynamicQuery *string
	CreatedBy    string
}

type deviceGroupCreatedRaw struct {
	Name         string  `json:"name"`
	Description  *string `json:"description,omitempty"`
	IsDynamic    *bool   `json:"is_dynamic,omitempty"`
	DynamicQuery *string `json:"dynamic_query,omitempty"`
}

// DeviceGroupCreatedFromEvent decodes DeviceGroupCreated. Returns
// ErrIgnoredEvent for any other (stream, event_type) so the listener
// wrapper can silently no-op.
//
// name is required because the underlying NOT NULL column would
// otherwise fail the INSERT, surfacing as a Postgres constraint
// violation rather than a projector-level validation error.
func DeviceGroupCreatedFromEvent(e store.PersistedEvent) (DeviceGroupCreatedPayload, error) {
	raw, err := decodePayload[deviceGroupCreatedRaw](e, "device_group", eventtypes.DeviceGroupCreated)
	if err != nil {
		return DeviceGroupCreatedPayload{}, err
	}
	if raw.Name == "" {
		return DeviceGroupCreatedPayload{}, fmt.Errorf("projector: DeviceGroupCreated requires name")
	}
	out := DeviceGroupCreatedPayload{
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

// DeviceGroupRenamedPayload covers the single mutable field the
// PL/pgSQL projector wrote on DeviceGroupRenamed. Empty Name is
// treated as a validation error rather than silently no-op'd — the
// PL/pgSQL projector would have written NULL and broken the NOT NULL
// constraint, so emitters that drop the field hit the same error
// class either way.
type DeviceGroupRenamedPayload struct {
	ID   string
	Name string
}

type deviceGroupRenamedRaw struct {
	Name string `json:"name"`
}

// DeviceGroupRenamedFromEvent decodes DeviceGroupRenamed.
func DeviceGroupRenamedFromEvent(e store.PersistedEvent) (DeviceGroupRenamedPayload, error) {
	raw, err := decodePayload[deviceGroupRenamedRaw](e, "device_group", eventtypes.DeviceGroupRenamed)
	if err != nil {
		return DeviceGroupRenamedPayload{}, err
	}
	if raw.Name == "" {
		return DeviceGroupRenamedPayload{}, fmt.Errorf("projector: DeviceGroupRenamed requires name")
	}
	return DeviceGroupRenamedPayload{ID: e.StreamID, Name: raw.Name}, nil
}

// DeviceGroupDescriptionUpdatedPayload mirrors the PL/pgSQL projector's
// `COALESCE(event.data->>'description', "")` collapse: if the payload
// omits the key OR sends an explicit empty string, the description
// becomes "". Both cases land here as Description == "".
type DeviceGroupDescriptionUpdatedPayload struct {
	ID          string
	Description string
}

type deviceGroupDescriptionUpdatedRaw struct {
	Description *string `json:"description,omitempty"`
}

// DeviceGroupDescriptionUpdatedFromEvent decodes
// DeviceGroupDescriptionUpdated. An empty payload (e.g. `{}`) maps to
// Description == "", matching the PL/pgSQL COALESCE-to-empty-string
// behaviour.
func DeviceGroupDescriptionUpdatedFromEvent(e store.PersistedEvent) (DeviceGroupDescriptionUpdatedPayload, error) {
	if e.StreamType != "device_group" || e.EventType != string(eventtypes.DeviceGroupDescriptionUpdated) {
		return DeviceGroupDescriptionUpdatedPayload{}, ErrIgnoredEvent
	}
	out := DeviceGroupDescriptionUpdatedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw deviceGroupDescriptionUpdatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceGroupDescriptionUpdatedPayload{}, fmt.Errorf("projector: invalid DeviceGroupDescriptionUpdated payload: %w", err)
	}
	if raw.Description != nil {
		out.Description = *raw.Description
	}
	return out, nil
}

// DeviceGroupQueryUpdatedPayload mirrors the PL/pgSQL projector's
// dynamic-query toggle. is_dynamic defaults to FALSE when missing
// (matches `COALESCE((event.data->>'is_dynamic')::BOOLEAN, FALSE)`);
// dynamic_query is nullable.
type DeviceGroupQueryUpdatedPayload struct {
	ID           string
	IsDynamic    bool
	DynamicQuery *string
}

type deviceGroupQueryUpdatedRaw struct {
	IsDynamic    *bool   `json:"is_dynamic,omitempty"`
	DynamicQuery *string `json:"dynamic_query,omitempty"`
}

// DeviceGroupQueryUpdatedFromEvent decodes DeviceGroupQueryUpdated.
func DeviceGroupQueryUpdatedFromEvent(e store.PersistedEvent) (DeviceGroupQueryUpdatedPayload, error) {
	if e.StreamType != "device_group" || e.EventType != string(eventtypes.DeviceGroupQueryUpdated) {
		return DeviceGroupQueryUpdatedPayload{}, ErrIgnoredEvent
	}
	out := DeviceGroupQueryUpdatedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw deviceGroupQueryUpdatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceGroupQueryUpdatedPayload{}, fmt.Errorf("projector: invalid DeviceGroupQueryUpdated payload: %w", err)
	}
	if raw.IsDynamic != nil {
		out.IsDynamic = *raw.IsDynamic
	}
	out.DynamicQuery = raw.DynamicQuery
	return out, nil
}

// DeviceGroupSyncIntervalSetPayload mirrors the PL/pgSQL projector's
// `COALESCE((event.data->>'sync_interval_minutes')::INTEGER, 0)` —
// missing key collapses to 0.
type DeviceGroupSyncIntervalSetPayload struct {
	ID                  string
	SyncIntervalMinutes int32
}

type deviceGroupSyncIntervalSetRaw struct {
	SyncIntervalMinutes *int32 `json:"sync_interval_minutes,omitempty"`
}

// DeviceGroupSyncIntervalSetFromEvent decodes DeviceGroupSyncIntervalSet.
func DeviceGroupSyncIntervalSetFromEvent(e store.PersistedEvent) (DeviceGroupSyncIntervalSetPayload, error) {
	if e.StreamType != "device_group" || e.EventType != string(eventtypes.DeviceGroupSyncIntervalSet) {
		return DeviceGroupSyncIntervalSetPayload{}, ErrIgnoredEvent
	}
	out := DeviceGroupSyncIntervalSetPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw deviceGroupSyncIntervalSetRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceGroupSyncIntervalSetPayload{}, fmt.Errorf("projector: invalid DeviceGroupSyncIntervalSet payload: %w", err)
	}
	if raw.SyncIntervalMinutes != nil {
		out.SyncIntervalMinutes = *raw.SyncIntervalMinutes
	}
	return out, nil
}

// DeviceGroupInventoryIntervalSetPayload is the decoded per-group
// inventory-collection interval (spec 22) — a missing key collapses
// to 0, matching the sync-interval decoder.
type DeviceGroupInventoryIntervalSetPayload struct {
	ID                       string
	InventoryIntervalMinutes int32
}

type deviceGroupInventoryIntervalSetRaw struct {
	InventoryIntervalMinutes *int32 `json:"inventory_interval_minutes,omitempty"`
}

// DeviceGroupInventoryIntervalSetFromEvent decodes DeviceGroupInventoryIntervalSet.
func DeviceGroupInventoryIntervalSetFromEvent(e store.PersistedEvent) (DeviceGroupInventoryIntervalSetPayload, error) {
	if e.StreamType != "device_group" || e.EventType != string(eventtypes.DeviceGroupInventoryIntervalSet) {
		return DeviceGroupInventoryIntervalSetPayload{}, ErrIgnoredEvent
	}
	out := DeviceGroupInventoryIntervalSetPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw deviceGroupInventoryIntervalSetRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceGroupInventoryIntervalSetPayload{}, fmt.Errorf("projector: invalid DeviceGroupInventoryIntervalSet payload: %w", err)
	}
	if raw.InventoryIntervalMinutes != nil {
		out.InventoryIntervalMinutes = *raw.InventoryIntervalMinutes
	}
	return out, nil
}

// DeviceGroupMaintenanceWindowSetPayload mirrors the PL/pgSQL
// projector's `COALESCE(event.data->'maintenance_window', '{}'::JSONB)`
// fallback. A missing key collapses to '{}' (held as raw bytes so the
// listener writes the same JSONB shape the PL/pgSQL projector would
// have produced).
type DeviceGroupMaintenanceWindowSetPayload struct {
	ID                string
	MaintenanceWindow []byte
}

type deviceGroupMaintenanceWindowSetRaw struct {
	MaintenanceWindow json.RawMessage `json:"maintenance_window,omitempty"`
}

// DeviceGroupMaintenanceWindowSetFromEvent decodes
// DeviceGroupMaintenanceWindowSet.
func DeviceGroupMaintenanceWindowSetFromEvent(e store.PersistedEvent) (DeviceGroupMaintenanceWindowSetPayload, error) {
	if e.StreamType != "device_group" || e.EventType != string(eventtypes.DeviceGroupMaintenanceWindowSet) {
		return DeviceGroupMaintenanceWindowSetPayload{}, ErrIgnoredEvent
	}
	out := DeviceGroupMaintenanceWindowSetPayload{
		ID:                e.StreamID,
		MaintenanceWindow: defaultDeviceGroupMaintenanceWindow,
	}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw deviceGroupMaintenanceWindowSetRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceGroupMaintenanceWindowSetPayload{}, fmt.Errorf("projector: invalid DeviceGroupMaintenanceWindowSet payload: %w", err)
	}
	if len(raw.MaintenanceWindow) > 0 {
		// Preserve the wire bytes verbatim so the listener writes the
		// same JSONB the emitter sent (matches the PL/pgSQL projector's
		// `(event.data->'maintenance_window')::JSONB` cast).
		out.MaintenanceWindow = []byte(raw.MaintenanceWindow)
	}
	return out, nil
}

// DeviceGroupMemberPayload covers DeviceGroupMemberAdded /
// DeviceAddedToGroup and DeviceGroupMemberRemoved / DeviceRemovedFromGroup.
// All four event names share the same payload shape; the listener
// distinguishes add vs remove by event_type at dispatch.
//
// device_id is required: the PL/pgSQL projector would have INSERTed
// NULL into the NOT NULL column otherwise, surfacing as a constraint
// violation. Pre-validating here keeps the failure surface inside the
// projector log instead of leaking through as a Postgres error.
type DeviceGroupMemberPayload struct {
	GroupID  string
	DeviceID string
}

type deviceGroupMemberRaw struct {
	DeviceID string `json:"device_id"`
}

// DeviceGroupMemberAddedFromEvent decodes the add-side member event.
// Both 'DeviceGroupMemberAdded' and 'DeviceAddedToGroup' are accepted —
// the PL/pgSQL projector handled them in the same WHEN branch and the
// in-flight payload shapes are identical. Treat them as aliases.
func DeviceGroupMemberAddedFromEvent(e store.PersistedEvent) (DeviceGroupMemberPayload, error) {
	if e.StreamType != "device_group" {
		return DeviceGroupMemberPayload{}, ErrIgnoredEvent
	}
	if e.EventType != string(eventtypes.DeviceGroupMemberAdded) && e.EventType != string(eventtypes.DeviceAddedToGroup) {
		return DeviceGroupMemberPayload{}, ErrIgnoredEvent
	}
	return decodeDeviceGroupMember(e)
}

// DeviceGroupMemberRemovedFromEvent decodes the remove-side member event.
// Both 'DeviceGroupMemberRemoved' and 'DeviceRemovedFromGroup' are
// accepted as aliases — same WHEN branch in the PL/pgSQL projector.
func DeviceGroupMemberRemovedFromEvent(e store.PersistedEvent) (DeviceGroupMemberPayload, error) {
	if e.StreamType != "device_group" {
		return DeviceGroupMemberPayload{}, ErrIgnoredEvent
	}
	if e.EventType != string(eventtypes.DeviceGroupMemberRemoved) && e.EventType != string(eventtypes.DeviceRemovedFromGroup) {
		return DeviceGroupMemberPayload{}, ErrIgnoredEvent
	}
	return decodeDeviceGroupMember(e)
}

func decodeDeviceGroupMember(e store.PersistedEvent) (DeviceGroupMemberPayload, error) {
	if len(e.Data) == 0 {
		return DeviceGroupMemberPayload{}, fmt.Errorf("projector: empty %s payload", e.EventType)
	}
	var raw deviceGroupMemberRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return DeviceGroupMemberPayload{}, fmt.Errorf("projector: invalid %s payload: %w", e.EventType, err)
	}
	if raw.DeviceID == "" {
		return DeviceGroupMemberPayload{}, fmt.Errorf("projector: %s requires device_id", e.EventType)
	}
	return DeviceGroupMemberPayload{GroupID: e.StreamID, DeviceID: raw.DeviceID}, nil
}
