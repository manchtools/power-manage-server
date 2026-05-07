package projectors

import (
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
)

// SCIMGroupMappedPayload covers the upsert path. The PL/pgSQL
// projector required provider_id, scim_group_id, user_group_id and
// defaulted scim_display_name to "" (empty string).
type SCIMGroupMappedPayload struct {
	ID              string
	ProviderID      string
	SCIMGroupID     string
	SCIMDisplayName string
	UserGroupID     string
}

// SCIMGroupUnmappedPayload — composite key only.
type SCIMGroupUnmappedPayload struct {
	ProviderID  string
	SCIMGroupID string
}

// SCIMGroupMappingUpdatedPayload — only display_name is updatable.
// Pointer field distinguishes "field present" from "field omitted"
// so the SQL UPDATE can use COALESCE to preserve existing on omit.
type SCIMGroupMappingUpdatedPayload struct {
	ProviderID      string
	SCIMGroupID     string
	SCIMDisplayName *string
}

// SCIMGroupMappedFromEvent decodes SCIMGroupMapped.
func SCIMGroupMappedFromEvent(e store.PersistedEvent) (SCIMGroupMappedPayload, error) {
	if e.StreamType != "scim_group_mapping" || e.EventType != "SCIMGroupMapped" {
		return SCIMGroupMappedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return SCIMGroupMappedPayload{}, fmt.Errorf("projector: empty SCIMGroupMapped payload")
	}
	var raw struct {
		ProviderID      string  `json:"provider_id"`
		SCIMGroupID     string  `json:"scim_group_id"`
		SCIMDisplayName *string `json:"scim_display_name,omitempty"`
		UserGroupID     string  `json:"user_group_id"`
	}
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return SCIMGroupMappedPayload{}, fmt.Errorf("projector: invalid SCIMGroupMapped payload: %w", err)
	}
	switch {
	case raw.ProviderID == "":
		return SCIMGroupMappedPayload{}, fmt.Errorf("projector: SCIMGroupMapped requires provider_id")
	case raw.SCIMGroupID == "":
		return SCIMGroupMappedPayload{}, fmt.Errorf("projector: SCIMGroupMapped requires scim_group_id")
	case raw.UserGroupID == "":
		return SCIMGroupMappedPayload{}, fmt.Errorf("projector: SCIMGroupMapped requires user_group_id")
	}
	out := SCIMGroupMappedPayload{
		ID:          e.StreamID,
		ProviderID:  raw.ProviderID,
		SCIMGroupID: raw.SCIMGroupID,
		UserGroupID: raw.UserGroupID,
	}
	if raw.SCIMDisplayName != nil {
		out.SCIMDisplayName = *raw.SCIMDisplayName
	}
	return out, nil
}

// SCIMGroupUnmappedFromEvent decodes SCIMGroupUnmapped.
func SCIMGroupUnmappedFromEvent(e store.PersistedEvent) (SCIMGroupUnmappedPayload, error) {
	if e.StreamType != "scim_group_mapping" || e.EventType != "SCIMGroupUnmapped" {
		return SCIMGroupUnmappedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return SCIMGroupUnmappedPayload{}, fmt.Errorf("projector: empty SCIMGroupUnmapped payload")
	}
	var raw struct {
		ProviderID  string `json:"provider_id"`
		SCIMGroupID string `json:"scim_group_id"`
	}
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return SCIMGroupUnmappedPayload{}, fmt.Errorf("projector: invalid SCIMGroupUnmapped payload: %w", err)
	}
	switch {
	case raw.ProviderID == "":
		return SCIMGroupUnmappedPayload{}, fmt.Errorf("projector: SCIMGroupUnmapped requires provider_id")
	case raw.SCIMGroupID == "":
		return SCIMGroupUnmappedPayload{}, fmt.Errorf("projector: SCIMGroupUnmapped requires scim_group_id")
	}
	return SCIMGroupUnmappedPayload{ProviderID: raw.ProviderID, SCIMGroupID: raw.SCIMGroupID}, nil
}

// SCIMGroupMappingUpdatedFromEvent decodes SCIMGroupMappingUpdated.
// Only scim_display_name is updatable; pointer field preserves
// "missing → no update" via COALESCE.
func SCIMGroupMappingUpdatedFromEvent(e store.PersistedEvent) (SCIMGroupMappingUpdatedPayload, error) {
	if e.StreamType != "scim_group_mapping" || e.EventType != "SCIMGroupMappingUpdated" {
		return SCIMGroupMappingUpdatedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return SCIMGroupMappingUpdatedPayload{}, fmt.Errorf("projector: empty SCIMGroupMappingUpdated payload")
	}
	var raw struct {
		ProviderID      string  `json:"provider_id"`
		SCIMGroupID     string  `json:"scim_group_id"`
		SCIMDisplayName *string `json:"scim_display_name,omitempty"`
	}
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return SCIMGroupMappingUpdatedPayload{}, fmt.Errorf("projector: invalid SCIMGroupMappingUpdated payload: %w", err)
	}
	switch {
	case raw.ProviderID == "":
		return SCIMGroupMappingUpdatedPayload{}, fmt.Errorf("projector: SCIMGroupMappingUpdated requires provider_id")
	case raw.SCIMGroupID == "":
		return SCIMGroupMappingUpdatedPayload{}, fmt.Errorf("projector: SCIMGroupMappingUpdated requires scim_group_id")
	}
	return SCIMGroupMappingUpdatedPayload{
		ProviderID:      raw.ProviderID,
		SCIMGroupID:     raw.SCIMGroupID,
		SCIMDisplayName: raw.SCIMDisplayName,
	}, nil
}
