package payloads

// SCIMGroupMapped is the wire shape for SCIMGroupMapped — a SCIM
// provider group bound to a local user group. The projector UPSERTs
// the mapping row keyed by (provider_id, scim_group_id). The pointer
// SCIMDisplayName preserves the decoder's absent-vs-empty distinction
// (absent defaults to ""); emit sites always set it.
type SCIMGroupMapped struct {
	ProviderID      string  `json:"provider_id"`
	SCIMGroupID     string  `json:"scim_group_id"`
	SCIMDisplayName *string `json:"scim_display_name,omitempty"`
	UserGroupID     string  `json:"user_group_id"`
}

// SCIMGroupUnmapped is the wire shape for SCIMGroupUnmapped — the
// composite key of the mapping row the projector deletes.
type SCIMGroupUnmapped struct {
	ProviderID  string `json:"provider_id"`
	SCIMGroupID string `json:"scim_group_id"`
}

// SCIMGroupMappingUpdated is the wire shape for SCIMGroupMappingUpdated.
// Only the display name is updatable; the pointer signals update
// (non-nil, including "") vs preserve (nil → COALESCE keeps existing).
type SCIMGroupMappingUpdated struct {
	ProviderID      string  `json:"provider_id"`
	SCIMGroupID     string  `json:"scim_group_id"`
	SCIMDisplayName *string `json:"scim_display_name,omitempty"`
}
