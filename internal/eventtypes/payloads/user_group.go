package payloads

// UserGroupCreated is the wire shape for UserGroupCreated. Mirrors the
// emit-site map key set verbatim. Description / IsDynamic /
// DynamicQuery are always emitted (the handler reads them off
// req.Msg.* without conditional omission); the projector decoder uses
// pointer fields with omitempty when it needs preserve semantics, but
// the wire shape simply round-trips whatever the handler sent.
type UserGroupCreated struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	IsDynamic    bool   `json:"is_dynamic"`
	DynamicQuery string `json:"dynamic_query"`
}

// UserGroupUpdated is the wire shape for UserGroupUpdated. Same
// always-emit semantics as UserGroupCreated.
type UserGroupUpdated struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// UserGroupMaintenanceWindowSet is the wire shape for the
// MaintenanceWindowSet event. The maintenance_window value mirrors
// the JSONB shape produced by maintenanceWindowToMap on the handler
// side — keep it as a map[string]any so the wire bytes are identical
// to the historical Data: map[string]any{} payload and the projector
// continues to read it through its existing JSONB->struct path.
type UserGroupMaintenanceWindowSet struct {
	MaintenanceWindow map[string]any `json:"maintenance_window"`
}

// UserGroupMemberAdded / UserGroupMemberRemoved share the same
// (group_id, user_id) composite-key shape — the listener writes /
// deletes the matching membership row.
type UserGroupMemberAdded struct {
	GroupID string `json:"group_id"`
	UserID  string `json:"user_id"`
}

type UserGroupMemberRemoved struct {
	GroupID string `json:"group_id"`
	UserID  string `json:"user_id"`
}

// UserGroupRoleAssigned / UserGroupRoleRevoked share the same
// (group_id, role_id) composite-key shape plus the optional scope
// tuple added in server #7 S2 / S5 (paired-or-neither, both nil =
// unscoped grant for backward compat).
type UserGroupRoleAssigned struct {
	GroupID   string  `json:"group_id"`
	RoleID    string  `json:"role_id"`
	ScopeKind *string `json:"scope_kind,omitempty"`
	ScopeID   *string `json:"scope_id,omitempty"`
}

type UserGroupRoleRevoked struct {
	GroupID   string  `json:"group_id"`
	RoleID    string  `json:"role_id"`
	ScopeKind *string `json:"scope_kind,omitempty"`
	ScopeID   *string `json:"scope_id,omitempty"`
}

// UserGroupQueryUpdated toggles a static group to dynamic (or back).
// Both fields are always emitted to mirror the historical map[string]any{}
// shape.
type UserGroupQueryUpdated struct {
	IsDynamic    bool   `json:"is_dynamic"`
	DynamicQuery string `json:"dynamic_query"`
}
