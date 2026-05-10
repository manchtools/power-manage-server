package payloads

// RoleCreated is the wire shape for RoleCreated. Mirrors the legacy
// emit-site map key set verbatim:
//
//   - name (required, NOT NULL on roles_projection)
//   - description (always emitted; empty string is "set to empty",
//     NOT "preserve" — see internal/projectors/role.go)
//   - permissions (always emitted; empty slice is "set to empty")
//   - is_system (always emitted; the legacy emit hardcoded false on
//     the user-facing CreateRole RPC — system roles are seeded via
//     migrations, not this RPC)
//
// The projector decoder uses pointer fields to detect "missing", so
// keeping the JSON keys present (no omitempty on the never-omitted
// fields) preserves the exact PL/pgSQL `COALESCE(payload, existing)`
// fall-through that historical events relied on.
type RoleCreated struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	IsSystem    bool     `json:"is_system"`
}

// RoleUpdated is the wire shape for RoleUpdated. Same emit-site
// contract as RoleCreated minus is_system (system roles' name +
// permissions are protected at the handler layer; the projector
// has no special-case for system roles on Update). All three fields
// are always present on the wire — the projector applies the
// COALESCE/NULLIF preserve semantics off pointer-vs-empty distinctions
// that arise when downstream consumers replay older payloads.
type RoleUpdated struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

// UserRoleAssigned is the wire shape for UserRoleAssigned. Both
// fields are required — they are the composite-key columns of the
// user_roles_projection row this event projects.
type UserRoleAssigned struct {
	UserID string `json:"user_id"`
	RoleID string `json:"role_id"`
}

// UserRoleRevoked is the wire shape for UserRoleRevoked. Same
// composite-key shape as UserRoleAssigned; the projector deletes the
// matching row.
type UserRoleRevoked struct {
	UserID string `json:"user_id"`
	RoleID string `json:"role_id"`
}
