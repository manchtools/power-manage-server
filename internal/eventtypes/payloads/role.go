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

// UserRoleAssigned is the wire shape for UserRoleAssigned. UserID
// and RoleID are required — they are the composite-key columns of
// the user_roles_projection row this event projects.
//
// ScopeKind and ScopeID are paired optional fields added in
// server #7 S2. Both nil means an unscoped/global grant
// (backward-compatible with every pre-#7 event). Both populated
// means the grant is constrained to the named group. Half-set is
// invalid and rejected by the projector and the DB CHECK.
// Pointer types preserve the absent-vs-empty distinction across
// JSON round-trips so the projector can tell a legacy event from
// one with an intentionally-empty scope value.
type UserRoleAssigned struct {
	UserID    string  `json:"user_id"`
	RoleID    string  `json:"role_id"`
	ScopeKind *string `json:"scope_kind,omitempty"`
	ScopeID   *string `json:"scope_id,omitempty"`
}

// UserRoleRevoked is the wire shape for UserRoleRevoked. Same
// composite-key shape as UserRoleAssigned plus the optional
// (ScopeKind, ScopeID) pair from #7 S5's 4-tuple revoke grammar.
// Both nil = revoke the unscoped grant; both set = revoke the
// matching scoped grant. The projector dispatches via
// IS NOT DISTINCT FROM.
type UserRoleRevoked struct {
	UserID    string  `json:"user_id"`
	RoleID    string  `json:"role_id"`
	ScopeKind *string `json:"scope_kind,omitempty"`
	ScopeID   *string `json:"scope_id,omitempty"`
}
