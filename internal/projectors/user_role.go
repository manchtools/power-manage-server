package projectors

import (
	"fmt"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// UserRoleAssignedPayload is the decoded shape of a UserRoleAssigned
// event. UserID and RoleID are required — they're the
// composite-key columns of the row this projector inserts.
// ScopeKind and ScopeID are paired optional (server #7 S2): both
// nil means an unscoped/global grant, both set means a scoped grant.
// Half-set is rejected at decode time as defense-in-depth on top
// of the DB CHECK constraint.
type UserRoleAssignedPayload struct {
	UserID     string  `json:"user_id"`
	RoleID     string  `json:"role_id"`
	ScopeKind  *string `json:"scope_kind,omitempty"`
	ScopeID    *string `json:"scope_id,omitempty"`
	AssignedBy string  // populated from event.actor_id, not the JSON payload
}

// UserRoleRevokedPayload mirrors the assigned shape — same
// composite-key requirements plus the optional scope tuple for the
// 4-tuple revoke grammar (server #7 S5).
type UserRoleRevokedPayload struct {
	UserID    string  `json:"user_id"`
	RoleID    string  `json:"role_id"`
	ScopeKind *string `json:"scope_kind,omitempty"`
	ScopeID   *string `json:"scope_id,omitempty"`
}

// UserRoleAssignedFromEvent decodes UserRoleAssigned. Returns
// ErrIgnoredEvent for any other (stream, event_type) so the listener
// wrapper can silently no-op.
func UserRoleAssignedFromEvent(e store.PersistedEvent) (UserRoleAssignedPayload, error) {
	p, err := decodePayload[UserRoleAssignedPayload](e, "user_role", eventtypes.UserRoleAssigned)
	if err != nil {
		return UserRoleAssignedPayload{}, err
	}
	switch {
	case p.UserID == "":
		return UserRoleAssignedPayload{}, fmt.Errorf("projector: UserRoleAssigned requires user_id")
	case p.RoleID == "":
		return UserRoleAssignedPayload{}, fmt.Errorf("projector: UserRoleAssigned requires role_id")
	}
	if err := validateScopePair(p.ScopeKind, p.ScopeID, "UserRoleAssigned"); err != nil {
		return UserRoleAssignedPayload{}, err
	}
	p.AssignedBy = e.ActorID
	return p, nil
}

// UserRoleRevokedFromEvent decodes UserRoleRevoked. Same validation
// shape as UserRoleAssigned — both composite-key fields required.
func UserRoleRevokedFromEvent(e store.PersistedEvent) (UserRoleRevokedPayload, error) {
	p, err := decodePayload[UserRoleRevokedPayload](e, "user_role", eventtypes.UserRoleRevoked)
	if err != nil {
		return UserRoleRevokedPayload{}, err
	}
	switch {
	case p.UserID == "":
		return UserRoleRevokedPayload{}, fmt.Errorf("projector: UserRoleRevoked requires user_id")
	case p.RoleID == "":
		return UserRoleRevokedPayload{}, fmt.Errorf("projector: UserRoleRevoked requires role_id")
	}
	if err := validateScopePair(p.ScopeKind, p.ScopeID, "UserRoleRevoked"); err != nil {
		return UserRoleRevokedPayload{}, err
	}
	return p, nil
}

// validateScopePair enforces the paired-or-neither + known-kind
// invariant on the (scope_kind, scope_id) tuple. Mirrors the DB
// CHECK constraints from migration 010 so a misbehaving emit-site
// can't slip a half-scoped event past the projector even if the
// DB layer is bypassed (e.g. raw event-store inspection). Empty-
// string scope values are treated as malformed: a present field
// must carry a non-empty string. server #7 S2 T-S3.
func validateScopePair(scopeKind, scopeID *string, eventName string) error {
	switch {
	case scopeKind == nil && scopeID == nil:
		return nil // unscoped grant — backward-compatible shape
	case scopeKind == nil && scopeID != nil:
		return fmt.Errorf("projector: %s carries scope_id without scope_kind (paired-or-neither)", eventName)
	case scopeKind != nil && scopeID == nil:
		return fmt.Errorf("projector: %s carries scope_kind without scope_id (paired-or-neither)", eventName)
	case *scopeKind == "":
		return fmt.Errorf("projector: %s carries an empty scope_kind", eventName)
	case *scopeID == "":
		return fmt.Errorf("projector: %s carries an empty scope_id", eventName)
	case *scopeKind != "device_group" && *scopeKind != "user_group":
		return fmt.Errorf("projector: %s carries unknown scope_kind %q", eventName, *scopeKind)
	}
	return nil
}
