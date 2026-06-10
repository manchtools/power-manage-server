package api

import (
	"context"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// scopeKindString maps the proto RoleGrantScopeKind to the store/auth
// scope-kind string. UNSPECIFIED (and any unknown) → "" = unscoped.
func scopeKindString(k pm.RoleGrantScopeKind) string {
	switch k {
	case pm.RoleGrantScopeKind_ROLE_GRANT_SCOPE_KIND_DEVICE_GROUP:
		return auth.ScopeKindDeviceGroup
	case pm.RoleGrantScopeKind_ROLE_GRANT_SCOPE_KIND_USER_GROUP:
		return auth.ScopeKindUserGroup
	default:
		return ""
	}
}

// scopePtrs converts an empty-or-set (kind, id) pair to the nil-or-set
// pointer pair the event payloads carry (nil together = unscoped).
func scopePtrs(scopeKind, scopeID string) (*string, *string) {
	if scopeKind == "" {
		return nil, nil
	}
	return &scopeKind, &scopeID
}

// validateAssignGrantScope runs the role-independent validation for the
// scope tuple on an assign-role request and returns the normalized
// (scopeKind, scopeID) to emit ("" / "" for an unscoped grant). It
// enforces: paired-or-neither, the AssignRoleScope gate + escalation
// bound for scoped grants, scope-group existence, and the
// scope-limited-admin-can't-grant-unscoped bound for unscoped grants.
//
// The per-role target_kind match (every permission in the role must
// accept this scope kind) is the CALLER's responsibility — it has each
// role's permission list. Use rejectUnscopableRole for that.
func validateAssignGrantScope(ctx context.Context, q *db.Queries, scopeKindEnum pm.RoleGrantScopeKind, scopeID string) (string, string, error) {
	scopeKind := scopeKindString(scopeKindEnum)

	// Paired-or-neither: both set or both absent.
	if (scopeKind == "") != (scopeID == "") {
		return "", "", apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument,
			"scope_kind and scope_id must be set together")
	}

	if scopeKind == "" {
		// Unscoped grant — a scope-limited admin may not create one.
		if err := auth.EnforceUnscopedGrantAuthority(ctx); err != nil {
			return "", "", err
		}
		return "", "", nil
	}

	// Scoped grant. Authority to attach a scope at all:
	if !auth.HasPermission(ctx, auth.AssignRoleScopePermission) {
		return "", "", apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied,
			"AssignRoleScope permission is required to scope a role grant")
	}
	// The scope group must exist.
	if err := scopeGroupExists(ctx, q, scopeKind, scopeID); err != nil {
		return "", "", err
	}
	// Escalation bound: the actor's own scope authority must cover it.
	if err := auth.EnforceGrantScopeAuthority(ctx, scopeKind, scopeID); err != nil {
		return "", "", err
	}
	return scopeKind, scopeID, nil
}

// scopeGroupExists verifies the scope_id references an existing group of
// the right kind.
func scopeGroupExists(ctx context.Context, q *db.Queries, scopeKind, scopeID string) error {
	switch scopeKind {
	case auth.ScopeKindDeviceGroup:
		if _, err := q.GetDeviceGroupByID(ctx, scopeID); err != nil {
			if store.IsNotFound(err) {
				return apiErrorCtx(ctx, ErrDeviceGroupNotFound, connect.CodeNotFound, "scope device group not found")
			}
			return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to verify scope device group")
		}
	case auth.ScopeKindUserGroup:
		if _, err := q.GetUserGroupByID(ctx, scopeID); err != nil {
			if store.IsNotFound(err) {
				return apiErrorCtx(ctx, ErrUserGroupNotFound, connect.CodeNotFound, "scope user group not found")
			}
			return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to verify scope user group")
		}
	default:
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "unknown scope_kind")
	}
	return nil
}

// rejectUnscopableRole returns an error when the role's permission set
// cannot be scoped with scopeKind (a target_kind mismatch — including
// any TargetUnspecified permission, which is never scopable). A no-op
// for an unscoped grant (scopeKind == "").
func rejectUnscopableRole(ctx context.Context, scopeKind string, permissions []string) error {
	if scopeKind == "" {
		return nil
	}
	if badPerm, ok := auth.RolePermissionsScopableWith(permissions, scopeKind); !ok {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument,
			"role permission "+badPerm+" cannot be scoped to a "+scopeKind)
	}
	return nil
}
