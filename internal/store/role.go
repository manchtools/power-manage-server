package store

import (
	"context"
	"time"
)

// Role is a permission-bearing role definition. Permissions is the
// flat list of permission keys this role grants — names match what
// auth.HasPermission checks against. IsSystem flags roles that the
// platform manages (e.g. the built-in Admin / User roles) and that
// the role-CRUD endpoints refuse to delete or mutate.
type Role struct {
	ID          string
	Name        string
	Description string
	Permissions []string
	IsSystem    bool
	CreatedAt   time.Time
	CreatedBy   string
	UpdatedAt   *time.Time
}

// ListRolesFilter is the pagination shape for the role list endpoint.
type ListRolesFilter struct {
	Limit  int32
	Offset int32
}

// RoleGrant is a single, scoped role assignment (#7). Unlike
// ListUserRoles (de-duplicated by role id), a RoleGrant preserves the
// grant's scope, so the same role granted both globally and scoped to a
// device group appears as two grants. ScopeKind is "" for an unscoped
// (global) grant; otherwise "device_group" or "user_group", with ScopeID
// the group id and ScopeName its resolved display name ("" when unscoped
// or the group was deleted).
type RoleGrant struct {
	Role      Role
	ScopeKind string
	ScopeID   string
	ScopeName string
}

// RoleRepo reads role definitions and per-user role membership from
// the projection. Writes (RoleCreated / RoleUpdated / RoleDeleted /
// UserRoleAssigned / UserRoleRevoked) flow through the event store.
//
// The repo bundles both the role catalog (Get / List / Count) and
// the user-role membership graph (ListUserRoles / UserHasRole /
// ListUserIDsWithRole / ...) because they share the same projection
// pipeline and are queried together from the role handler.
type RoleRepo interface {
	// Get returns a role by ID. Returns ErrNotFound when no role
	// with that ID exists.
	Get(ctx context.Context, id string) (Role, error)

	// GetByName returns a role by its display name. Returns
	// ErrNotFound when no role with that name exists. Used by the
	// CreateRole pre-check and admin bootstrap.
	GetByName(ctx context.Context, name string) (Role, error)

	// List returns a page of roles. Empty slice past the end.
	List(ctx context.Context, filter ListRolesFilter) ([]Role, error)

	// Count returns the total role count for pagination.
	Count(ctx context.Context) (int64, error)

	// ListUserRoles returns all roles assigned to the user — both
	// directly and via groups, deduplicated. Empty slice when the
	// user has no roles.
	ListUserRoles(ctx context.Context, userID string) ([]Role, error)

	// ListUserRoleGrants returns the user's DIRECTLY-assigned role
	// grants WITH each grant's scope (#7), not de-duplicated — the same
	// role granted globally and scoped to a device group yields two
	// grants. Empty slice when the user has no direct grants.
	ListUserRoleGrants(ctx context.Context, userID string) ([]RoleGrant, error)

	// ListUserGroupRoleGrants returns a user group's role grants WITH
	// each grant's scope (#7), not de-duplicated. Empty slice when the
	// group has no role grants.
	ListUserGroupRoleGrants(ctx context.Context, groupID string) ([]RoleGrant, error)

	// UserHasRole reports whether the user has the given role
	// assigned, either directly or via a group membership.
	UserHasRole(ctx context.Context, userID, roleID string) (bool, error)

	// CountUsersWithRole returns the number of users with this role
	// assigned directly. Used by the "cannot delete role with
	// active users" pre-condition.
	CountUsersWithRole(ctx context.Context, roleID string) (int64, error)

	// CountGroupsWithRole returns the number of user-groups that
	// carry this role. Same delete-pre-condition use case.
	CountGroupsWithRole(ctx context.Context, roleID string) (int64, error)

	// ListUserIDsWithRole returns the IDs of users with this role
	// assigned directly. Used by the session-version bump pathway
	// when a role's permission set changes.
	ListUserIDsWithRole(ctx context.Context, roleID string) ([]string, error)

	// ListUserIDsWithGroupRole returns the IDs of users transitively
	// assigned this role via a user-group. Same session-version
	// bump pathway.
	ListUserIDsWithGroupRole(ctx context.Context, roleID string) ([]string, error)
}
