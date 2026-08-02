package store

import (
	"context"
	"fmt"
	"time"

	"github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/store/sqlitetype"
)

// Identity reads. Same rule as reads.go: one exported method per
// question, so the set of things a caller can ask the database stays
// enumerable and a read can never become a write by accident.

// Row aliases for the identity tables and join shapes.
type (
	// RoleRow is one stored role.
	RoleRow = generated.Role
	// RoleGrantRow is one direct role grant on a user, with its scope
	// and the granted role resolved.
	RoleGrantRow = generated.ListUserRoleGrantsRow
	// GroupRoleGrantRow is one role grant on a user group.
	GroupRoleGrantRow = generated.ListUserGroupRoleGrantsRow
	// UserGroupView is one live group with derived membership and SCIM state.
	UserGroupView = generated.GetUserGroupViewRow
	// UserGroupMemberView is one live group member.
	UserGroupMemberView = generated.ListUserGroupMembersRow
	// UserDynamicEvaluationRow is the non-secret user state available to dynamic groups.
	UserDynamicEvaluationRow = generated.ListUsersForDynamicUserGroupEvaluationRow
	// InheritedRoleRow is a role a subject holds through a group.
	InheritedRoleRow = generated.ListInheritedRolesForUserRow
	// ScopedGrantRow is one (permission, scope) tuple a subject holds.
	// A nil ScopeKind/ScopeID pair is the global grant.
	ScopedGrantRow = generated.ListUserScopedGrantsRow
	// IdentityProviderRow is one stored identity provider.
	IdentityProviderRow = generated.IdentityProvider
	// IdentityLinkRow is one stored external-identity binding.
	IdentityLinkRow = generated.IdentityLink
	// IdentityLinkWithProviderRow is a link joined to its provider's
	// display fields.
	IdentityLinkWithProviderRow = generated.ListIdentityLinksForUserRow
	// UserSSHKeyRow is one authorized SSH public key.
	UserSSHKeyRow = generated.UserSshKey
	// ServerSettingsRow is the singleton settings row.
	ServerSettingsRow = generated.ServerSetting
	// UserSessionStateRow is the subject state a session check needs.
	UserSessionStateRow = generated.GetUserSessionStateRow
)

// UserGroupListFilter contains the keyset and user-group scope shared by
// group list reads.
type UserGroupListFilter struct {
	AfterID         string
	Limit           int32
	ScopeRestricted bool
	ScopeGroupIDs   []string
}

// GetUserByEmail returns one live user by address. ErrNotFound when no
// live user holds it.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (UserRow, error) {
	row, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		return UserRow{}, fmt.Errorf("user: get by email: %w", translateNotFound(err))
	}
	return row, nil
}

// GetUserSessionState reports whether a subject may still hold a
// session and at which session version. Unlike GetUser it does not
// filter retired rows, so the caller can distinguish "retired" from
// "never existed" and refuse both explicitly.
func (s *Store) GetUserSessionState(ctx context.Context, id string) (UserSessionStateRow, error) {
	row, err := s.queries.GetUserSessionState(ctx, id)
	if err != nil {
		return UserSessionStateRow{}, fmt.Errorf("user: session state: %w", translateNotFound(err))
	}
	return row, nil
}

// ListUsers returns up to limit live users whose id sorts after after.
// An empty after starts at the beginning.
func (s *Store) ListUsers(ctx context.Context, after string, limit int32) ([]UserRow, error) {
	rows, err := s.queries.ListUsers(ctx, generated.ListUsersParams{ID: after, Limit: int64(limit)})
	if err != nil {
		return nil, fmt.Errorf("user: list: %w", err)
	}
	return rows, nil
}

// ListUserPermissions returns the flat permission set a subject holds,
// directly and through their groups.
func (s *Store) ListUserPermissions(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.queries.ListUserPermissions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user: permissions: %w", err)
	}
	return rows, nil
}

// ListUserScopedGrants returns the subject's (permission, scope)
// tuples. A row with no scope is a global grant of that permission.
func (s *Store) ListUserScopedGrants(ctx context.Context, userID string) ([]ScopedGrantRow, error) {
	rows, err := s.queries.ListUserScopedGrants(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user: scoped grants: %w", err)
	}
	return rows, nil
}

// ListUserRoleGrants returns the subject's direct role grants, one per
// grant, each with its scope.
func (s *Store) ListUserRoleGrants(ctx context.Context, userID string) ([]RoleGrantRow, error) {
	rows, err := s.queries.ListUserRoleGrants(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user: role grants: %w", err)
	}
	return rows, nil
}

// ListUserGroupRoleGrants returns a group's role grants.
func (s *Store) ListUserGroupRoleGrants(ctx context.Context, groupID string) ([]GroupRoleGrantRow, error) {
	rows, err := s.queries.ListUserGroupRoleGrants(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("user_group: role grants: %w", err)
	}
	return rows, nil
}

// GetUserGroupView returns one live group with its derived display state.
func (s *Store) GetUserGroupView(ctx context.Context, id string) (UserGroupView, error) {
	row, err := s.queries.GetUserGroupView(ctx, id)
	if err != nil {
		return UserGroupView{}, fmt.Errorf("user_group: get: %w", translateNotFound(err))
	}
	return row, nil
}

// ListUserGroups returns a deterministic scoped keyset page.
func (s *Store) ListUserGroups(ctx context.Context, filter UserGroupListFilter) ([]UserGroupView, error) {
	if filter.Limit <= 0 || filter.Limit > 101 {
		return nil, fmt.Errorf("user_group: list limit must be between 1 and 101")
	}
	rows, err := s.queries.ListUserGroups(ctx, generated.ListUserGroupsParams{
		AfterID: filter.AfterID, RowLimit: int64(filter.Limit),
		ScopeRestricted: filter.ScopeRestricted, ScopeGroupIdsJson: sqlitetype.StringList(filter.ScopeGroupIDs),
	})
	if err != nil {
		return nil, fmt.Errorf("user_group: list: %w", err)
	}
	groups := make([]UserGroupView, len(rows))
	for i, row := range rows {
		groups[i] = UserGroupView(row)
	}
	return groups, nil
}

// CountUserGroups counts the same scope selected by ListUserGroups.
func (s *Store) CountUserGroups(ctx context.Context, filter UserGroupListFilter) (int64, error) {
	count, err := s.queries.CountUserGroups(ctx, generated.CountUserGroupsParams{
		ScopeRestricted: filter.ScopeRestricted, ScopeGroupIdsJson: sqlitetype.StringList(filter.ScopeGroupIDs),
	})
	if err != nil {
		return 0, fmt.Errorf("user_group: count: %w", err)
	}
	return count, nil
}

// ListUserGroupsForUser returns visible live groups containing a subject.
func (s *Store) ListUserGroupsForUser(ctx context.Context, userID string, filter UserGroupListFilter) ([]UserGroupView, error) {
	rows, err := s.queries.ListUserGroupsForUser(ctx, generated.ListUserGroupsForUserParams{
		UserID: userID, ScopeRestricted: filter.ScopeRestricted, ScopeGroupIdsJson: sqlitetype.StringList(filter.ScopeGroupIDs),
	})
	if err != nil {
		return nil, fmt.Errorf("user_group: list for user: %w", err)
	}
	groups := make([]UserGroupView, len(rows))
	for i, row := range rows {
		groups[i] = UserGroupView(row)
	}
	return groups, nil
}

// ListUserGroupMembers returns every live member of one group.
func (s *Store) ListUserGroupMembers(ctx context.Context, groupID string) ([]UserGroupMemberView, error) {
	rows, err := s.queries.ListUserGroupMembers(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("user_group: members: %w", err)
	}
	return rows, nil
}

// ListUsersForDynamicUserGroupEvaluation returns every live user's
// queryable non-secret fields in stable id order.
func (s *Store) ListUsersForDynamicUserGroupEvaluation(ctx context.Context) ([]UserDynamicEvaluationRow, error) {
	rows, err := s.queries.ListUsersForDynamicUserGroupEvaluation(ctx)
	if err != nil {
		return nil, fmt.Errorf("user_group: list evaluation users: %w", err)
	}
	return rows, nil
}

// ListInheritedRolesForUser returns the roles a subject holds because
// of a group they belong to, with the group that conferred each.
func (s *Store) ListInheritedRolesForUser(ctx context.Context, userID string) ([]InheritedRoleRow, error) {
	rows, err := s.queries.ListInheritedRolesForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user: inherited roles: %w", err)
	}
	return rows, nil
}

// ListUserGroupIDsForUser returns the ids of the live groups a subject
// belongs to.
func (s *Store) ListUserGroupIDsForUser(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.queries.ListUserGroupIDsForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user: group memberships: %w", err)
	}
	return rows, nil
}

// ListUserSSHKeys returns a subject's authorized SSH public keys.
func (s *Store) ListUserSSHKeys(ctx context.Context, userID string) ([]UserSSHKeyRow, error) {
	rows, err := s.queries.ListUserSshKeys(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user: ssh keys: %w", err)
	}
	return rows, nil
}

// GetRole returns one live role. ErrNotFound when unknown or retired.
func (s *Store) GetRole(ctx context.Context, id string) (RoleRow, error) {
	row, err := s.queries.GetRole(ctx, id)
	if err != nil {
		return RoleRow{}, fmt.Errorf("role: get: %w", translateNotFound(err))
	}
	return row, nil
}

// GetRoleByName returns one live role by name.
func (s *Store) GetRoleByName(ctx context.Context, name string) (RoleRow, error) {
	row, err := s.queries.GetRoleByName(ctx, name)
	if err != nil {
		return RoleRow{}, fmt.Errorf("role: get by name: %w", translateNotFound(err))
	}
	return row, nil
}

// ListRoles returns up to limit live roles whose id sorts after after.
func (s *Store) ListRoles(ctx context.Context, after string, limit int32) ([]RoleRow, error) {
	rows, err := s.queries.ListRoles(ctx, generated.ListRolesParams{ID: after, Limit: int64(limit)})
	if err != nil {
		return nil, fmt.Errorf("role: list: %w", err)
	}
	return rows, nil
}

// CountRoles returns the number of live roles.
func (s *Store) CountRoles(ctx context.Context) (int64, error) {
	n, err := s.queries.CountRoles(ctx)
	if err != nil {
		return 0, fmt.Errorf("role: count: %w", err)
	}
	return n, nil
}

// CountRoleHolders returns how many distinct subjects hold the role,
// directly or through a group.
func (s *Store) CountRoleHolders(ctx context.Context, roleID string) (int64, error) {
	n, err := s.queries.CountRoleHolders(ctx, roleID)
	if err != nil {
		return 0, fmt.Errorf("role: count holders: %w", err)
	}
	return n, nil
}

// GetIdentityProvider returns one live provider.
func (s *Store) GetIdentityProvider(ctx context.Context, id string) (IdentityProviderRow, error) {
	row, err := s.queries.GetIdentityProvider(ctx, id)
	if err != nil {
		return IdentityProviderRow{}, fmt.Errorf("identity_provider: get: %w", translateNotFound(err))
	}
	return row, nil
}

// GetIdentityProviderBySlug returns one live provider by its slug.
func (s *Store) GetIdentityProviderBySlug(ctx context.Context, slug string) (IdentityProviderRow, error) {
	row, err := s.queries.GetIdentityProviderBySlug(ctx, slug)
	if err != nil {
		return IdentityProviderRow{}, fmt.Errorf("identity_provider: get by slug: %w", translateNotFound(err))
	}
	return row, nil
}

// ListIdentityProviders returns up to limit live providers whose id
// sorts after after.
func (s *Store) ListIdentityProviders(ctx context.Context, after string, limit int32) ([]IdentityProviderRow, error) {
	rows, err := s.queries.ListIdentityProviders(ctx, generated.ListIdentityProvidersParams{ID: after, Limit: int64(limit)})
	if err != nil {
		return nil, fmt.Errorf("identity_provider: list: %w", err)
	}
	return rows, nil
}

// ListEnabledIdentityProviders returns every live, enabled provider.
// This is what the unauthenticated login page is allowed to see.
func (s *Store) ListEnabledIdentityProviders(ctx context.Context) ([]IdentityProviderRow, error) {
	rows, err := s.queries.ListEnabledIdentityProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("identity_provider: list enabled: %w", err)
	}
	return rows, nil
}

// CountIdentityProviders returns the number of live providers.
func (s *Store) CountIdentityProviders(ctx context.Context) (int64, error) {
	n, err := s.queries.CountIdentityProviders(ctx)
	if err != nil {
		return 0, fmt.Errorf("identity_provider: count: %w", err)
	}
	return n, nil
}

// GetIdentityLink returns one external-identity binding.
func (s *Store) GetIdentityLink(ctx context.Context, id string) (IdentityLinkRow, error) {
	row, err := s.queries.GetIdentityLink(ctx, id)
	if err != nil {
		return IdentityLinkRow{}, fmt.Errorf("identity_link: get: %w", translateNotFound(err))
	}
	return row, nil
}

// ListIdentityLinksForUser returns a subject's external identities with
// their providers' display fields.
func (s *Store) ListIdentityLinksForUser(ctx context.Context, userID string) ([]IdentityLinkWithProviderRow, error) {
	rows, err := s.queries.ListIdentityLinksForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("identity_link: list: %w", err)
	}
	return rows, nil
}

// IsTokenRevoked reports whether a session token id is on the
// revocation list.
func (s *Store) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	revoked, err := s.queries.IsTokenRevoked(ctx, jti)
	if err != nil {
		return false, fmt.Errorf("revoked_token: lookup: %w", err)
	}
	return revoked, nil
}

// GetServerSettings returns the singleton settings row.
func (s *Store) GetServerSettings(ctx context.Context) (ServerSettingsRow, error) {
	row, err := s.queries.GetServerSettings(ctx)
	if err != nil {
		return ServerSettingsRow{}, fmt.Errorf("server_settings: get: %w", translateNotFound(err))
	}
	return row, nil
}

// CountLiveBootstrapAdminTokens returns how many host-authorized
// bootstrap tokens are still presentable at the given instant.
//
// The instant is a parameter rather than this package's clock: the
// bootstrap path issues and spends against one clock, and asking the
// same question against a different one would make the answer depend
// on skew between them.
func (s *Store) CountLiveBootstrapAdminTokens(ctx context.Context, at time.Time) (int64, error) {
	at = at.UTC()
	n, err := s.queries.CountLiveBootstrapAdminTokens(ctx, generated.CountLiveBootstrapAdminTokensParams{
		ReservedName: BootstrapAdminTokenName,
		Now:          &at,
	})
	if err != nil {
		return 0, fmt.Errorf("bootstrap_token: count: %w", err)
	}
	return n, nil
}

// BootstrapAdminTokenName is the reserved `tokens.name` that marks a
// host-authorized bootstrap-admin token. No other writer may use it:
// the consume-once statement keys on it, so a token created under this
// name is presentable at the bootstrap boundary.
const BootstrapAdminTokenName = "bootstrap-admin"

// AuthStateRow is one in-flight OIDC authorization-code exchange.
type AuthStateRow = generated.AuthState
