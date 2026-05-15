package store

import (
	"context"
	"time"
)

// SCIMGroupMapping is one (provider, scim_group_id, user_group_id)
// triple from scim_group_mapping_projection. The mapping links a SCIM
// group provisioned by the upstream IdP to a Power Manage user_group;
// the projection enforces uniqueness on (provider_id, scim_group_id)
// AND on (provider_id, user_group_id) so each side is single-bound.
type SCIMGroupMapping struct {
	ID              string
	ProviderID      string
	SCIMGroupID     string
	SCIMDisplayName string
	UserGroupID     string
	CreatedAt       time.Time
}

// SCIMGroupMappingKey is the composite key used by the SCIM API to
// look up a single mapping by (provider, SCIM group ID).
type SCIMGroupMappingKey struct {
	ProviderID  string
	SCIMGroupID string
}

// SCIMGroupMappingByUserGroupKey is the inverse-direction lookup —
// SCIM patch handlers receive a Power Manage user_group_id and need
// to find the matching SCIM mapping (if any) to round-trip the
// display_name back to the IdP.
type SCIMGroupMappingByUserGroupKey struct {
	ProviderID  string
	UserGroupID string
}

// SCIMRepo reads SCIM mapping state. SCIM user reads
// (FindSCIMUserByEmail / ListSCIMUsers / etc.) return user-projection-
// shaped rows and migrate with the User domain in a later wave. Writes
// to scim_group_mapping_projection happen inside the projector
// listener — pure projector internals, stay on Queries().
type SCIMRepo interface {
	// GetGroupMapping returns the mapping for a (provider, SCIM
	// group) pair. Returns ErrNotFound when no mapping exists.
	GetGroupMapping(ctx context.Context, key SCIMGroupMappingKey) (SCIMGroupMapping, error)

	// GetGroupMappingByUserGroup returns the mapping for a
	// (provider, user_group) pair. Returns ErrNotFound when no
	// mapping exists (the user-group is not SCIM-managed).
	GetGroupMappingByUserGroup(ctx context.Context, key SCIMGroupMappingByUserGroupKey) (SCIMGroupMapping, error)

	// ListGroupMappings returns every mapping for the given
	// provider, ordered by scim_display_name. Empty slice when the
	// provider has no SCIM groups yet.
	ListGroupMappings(ctx context.Context, providerID string) ([]SCIMGroupMapping, error)

	// IsUserGroupSCIMManaged reports whether the given user_group
	// is managed by SCIM (i.e. has a mapping row for some
	// provider). Used by the user-group handler to refuse member
	// edits on SCIM-managed groups.
	IsUserGroupSCIMManaged(ctx context.Context, userGroupID string) (bool, error)
}
