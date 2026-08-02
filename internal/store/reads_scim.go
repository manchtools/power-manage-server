package store

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Directory-provisioning reads. Same rule as reads.go: one exported
// method per question.
//
// Every subject and group read here is keyed on a provider id. A SCIM
// directory addresses only what it is itself bound to, and the
// confinement lives in the statement rather than in a filter the
// caller has to remember to apply.

type (
	// UserGroupRow is one stored user group.
	UserGroupRow = generated.UserGroup
	// SCIMGroupMappingRow binds one directory group to one local user
	// group.
	SCIMGroupMappingRow = generated.ScimGroupMapping
)

// SCIMUserRow is a subject as one directory sees it: the user row plus
// the external identifier that directory's link carries for them.
//
// The three lookups below return the same shape, so the SCIM handlers
// have one type to translate rather than one per query.
type SCIMUserRow struct {
	User       UserRow
	ExternalID string
}

// ListSCIMUsers pages the subjects bound to one provider, ordered by
// subject id.
func (s *Store) ListSCIMUsers(ctx context.Context, providerID string, limit, offset int32) ([]SCIMUserRow, error) {
	rows, err := s.queries.ListSCIMUsers(ctx, generated.ListSCIMUsersParams{
		ProviderID: providerID,
		Limit:      int64(limit),
		Offset:     int64(offset),
	})
	if err != nil {
		return nil, fmt.Errorf("scim: list users: %w", err)
	}
	out := make([]SCIMUserRow, len(rows))
	for i, r := range rows {
		out[i] = SCIMUserRow{User: r.User, ExternalID: r.ExternalID}
	}
	return out, nil
}

// CountSCIMUsers reports how many subjects are bound to one provider.
func (s *Store) CountSCIMUsers(ctx context.Context, providerID string) (int64, error) {
	n, err := s.queries.CountSCIMUsers(ctx, providerID)
	if err != nil {
		return 0, fmt.Errorf("scim: count users: %w", err)
	}
	return n, nil
}

// FindSCIMUserByEmail resolves one of a provider's subjects by address.
func (s *Store) FindSCIMUserByEmail(ctx context.Context, providerID, email string) (SCIMUserRow, error) {
	row, err := s.queries.FindSCIMUserByEmail(ctx, generated.FindSCIMUserByEmailParams{
		ProviderID: providerID,
		Email:      email,
	})
	if err != nil {
		return SCIMUserRow{}, fmt.Errorf("scim: find user by email: %w", translateNotFound(err))
	}
	return SCIMUserRow{User: row.User, ExternalID: row.ExternalID}, nil
}

// FindSCIMUserByExternalID resolves one of a provider's subjects by the
// identifier the directory assigned them.
func (s *Store) FindSCIMUserByExternalID(ctx context.Context, providerID, externalID string) (SCIMUserRow, error) {
	row, err := s.queries.FindSCIMUserByExternalID(ctx, generated.FindSCIMUserByExternalIDParams{
		ProviderID: providerID,
		ExternalID: externalID,
	})
	if err != nil {
		return SCIMUserRow{}, fmt.Errorf("scim: find user by external id: %w", translateNotFound(err))
	}
	return SCIMUserRow{User: row.User, ExternalID: row.ExternalID}, nil
}

// GetIdentityLinkByProviderAndUser answers the ownership question a
// directory-scoped handler asks before it touches a subject.
// ErrNotFound means the subject is not bound to that provider.
func (s *Store) GetIdentityLinkByProviderAndUser(ctx context.Context, providerID, userID string) (IdentityLinkRow, error) {
	row, err := s.queries.GetIdentityLinkByProviderAndUser(ctx, generated.GetIdentityLinkByProviderAndUserParams{
		ProviderID: providerID,
		UserID:     userID,
	})
	if err != nil {
		return IdentityLinkRow{}, fmt.Errorf("identity_link: get by provider and user: %w", translateNotFound(err))
	}
	return row, nil
}

// CountIdentityLinksForUser reports how many external identities a
// subject still has. Removing the last one is what turns an unlink into
// an erasure.
func (s *Store) CountIdentityLinksForUser(ctx context.Context, userID string) (int64, error) {
	n, err := s.queries.CountIdentityLinksForUser(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("identity_link: count for user: %w", err)
	}
	return n, nil
}

// GetUserGroup returns one live group. ErrNotFound when unknown or
// retired.
func (s *Store) GetUserGroup(ctx context.Context, id string) (UserGroupRow, error) {
	row, err := s.queries.GetUserGroup(ctx, id)
	if err != nil {
		return UserGroupRow{}, fmt.Errorf("user_group: get: %w", translateNotFound(err))
	}
	return row, nil
}

// ListUserGroupMemberIDs returns the ids of a group's members.
func (s *Store) ListUserGroupMemberIDs(ctx context.Context, groupID string) ([]string, error) {
	rows, err := s.queries.ListUserGroupMemberIDs(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("user_group: list members: %w", err)
	}
	return rows, nil
}

// GetSCIMGroupMapping resolves a directory group to its local binding.
func (s *Store) GetSCIMGroupMapping(ctx context.Context, providerID, scimGroupID string) (SCIMGroupMappingRow, error) {
	row, err := s.queries.GetSCIMGroupMapping(ctx, generated.GetSCIMGroupMappingParams{
		ProviderID:  providerID,
		ScimGroupID: scimGroupID,
	})
	if err != nil {
		return SCIMGroupMappingRow{}, fmt.Errorf("scim_group_mapping: get: %w", translateNotFound(err))
	}
	return row, nil
}

// GetSCIMGroupMappingByUserGroup resolves a local group to the
// directory binding one provider holds on it.
func (s *Store) GetSCIMGroupMappingByUserGroup(ctx context.Context, providerID, userGroupID string) (SCIMGroupMappingRow, error) {
	row, err := s.queries.GetSCIMGroupMappingByUserGroup(ctx, generated.GetSCIMGroupMappingByUserGroupParams{
		ProviderID:  providerID,
		UserGroupID: userGroupID,
	})
	if err != nil {
		return SCIMGroupMappingRow{}, fmt.Errorf("scim_group_mapping: get by user group: %w", translateNotFound(err))
	}
	return row, nil
}

// ListSCIMGroupMappings returns every binding one provider holds.
func (s *Store) ListSCIMGroupMappings(ctx context.Context, providerID string) ([]SCIMGroupMappingRow, error) {
	rows, err := s.queries.ListSCIMGroupMappings(ctx, providerID)
	if err != nil {
		return nil, fmt.Errorf("scim_group_mapping: list: %w", err)
	}
	return rows, nil
}
