package postgres

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// SCIM implements store.SCIMRepo against scim_group_mapping_projection.
type SCIM struct {
	q *generated.Queries
}

// NewSCIM returns a SCIM repo bound to the given sqlc handle.
func NewSCIM(q *generated.Queries) *SCIM {
	return &SCIM{q: q}
}

func (s *SCIM) GetGroupMapping(ctx context.Context, key store.SCIMGroupMappingKey) (store.SCIMGroupMapping, error) {
	row, err := s.q.GetSCIMGroupMapping(ctx, generated.GetSCIMGroupMappingParams{
		ProviderID:  key.ProviderID,
		ScimGroupID: key.SCIMGroupID,
	})
	if err != nil {
		return store.SCIMGroupMapping{}, fmt.Errorf("scim: get group mapping: %w", translateNotFound(err))
	}
	return scimGroupMappingFromRow(row), nil
}

func (s *SCIM) GetGroupMappingByUserGroup(ctx context.Context, key store.SCIMGroupMappingByUserGroupKey) (store.SCIMGroupMapping, error) {
	row, err := s.q.GetSCIMGroupMappingByUserGroup(ctx, generated.GetSCIMGroupMappingByUserGroupParams{
		ProviderID:  key.ProviderID,
		UserGroupID: key.UserGroupID,
	})
	if err != nil {
		return store.SCIMGroupMapping{}, fmt.Errorf("scim: get group mapping by user group: %w", translateNotFound(err))
	}
	return scimGroupMappingFromRow(row), nil
}

func (s *SCIM) ListGroupMappings(ctx context.Context, providerID string) ([]store.SCIMGroupMapping, error) {
	rows, err := s.q.ListSCIMGroupMappings(ctx, providerID)
	if err != nil {
		return nil, fmt.Errorf("scim: list group mappings: %w", err)
	}
	out := make([]store.SCIMGroupMapping, len(rows))
	for i, r := range rows {
		out[i] = scimGroupMappingFromRow(r)
	}
	return out, nil
}

func (s *SCIM) IsUserGroupSCIMManaged(ctx context.Context, userGroupID string) (bool, error) {
	managed, err := s.q.IsUserGroupSCIMManaged(ctx, userGroupID)
	if err != nil {
		return false, fmt.Errorf("scim: is user group scim managed: %w", translateNotFound(err))
	}
	return managed, nil
}

func scimGroupMappingFromRow(r generated.ScimGroupMappingProjection) store.SCIMGroupMapping {
	return store.SCIMGroupMapping{
		ID:              r.ID,
		ProviderID:      r.ProviderID,
		SCIMGroupID:     r.ScimGroupID,
		SCIMDisplayName: r.ScimDisplayName,
		UserGroupID:     r.UserGroupID,
		CreatedAt:       r.CreatedAt,
	}
}
