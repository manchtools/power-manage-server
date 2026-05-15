package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// UserGroup implements store.UserGroupRepo against
// user_groups_projection + user_group_members_projection.
type UserGroup struct {
	q *generated.Queries
}

// NewUserGroup returns a UserGroup repo bound to the given sqlc handle.
func NewUserGroup(q *generated.Queries) *UserGroup {
	return &UserGroup{q: q}
}

func (g *UserGroup) Get(ctx context.Context, id string) (store.UserGroup, error) {
	row, err := g.q.GetUserGroupByID(ctx, id)
	if err != nil {
		return store.UserGroup{}, fmt.Errorf("user_group: get: %w", translateNotFound(err))
	}
	return userGroupFromRow(row), nil
}

func (g *UserGroup) GetByName(ctx context.Context, name string) (store.UserGroup, error) {
	row, err := g.q.GetUserGroupByName(ctx, name)
	if err != nil {
		return store.UserGroup{}, fmt.Errorf("user_group: get by name: %w", translateNotFound(err))
	}
	return userGroupFromRow(row), nil
}

func (g *UserGroup) GetWithMembers(ctx context.Context, id string) (store.UserGroupWithMembers, error) {
	row, err := g.q.GetUserGroupWithMembers(ctx, id)
	if err != nil {
		return store.UserGroupWithMembers{}, fmt.Errorf("user_group: get with members: %w", translateNotFound(err))
	}
	return store.UserGroupWithMembers{
		UserGroup: store.UserGroup{
			ID:                row.ID,
			Name:              row.Name,
			Description:       row.Description,
			MemberCount:       row.MemberCount,
			CreatedAt:         row.CreatedAt,
			CreatedBy:         row.CreatedBy,
			UpdatedAt:         row.UpdatedAt,
			IsDynamic:         row.IsDynamic,
			DynamicQuery:      row.DynamicQuery,
			MaintenanceWindow: json.RawMessage(row.MaintenanceWindow),
		},
		ActualMemberCount: row.ActualMemberCount,
	}, nil
}

func (g *UserGroup) List(ctx context.Context, filter store.ListUserGroupsFilter) ([]store.UserGroup, error) {
	rows, err := g.q.ListUserGroups(ctx, generated.ListUserGroupsParams{
		Limit:  filter.Limit,
		Offset: filter.Offset,
	})
	if err != nil {
		return nil, fmt.Errorf("user_group: list: %w", err)
	}
	out := make([]store.UserGroup, len(rows))
	for i, r := range rows {
		out[i] = userGroupFromRow(r)
	}
	return out, nil
}

func (g *UserGroup) Count(ctx context.Context) (int64, error) {
	n, err := g.q.CountUserGroups(ctx)
	if err != nil {
		return 0, fmt.Errorf("user_group: count: %w", translateNotFound(err))
	}
	return n, nil
}

func (g *UserGroup) ListForUser(ctx context.Context, userID string) ([]store.UserGroup, error) {
	rows, err := g.q.ListUserGroupsForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user_group: list for user: %w", err)
	}
	out := make([]store.UserGroup, len(rows))
	for i, r := range rows {
		out[i] = userGroupFromRow(r)
	}
	return out, nil
}

func (g *UserGroup) ListMemberIDs(ctx context.Context, groupID string) ([]string, error) {
	ids, err := g.q.ListUserGroupMemberIDs(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("user_group: list member ids: %w", err)
	}
	return ids, nil
}

func (g *UserGroup) ListMembers(ctx context.Context, groupID string) ([]store.UserGroupMember, error) {
	rows, err := g.q.ListUserGroupMembers(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("user_group: list members: %w", err)
	}
	out := make([]store.UserGroupMember, len(rows))
	for i, r := range rows {
		out[i] = store.UserGroupMember{
			UserID:  r.UserID,
			Email:   r.Email,
			AddedAt: r.AddedAt,
		}
	}
	return out, nil
}

func userGroupFromRow(r generated.UserGroupsProjection) store.UserGroup {
	return store.UserGroup{
		ID:                r.ID,
		Name:              r.Name,
		Description:       r.Description,
		MemberCount:       r.MemberCount,
		CreatedAt:         r.CreatedAt,
		CreatedBy:         r.CreatedBy,
		UpdatedAt:         r.UpdatedAt,
		IsDynamic:         r.IsDynamic,
		DynamicQuery:      r.DynamicQuery,
		MaintenanceWindow: json.RawMessage(r.MaintenanceWindow),
	}
}
