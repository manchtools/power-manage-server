package postgres

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Role implements store.RoleRepo against the roles_projection +
// user_roles_projection tables.
type Role struct {
	q *generated.Queries
}

// NewRole returns a Role repo bound to the given sqlc handle.
func NewRole(q *generated.Queries) *Role {
	return &Role{q: q}
}

func (r *Role) Get(ctx context.Context, id string) (store.Role, error) {
	row, err := r.q.GetRoleByID(ctx, id)
	if err != nil {
		return store.Role{}, fmt.Errorf("role: get: %w", translateNotFound(err))
	}
	return roleFromRow(row), nil
}

func (r *Role) GetByName(ctx context.Context, name string) (store.Role, error) {
	row, err := r.q.GetRoleByName(ctx, name)
	if err != nil {
		return store.Role{}, fmt.Errorf("role: get by name: %w", translateNotFound(err))
	}
	return roleFromRow(row), nil
}

func (r *Role) List(ctx context.Context, filter store.ListRolesFilter) ([]store.Role, error) {
	rows, err := r.q.ListRoles(ctx, generated.ListRolesParams{
		Limit:  filter.Limit,
		Offset: filter.Offset,
	})
	if err != nil {
		return nil, fmt.Errorf("role: list: %w", err)
	}
	out := make([]store.Role, len(rows))
	for i, row := range rows {
		out[i] = roleFromRow(row)
	}
	return out, nil
}

func (r *Role) Count(ctx context.Context) (int64, error) {
	n, err := r.q.CountRoles(ctx)
	if err != nil {
		return 0, fmt.Errorf("role: count: %w", translateNotFound(err))
	}
	return n, nil
}

func (r *Role) ListUserRoles(ctx context.Context, userID string) ([]store.Role, error) {
	rows, err := r.q.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("role: list user roles: %w", err)
	}
	out := make([]store.Role, len(rows))
	for i, row := range rows {
		out[i] = roleFromRow(row)
	}
	return out, nil
}

func (r *Role) UserHasRole(ctx context.Context, userID, roleID string) (bool, error) {
	has, err := r.q.UserHasRole(ctx, generated.UserHasRoleParams{
		UserID: userID,
		RoleID: roleID,
	})
	if err != nil {
		return false, fmt.Errorf("role: user has role: %w", translateNotFound(err))
	}
	return has, nil
}

func (r *Role) CountUsersWithRole(ctx context.Context, roleID string) (int64, error) {
	n, err := r.q.CountUsersWithRole(ctx, roleID)
	if err != nil {
		return 0, fmt.Errorf("role: count users with role: %w", translateNotFound(err))
	}
	return n, nil
}

func (r *Role) CountGroupsWithRole(ctx context.Context, roleID string) (int64, error) {
	n, err := r.q.CountGroupsWithRole(ctx, roleID)
	if err != nil {
		return 0, fmt.Errorf("role: count groups with role: %w", translateNotFound(err))
	}
	return n, nil
}

func (r *Role) ListUserIDsWithRole(ctx context.Context, roleID string) ([]string, error) {
	ids, err := r.q.ListUserIDsWithRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("role: list user ids: %w", err)
	}
	return ids, nil
}

func (r *Role) ListUserIDsWithGroupRole(ctx context.Context, roleID string) ([]string, error) {
	ids, err := r.q.ListUserIDsWithGroupRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("role: list group-role user ids: %w", err)
	}
	return ids, nil
}

// roleFromRow translates a sqlc projection row to the domain shape.
// Shared so the field mapping lives in one place across Get /
// GetByName / List / ListUserRoles.
func roleFromRow(row generated.RolesProjection) store.Role {
	return store.Role{
		ID:          row.ID,
		Name:        row.Name,
		Description: row.Description,
		Permissions: row.Permissions,
		IsSystem:    row.IsSystem,
		CreatedAt:   row.CreatedAt,
		CreatedBy:   row.CreatedBy,
		UpdatedAt:   row.UpdatedAt,
	}
}
