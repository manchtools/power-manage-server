package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// RoleHandler handles role management RPCs.
type RoleHandler struct {
	store  *store.Store
	logger *slog.Logger
}

// NewRoleHandler creates a new role handler.
func NewRoleHandler(st *store.Store, logger *slog.Logger) *RoleHandler {
	return &RoleHandler{
		store:  st,
		logger: logger,
	}
}

// CreateRole creates a new role.
func (h *RoleHandler) CreateRole(ctx context.Context, req *connect.Request[pm.CreateRoleRequest]) (*connect.Response[pm.CreateRoleResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Validate permissions
	validPerms := auth.ValidPermissionKeys()
	for _, p := range req.Msg.Permissions {
		if !validPerms[p] {
			return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, fmt.Sprintf("invalid permission: %s", p))
		}
	}

	// Check name uniqueness
	_, err := h.store.Queries().GetRoleByName(ctx, req.Msg.Name)
	if err == nil {
		return nil, apiErrorCtx(ctx, ErrRoleNameExists, connect.CodeAlreadyExists, "role name already exists")
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	id := ulid.Make().String()

	perms := req.Msg.Permissions
	if perms == nil {
		perms = []string{}
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "role",
		StreamID:   id,
		EventType:  "RoleCreated",
		Data: map[string]any{
			"name":        req.Msg.Name,
			"description": req.Msg.Description,
			"permissions": perms,
			"is_system":   false,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to create role"); err != nil {
		return nil, err
	}

	role, err := h.store.Queries().GetRoleByID(ctx, id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to read role")
	}

	return connect.NewResponse(&pm.CreateRoleResponse{
		Role: roleToProto(role),
	}), nil
}

// GetRole returns a role by ID.
func (h *RoleHandler) GetRole(ctx context.Context, req *connect.Request[pm.GetRoleRequest]) (*connect.Response[pm.GetRoleResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	role, err := h.store.Queries().GetRoleByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrRoleNotFound, "role not found")
	}

	userCount, err := h.store.Queries().CountUsersWithRole(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count users")
	}

	return connect.NewResponse(&pm.GetRoleResponse{
		Role:      roleToProto(role),
		UserCount: int32(userCount),
	}), nil
}

// ListRoles returns a paginated list of roles.
func (h *RoleHandler) ListRoles(ctx context.Context, req *connect.Request[pm.ListRolesRequest]) (*connect.Response[pm.ListRolesResponse], error) {
	pageSize, offset, err := parsePagination(int32(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, err
	}

	roles, err := h.store.Queries().ListRoles(ctx, db.ListRolesParams{
		Limit:  pageSize,
		Offset: offset,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list roles")
	}

	count, err := h.store.Queries().CountRoles(ctx)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count roles")
	}

	nextPageToken := buildNextPageToken(int32(len(roles)), offset, pageSize, count)

	protoRoles := make([]*pm.Role, len(roles))
	for i, r := range roles {
		protoRoles[i] = roleToProto(r)
	}

	return connect.NewResponse(&pm.ListRolesResponse{
		Roles:         protoRoles,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// UpdateRole updates a role's name, description, and permissions.
func (h *RoleHandler) UpdateRole(ctx context.Context, req *connect.Request[pm.UpdateRoleRequest]) (*connect.Response[pm.UpdateRoleResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	role, err := h.store.Queries().GetRoleByID(ctx, req.Msg.RoleId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrRoleNotFound, "role not found")
	}

	// System roles can't have their name changed
	if role.IsSystem && req.Msg.Name != role.Name {
		return nil, apiErrorCtx(ctx, ErrCannotRenameSystemRole, connect.CodeFailedPrecondition, "cannot rename system role")
	}

	// Validate permissions
	validPerms := auth.ValidPermissionKeys()
	for _, p := range req.Msg.Permissions {
		if !validPerms[p] {
			return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, fmt.Sprintf("invalid permission: %s", p))
		}
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	perms := req.Msg.Permissions
	if perms == nil {
		perms = []string{}
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "role",
		StreamID:   req.Msg.RoleId,
		EventType:  "RoleUpdated",
		Data: map[string]any{
			"name":        req.Msg.Name,
			"description": req.Msg.Description,
			"permissions": perms,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to update role"); err != nil {
		return nil, err
	}

	// Bump session_version for all users with this role to invalidate cached permissions
	h.bumpSessionVersionForRole(ctx, req.Msg.RoleId, userCtx.ID)

	updated, err := h.store.Queries().GetRoleByID(ctx, req.Msg.RoleId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to read role")
	}

	return connect.NewResponse(&pm.UpdateRoleResponse{
		Role: roleToProto(updated),
	}), nil
}

// DeleteRole deletes a role.
func (h *RoleHandler) DeleteRole(ctx context.Context, req *connect.Request[pm.DeleteRoleRequest]) (*connect.Response[pm.DeleteRoleResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	role, err := h.store.Queries().GetRoleByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrRoleNotFound, "role not found")
	}

	if role.IsSystem {
		return nil, apiErrorCtx(ctx, ErrCannotDeleteSystemRole, connect.CodeFailedPrecondition, "cannot delete system role")
	}

	userCount, err := h.store.Queries().CountUsersWithRole(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count users")
	}
	if userCount > 0 {
		return nil, apiErrorCtx(ctx, ErrRoleInUse, connect.CodeFailedPrecondition, fmt.Sprintf("role still has %d assigned users", userCount))
	}

	groupCount, err := h.store.Queries().CountGroupsWithRole(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count user groups")
	}
	if groupCount > 0 {
		return nil, apiErrorCtx(ctx, ErrRoleInUse, connect.CodeFailedPrecondition, fmt.Sprintf("role still assigned to %d user groups", groupCount))
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "role",
		StreamID:   req.Msg.Id,
		EventType:  "RoleDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to delete role"); err != nil {
		return nil, err
	}

	return connect.NewResponse(&pm.DeleteRoleResponse{}), nil
}

// AssignRoleToUser assigns one or more roles to a user.
func (h *RoleHandler) AssignRoleToUser(ctx context.Context, req *connect.Request[pm.AssignRoleToUserRequest]) (*connect.Response[pm.AssignRoleToUserResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Collect role IDs from single + repeated fields
	roleIDs := append([]string{}, req.Msg.RoleIds...)
	if req.Msg.RoleId != "" {
		roleIDs = append(roleIDs, req.Msg.RoleId)
	}
	if len(roleIDs) == 0 {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "at least one role_id or role_ids must be set")
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	q := h.store.Queries()

	// Verify user exists
	_, err = q.GetUserByID(ctx, req.Msg.UserId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserNotFound, "user not found")
	}

	for _, roleID := range roleIDs {
		// Verify role exists
		_, err = q.GetRoleByID(ctx, roleID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, apiErrorCtx(ctx, ErrRoleNotFound, connect.CodeNotFound, "role not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get role")
		}

		// Check if already assigned — skip silently in batch
		hasRole, err := q.UserHasRole(ctx, db.UserHasRoleParams{
			UserID: req.Msg.UserId,
			RoleID: roleID,
		})
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to check role assignment")
		}
		if hasRole {
			continue
		}

		streamID := req.Msg.UserId + ":" + roleID
		if err := appendEvent(ctx, h.store, h.logger, store.Event{
			StreamType: "user_role",
			StreamID:   streamID,
			EventType:  "UserRoleAssigned",
			Data: map[string]any{
				"user_id": req.Msg.UserId,
				"role_id": roleID,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		}, "failed to assign role"); err != nil {
			return nil, err
		}
	}

	// Bump user's session version once to invalidate cached permissions
	h.bumpUserSessionVersion(ctx, req.Msg.UserId, userCtx.ID)

	return connect.NewResponse(&pm.AssignRoleToUserResponse{}), nil
}

// RevokeRoleFromUser removes a role from a user.
func (h *RoleHandler) RevokeRoleFromUser(ctx context.Context, req *connect.Request[pm.RevokeRoleFromUserRequest]) (*connect.Response[pm.RevokeRoleFromUserResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Check if the role is the Admin system role
	role, err := h.store.Queries().GetRoleByID(ctx, req.Msg.RoleId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrRoleNotFound, "role not found")
	}

	// Prevent removing the last user from the Admin system role
	if role.IsSystem && role.Name == "Admin" {
		userCount, err := h.store.Queries().CountUsersWithRole(ctx, req.Msg.RoleId)
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count users")
		}
		if userCount <= 1 {
			return nil, apiErrorCtx(ctx, ErrCannotRenameSystemRole, connect.CodeFailedPrecondition, "cannot remove last user from Admin role")
		}
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	streamID := req.Msg.UserId + ":" + req.Msg.RoleId
	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "user_role",
		StreamID:   streamID,
		EventType:  "UserRoleRevoked",
		Data: map[string]any{
			"user_id": req.Msg.UserId,
			"role_id": req.Msg.RoleId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to revoke role"); err != nil {
		return nil, err
	}

	// Bump user's session version to invalidate cached permissions
	h.bumpUserSessionVersion(ctx, req.Msg.UserId, userCtx.ID)

	return connect.NewResponse(&pm.RevokeRoleFromUserResponse{}), nil
}

// ListPermissions returns all available permissions.
func (h *RoleHandler) ListPermissions(ctx context.Context, req *connect.Request[pm.ListPermissionsRequest]) (*connect.Response[pm.ListPermissionsResponse], error) {
	allPerms := auth.AllPermissions()
	protoPerms := make([]*pm.PermissionInfo, len(allPerms))
	for i, p := range allPerms {
		protoPerms[i] = &pm.PermissionInfo{
			Key:         p.Key,
			Group:       p.Group,
			Description: p.Description,
		}
	}

	return connect.NewResponse(&pm.ListPermissionsResponse{
		Permissions: protoPerms,
	}), nil
}

// bumpUserSessionVersion increments a user's session_version to invalidate JWT/permission cache.
func (h *RoleHandler) bumpUserSessionVersion(ctx context.Context, userID, actorID string) {
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  "UserSessionInvalidated",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    actorID,
	}); err != nil {
		h.logger.Warn("failed to append UserSessionInvalidated event", "user_id", userID, "error", err)
	} else {
		h.logger.Debug("event appended",
			"stream_type", "user",
			"stream_id", userID,
			"event_type", "UserSessionInvalidated",
		)
	}
}

// bumpSessionVersionForRole bumps session_version for all users with a given role
// (directly assigned or via user groups).
func (h *RoleHandler) bumpSessionVersionForRole(ctx context.Context, roleID, actorID string) {
	seen := make(map[string]bool)

	// Direct role assignments
	userIDs, err := h.store.Queries().ListUserIDsWithRole(ctx, roleID)
	if err == nil {
		for _, uid := range userIDs {
			if !seen[uid] {
				h.bumpUserSessionVersion(ctx, uid, actorID)
				seen[uid] = true
			}
		}
	}

	// User group role assignments
	groupUserIDs, err := h.store.Queries().ListUserIDsWithGroupRole(ctx, roleID)
	if err == nil {
		for _, uid := range groupUserIDs {
			if !seen[uid] {
				h.bumpUserSessionVersion(ctx, uid, actorID)
				seen[uid] = true
			}
		}
	}
}

// roleToProto converts a database role projection to a protobuf Role.
func roleToProto(r db.RolesProjection) *pm.Role {
	role := &pm.Role{
		Id:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Permissions: r.Permissions,
		IsSystem:    r.IsSystem,
	}

	role.CreatedAt = timestamppb.New(r.CreatedAt)

	return role
}
