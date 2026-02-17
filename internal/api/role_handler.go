package api

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"time"

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
	store   *store.Store
	entropy *ulid.MonotonicEntropy
}

// NewRoleHandler creates a new role handler.
func NewRoleHandler(st *store.Store) *RoleHandler {
	return &RoleHandler{
		store:   st,
		entropy: ulid.Monotonic(rand.Reader, 0),
	}
}

// CreateRole creates a new role.
func (h *RoleHandler) CreateRole(ctx context.Context, req *connect.Request[pm.CreateRoleRequest]) (*connect.Response[pm.CreateRoleResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Validate permissions
	validPerms := auth.ValidPermissionKeys()
	for _, p := range req.Msg.Permissions {
		if !validPerms[p] {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid permission: %s", p))
		}
	}

	// Check name uniqueness
	_, err := h.store.Queries().GetRoleByName(ctx, req.Msg.Name)
	if err == nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("role name already exists"))
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	id := ulid.MustNew(ulid.Timestamp(time.Now()), h.entropy).String()

	permsJSON, _ := json.Marshal(req.Msg.Permissions)

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "role",
		StreamID:   id,
		EventType:  "RoleCreated",
		Data: map[string]any{
			"name":        req.Msg.Name,
			"description": req.Msg.Description,
			"permissions": json.RawMessage(permsJSON),
			"is_system":   false,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create role"))
	}

	role, err := h.store.Queries().GetRoleByID(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to read role"))
	}

	return connect.NewResponse(&pm.CreateRoleResponse{
		Role: roleToProto(role),
	}), nil
}

// GetRole returns a role by ID.
func (h *RoleHandler) GetRole(ctx context.Context, req *connect.Request[pm.GetRoleRequest]) (*connect.Response[pm.GetRoleResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	role, err := h.store.Queries().GetRoleByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get role"))
	}

	userCount, err := h.store.Queries().CountUsersWithRole(ctx, req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to count users"))
	}

	return connect.NewResponse(&pm.GetRoleResponse{
		Role:      roleToProto(role),
		UserCount: int32(userCount),
	}), nil
}

// ListRoles returns a paginated list of roles.
func (h *RoleHandler) ListRoles(ctx context.Context, req *connect.Request[pm.ListRolesRequest]) (*connect.Response[pm.ListRolesResponse], error) {
	pageSize := int32(req.Msg.PageSize)
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50
	}

	offset := int32(0)
	if req.Msg.PageToken != "" {
		offset64, err := parsePageToken(req.Msg.PageToken)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid page token"))
		}
		offset = int32(offset64)
	}

	roles, err := h.store.Queries().ListRoles(ctx, db.ListRolesParams{
		Limit:  pageSize,
		Offset: offset,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list roles"))
	}

	count, err := h.store.Queries().CountRoles(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to count roles"))
	}

	var nextPageToken string
	if int32(len(roles)) == pageSize && int64(offset)+int64(pageSize) < count {
		nextPageToken = formatPageToken(int64(offset) + int64(pageSize))
	}

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
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	role, err := h.store.Queries().GetRoleByID(ctx, req.Msg.RoleId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get role"))
	}

	// System roles can't have their name changed
	if role.IsSystem && req.Msg.Name != role.Name {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("cannot rename system role"))
	}

	// Validate permissions
	validPerms := auth.ValidPermissionKeys()
	for _, p := range req.Msg.Permissions {
		if !validPerms[p] {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid permission: %s", p))
		}
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	permsJSON, _ := json.Marshal(req.Msg.Permissions)

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "role",
		StreamID:   req.Msg.RoleId,
		EventType:  "RoleUpdated",
		Data: map[string]any{
			"name":        req.Msg.Name,
			"description": req.Msg.Description,
			"permissions": json.RawMessage(permsJSON),
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update role"))
	}

	// Bump session_version for all users with this role to invalidate cached permissions
	h.bumpSessionVersionForRole(ctx, req.Msg.RoleId, userCtx.ID)

	updated, err := h.store.Queries().GetRoleByID(ctx, req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to read role"))
	}

	return connect.NewResponse(&pm.UpdateRoleResponse{
		Role: roleToProto(updated),
	}), nil
}

// DeleteRole deletes a role.
func (h *RoleHandler) DeleteRole(ctx context.Context, req *connect.Request[pm.DeleteRoleRequest]) (*connect.Response[pm.DeleteRoleResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	role, err := h.store.Queries().GetRoleByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get role"))
	}

	if role.IsSystem {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("cannot delete system role"))
	}

	userCount, err := h.store.Queries().CountUsersWithRole(ctx, req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to count users"))
	}
	if userCount > 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("role still has %d assigned users", userCount))
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "role",
		StreamID:   req.Msg.Id,
		EventType:  "RoleDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete role"))
	}

	return connect.NewResponse(&pm.DeleteRoleResponse{}), nil
}

// AssignRoleToUser assigns a role to a user.
func (h *RoleHandler) AssignRoleToUser(ctx context.Context, req *connect.Request[pm.AssignRoleToUserRequest]) (*connect.Response[pm.AssignRoleToUserResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Verify role exists
	_, err := h.store.Queries().GetRoleByID(ctx, req.Msg.RoleId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get role"))
	}

	// Verify user exists
	_, err = h.store.Queries().GetUserByID(ctx, req.Msg.UserId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user"))
	}

	// Check if already assigned
	hasRole, err := h.store.Queries().UserHasRole(ctx, db.UserHasRoleParams{
		UserID: req.Msg.UserId,
		RoleID: req.Msg.RoleId,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to check role assignment"))
	}
	if hasRole {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("user already has this role"))
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	streamID := req.Msg.UserId + ":" + req.Msg.RoleId
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user_role",
		StreamID:   streamID,
		EventType:  "UserRoleAssigned",
		Data: map[string]any{
			"user_id": req.Msg.UserId,
			"role_id": req.Msg.RoleId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to assign role"))
	}

	// Bump user's session version to invalidate cached permissions
	h.bumpUserSessionVersion(ctx, req.Msg.UserId, userCtx.ID)

	return connect.NewResponse(&pm.AssignRoleToUserResponse{}), nil
}

// RevokeRoleFromUser removes a role from a user.
func (h *RoleHandler) RevokeRoleFromUser(ctx context.Context, req *connect.Request[pm.RevokeRoleFromUserRequest]) (*connect.Response[pm.RevokeRoleFromUserResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Check if the role is the Admin system role
	role, err := h.store.Queries().GetRoleByID(ctx, req.Msg.RoleId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get role"))
	}

	// Prevent removing the last user from the Admin system role
	if role.IsSystem && role.Name == "Admin" {
		userCount, err := h.store.Queries().CountUsersWithRole(ctx, req.Msg.RoleId)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to count users"))
		}
		if userCount <= 1 {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("cannot remove last user from Admin role"))
		}
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	streamID := req.Msg.UserId + ":" + req.Msg.RoleId
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user_role",
		StreamID:   streamID,
		EventType:  "UserRoleRevoked",
		Data: map[string]any{
			"user_id": req.Msg.UserId,
			"role_id": req.Msg.RoleId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to revoke role"))
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
	_ = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  "UserSessionInvalidated",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    actorID,
	})
}

// bumpSessionVersionForRole bumps session_version for all users with a given role.
func (h *RoleHandler) bumpSessionVersionForRole(ctx context.Context, roleID, actorID string) {
	userIDs, err := h.store.Queries().ListUserIDsWithRole(ctx, roleID)
	if err != nil {
		return
	}
	for _, uid := range userIDs {
		h.bumpUserSessionVersion(ctx, uid, actorID)
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

	if r.CreatedAt.Valid {
		role.CreatedAt = timestamppb.New(r.CreatedAt.Time)
	}

	return role
}
