package api

import (
	"context"
	"crypto/rand"
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

// UserGroupHandler handles user group management RPCs.
type UserGroupHandler struct {
	store   *store.Store
	entropy *ulid.MonotonicEntropy
}

// NewUserGroupHandler creates a new user group handler.
func NewUserGroupHandler(st *store.Store) *UserGroupHandler {
	return &UserGroupHandler{
		store:   st,
		entropy: ulid.Monotonic(rand.Reader, 0),
	}
}

// CreateUserGroup creates a new user group.
func (h *UserGroupHandler) CreateUserGroup(ctx context.Context, req *connect.Request[pm.CreateUserGroupRequest]) (*connect.Response[pm.CreateUserGroupResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Check name uniqueness
	_, err := h.store.Queries().GetUserGroupByName(ctx, req.Msg.Name)
	if err == nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("user group name already exists"))
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	id := ulid.MustNew(ulid.Timestamp(time.Now()), h.entropy).String()

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user_group",
		StreamID:   id,
		EventType:  "UserGroupCreated",
		Data: map[string]any{
			"name":        req.Msg.Name,
			"description": req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create user group"))
	}

	group, err := h.store.Queries().GetUserGroupByID(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to read user group"))
	}

	return connect.NewResponse(&pm.CreateUserGroupResponse{
		Group: userGroupToProto(group, nil),
	}), nil
}

// GetUserGroup returns a user group by ID with members and roles.
func (h *UserGroupHandler) GetUserGroup(ctx context.Context, req *connect.Request[pm.GetUserGroupRequest]) (*connect.Response[pm.GetUserGroupResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	group, err := h.store.Queries().GetUserGroupByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user group not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user group"))
	}

	roles, err := h.store.Queries().GetUserGroupRoles(ctx, req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get group roles"))
	}

	members, err := h.store.Queries().ListUserGroupMembers(ctx, req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get group members"))
	}

	protoMembers := make([]*pm.UserGroupMember, len(members))
	for i, m := range members {
		protoMembers[i] = &pm.UserGroupMember{
			UserId: m.UserID,
			Email:  m.Email,
		}
		if m.AddedAt.Valid {
			protoMembers[i].AddedAt = timestamppb.New(m.AddedAt.Time)
		}
	}

	return connect.NewResponse(&pm.GetUserGroupResponse{
		Group:   userGroupToProto(group, roles),
		Members: protoMembers,
	}), nil
}

// ListUserGroups returns a paginated list of user groups.
func (h *UserGroupHandler) ListUserGroups(ctx context.Context, req *connect.Request[pm.ListUserGroupsRequest]) (*connect.Response[pm.ListUserGroupsResponse], error) {
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

	groups, err := h.store.Queries().ListUserGroups(ctx, db.ListUserGroupsParams{
		Limit:  pageSize,
		Offset: offset,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list user groups"))
	}

	count, err := h.store.Queries().CountUserGroups(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to count user groups"))
	}

	var nextPageToken string
	if int32(len(groups)) == pageSize && int64(offset)+int64(pageSize) < count {
		nextPageToken = formatPageToken(int64(offset) + int64(pageSize))
	}

	protoGroups := make([]*pm.UserGroup, len(groups))
	for i, g := range groups {
		// Fetch roles for each group
		roles, _ := h.store.Queries().GetUserGroupRoles(ctx, g.ID)
		protoGroups[i] = userGroupToProto(g, roles)
	}

	return connect.NewResponse(&pm.ListUserGroupsResponse{
		Groups:        protoGroups,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// UpdateUserGroup updates a user group's name and description.
func (h *UserGroupHandler) UpdateUserGroup(ctx context.Context, req *connect.Request[pm.UpdateUserGroupRequest]) (*connect.Response[pm.UpdateUserGroupResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	_, err := h.store.Queries().GetUserGroupByID(ctx, req.Msg.GroupId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user group not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user group"))
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user_group",
		StreamID:   req.Msg.GroupId,
		EventType:  "UserGroupUpdated",
		Data: map[string]any{
			"name":        req.Msg.Name,
			"description": req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update user group"))
	}

	updated, err := h.store.Queries().GetUserGroupByID(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to read user group"))
	}

	roles, _ := h.store.Queries().GetUserGroupRoles(ctx, req.Msg.GroupId)

	return connect.NewResponse(&pm.UpdateUserGroupResponse{
		Group: userGroupToProto(updated, roles),
	}), nil
}

// DeleteUserGroup deletes a user group.
func (h *UserGroupHandler) DeleteUserGroup(ctx context.Context, req *connect.Request[pm.DeleteUserGroupRequest]) (*connect.Response[pm.DeleteUserGroupResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	_, err := h.store.Queries().GetUserGroupByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user group not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user group"))
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Bump session version for all members (they may lose permissions)
	h.bumpSessionVersionForGroupMembers(ctx, req.Msg.Id, userCtx.ID)

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user_group",
		StreamID:   req.Msg.Id,
		EventType:  "UserGroupDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete user group"))
	}

	return connect.NewResponse(&pm.DeleteUserGroupResponse{}), nil
}

// AddUserToGroup adds a user to a user group.
func (h *UserGroupHandler) AddUserToGroup(ctx context.Context, req *connect.Request[pm.AddUserToGroupRequest]) (*connect.Response[pm.AddUserToGroupResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Verify group exists
	_, err := h.store.Queries().GetUserGroupByID(ctx, req.Msg.GroupId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user group not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user group"))
	}

	// Verify user exists
	_, err = h.store.Queries().GetUserByID(ctx, req.Msg.UserId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user"))
	}

	// Check if already a member
	isMember, err := h.store.Queries().IsUserInGroup(ctx, db.IsUserInGroupParams{
		GroupID: req.Msg.GroupId,
		UserID:  req.Msg.UserId,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to check membership"))
	}
	if isMember {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("user is already a member of this group"))
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	streamID := req.Msg.GroupId + ":" + req.Msg.UserId
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user_group",
		StreamID:   streamID,
		EventType:  "UserGroupMemberAdded",
		Data: map[string]any{
			"group_id": req.Msg.GroupId,
			"user_id":  req.Msg.UserId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to add user to group"))
	}

	// Bump user's session version (they may gain new permissions from group roles)
	h.bumpUserSessionVersion(ctx, req.Msg.UserId, userCtx.ID)

	return connect.NewResponse(&pm.AddUserToGroupResponse{}), nil
}

// RemoveUserFromGroup removes a user from a user group.
func (h *UserGroupHandler) RemoveUserFromGroup(ctx context.Context, req *connect.Request[pm.RemoveUserFromGroupRequest]) (*connect.Response[pm.RemoveUserFromGroupResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Verify membership
	isMember, err := h.store.Queries().IsUserInGroup(ctx, db.IsUserInGroupParams{
		GroupID: req.Msg.GroupId,
		UserID:  req.Msg.UserId,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to check membership"))
	}
	if !isMember {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("user is not a member of this group"))
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	streamID := req.Msg.GroupId + ":" + req.Msg.UserId
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user_group",
		StreamID:   streamID,
		EventType:  "UserGroupMemberRemoved",
		Data: map[string]any{
			"group_id": req.Msg.GroupId,
			"user_id":  req.Msg.UserId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to remove user from group"))
	}

	// Bump user's session version (they may lose permissions from group roles)
	h.bumpUserSessionVersion(ctx, req.Msg.UserId, userCtx.ID)

	return connect.NewResponse(&pm.RemoveUserFromGroupResponse{}), nil
}

// AssignRoleToUserGroup assigns a role to a user group.
func (h *UserGroupHandler) AssignRoleToUserGroup(ctx context.Context, req *connect.Request[pm.AssignRoleToUserGroupRequest]) (*connect.Response[pm.AssignRoleToUserGroupResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Verify group exists
	_, err := h.store.Queries().GetUserGroupByID(ctx, req.Msg.GroupId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user group not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user group"))
	}

	// Verify role exists
	_, err = h.store.Queries().GetRoleByID(ctx, req.Msg.RoleId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get role"))
	}

	// Check if already assigned
	hasRole, err := h.store.Queries().UserGroupHasRole(ctx, db.UserGroupHasRoleParams{
		GroupID: req.Msg.GroupId,
		RoleID:  req.Msg.RoleId,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to check role assignment"))
	}
	if hasRole {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("user group already has this role"))
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	streamID := req.Msg.GroupId + ":role:" + req.Msg.RoleId
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user_group",
		StreamID:   streamID,
		EventType:  "UserGroupRoleAssigned",
		Data: map[string]any{
			"group_id": req.Msg.GroupId,
			"role_id":  req.Msg.RoleId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to assign role to user group"))
	}

	// Bump session version for all group members (they gain new permissions)
	h.bumpSessionVersionForGroupMembers(ctx, req.Msg.GroupId, userCtx.ID)

	return connect.NewResponse(&pm.AssignRoleToUserGroupResponse{}), nil
}

// RevokeRoleFromUserGroup revokes a role from a user group.
func (h *UserGroupHandler) RevokeRoleFromUserGroup(ctx context.Context, req *connect.Request[pm.RevokeRoleFromUserGroupRequest]) (*connect.Response[pm.RevokeRoleFromUserGroupResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Check if the role is assigned
	hasRole, err := h.store.Queries().UserGroupHasRole(ctx, db.UserGroupHasRoleParams{
		GroupID: req.Msg.GroupId,
		RoleID:  req.Msg.RoleId,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to check role assignment"))
	}
	if !hasRole {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("user group does not have this role"))
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	streamID := req.Msg.GroupId + ":role:" + req.Msg.RoleId
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user_group",
		StreamID:   streamID,
		EventType:  "UserGroupRoleRevoked",
		Data: map[string]any{
			"group_id": req.Msg.GroupId,
			"role_id":  req.Msg.RoleId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to revoke role from user group"))
	}

	// Bump session version for all group members (they may lose permissions)
	h.bumpSessionVersionForGroupMembers(ctx, req.Msg.GroupId, userCtx.ID)

	return connect.NewResponse(&pm.RevokeRoleFromUserGroupResponse{}), nil
}

// ListUserGroupsForUser returns all groups a user belongs to.
func (h *UserGroupHandler) ListUserGroupsForUser(ctx context.Context, req *connect.Request[pm.ListUserGroupsForUserRequest]) (*connect.Response[pm.ListUserGroupsForUserResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Verify user exists
	_, err := h.store.Queries().GetUserByID(ctx, req.Msg.UserId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user"))
	}

	groups, err := h.store.Queries().ListUserGroupsForUser(ctx, req.Msg.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list user groups"))
	}

	protoGroups := make([]*pm.UserGroup, len(groups))
	for i, g := range groups {
		roles, _ := h.store.Queries().GetUserGroupRoles(ctx, g.ID)
		protoGroups[i] = userGroupToProto(g, roles)
	}

	return connect.NewResponse(&pm.ListUserGroupsForUserResponse{
		Groups: protoGroups,
	}), nil
}

// bumpUserSessionVersion increments a user's session_version to invalidate JWT/permission cache.
func (h *UserGroupHandler) bumpUserSessionVersion(ctx context.Context, userID, actorID string) {
	_ = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  "UserSessionInvalidated",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    actorID,
	})
}

// bumpSessionVersionForGroupMembers bumps session_version for all members of a user group.
func (h *UserGroupHandler) bumpSessionVersionForGroupMembers(ctx context.Context, groupID, actorID string) {
	memberIDs, err := h.store.Queries().ListUserGroupMemberIDs(ctx, groupID)
	if err != nil {
		return
	}
	for _, uid := range memberIDs {
		h.bumpUserSessionVersion(ctx, uid, actorID)
	}
}

// userGroupToProto converts a database user group projection to a protobuf UserGroup.
func userGroupToProto(g db.UserGroupsProjection, roles []db.RolesProjection) *pm.UserGroup {
	group := &pm.UserGroup{
		Id:          g.ID,
		Name:        g.Name,
		Description: g.Description,
		MemberCount: g.MemberCount,
	}

	if g.CreatedAt.Valid {
		group.CreatedAt = timestamppb.New(g.CreatedAt.Time)
	}

	for _, r := range roles {
		group.Roles = append(group.Roles, roleToProto(r))
	}

	return group
}

// Suppress unused import warning
var _ = fmt.Sprintf
