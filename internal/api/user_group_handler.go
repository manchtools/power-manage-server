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
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// UserGroupHandler handles user group management RPCs.
type UserGroupHandler struct {
	store     *store.Store
	logger    *slog.Logger
	searchIdx *search.Index
}

// NewUserGroupHandler creates a new user group handler.
func NewUserGroupHandler(st *store.Store, logger *slog.Logger) *UserGroupHandler {
	return &UserGroupHandler{
		store:  st,
		logger: logger,
	}
}

// SetSearchIndex sets the search index for enqueuing index updates.
func (h *UserGroupHandler) SetSearchIndex(idx *search.Index) {
	h.searchIdx = idx
}

// enqueueUserGroupReindex enqueues a search index update for a user group.
func (h *UserGroupHandler) enqueueUserGroupReindex(ctx context.Context, g db.UserGroupsProjection) {
	if h.searchIdx == nil {
		return
	}
	isDynamic := "false"
	if g.IsDynamic {
		isDynamic = "true"
	}
	var createdAt int64
	if !g.CreatedAt.IsZero() {
		createdAt = g.CreatedAt.Unix()
	}
	data := &taskqueue.SearchEntityData{
		Name:        g.Name,
		Description: g.Description,
		IsDynamic:   isDynamic,
		MemberCount: g.MemberCount,
		CreatedAt:   createdAt,
	}
	if err := h.searchIdx.EnqueueReindex(ctx, search.ScopeUserGroup, g.ID, data); err != nil {
		h.logger.Warn("failed to enqueue search reindex", "scope", "user_group", "error", err)
	}
}

// CreateUserGroup creates a new user group.
func (h *UserGroupHandler) CreateUserGroup(ctx context.Context, req *connect.Request[pm.CreateUserGroupRequest]) (*connect.Response[pm.CreateUserGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Check name uniqueness
	_, err := h.store.Queries().GetUserGroupByName(ctx, req.Msg.Name)
	if err == nil {
		return nil, apiErrorCtx(ctx, ErrUserGroupNameExists, connect.CodeAlreadyExists, "user group name already exists")
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	id := ulid.Make().String()

	// Validate dynamic query if provided
	if req.Msg.IsDynamic && req.Msg.DynamicQuery != "" {
		validationErr, err := h.store.Queries().ValidateUserGroupQuery(ctx, req.Msg.DynamicQuery)
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to validate query")
		}
		if validationErr != "" {
			return nil, apiErrorCtx(ctx, ErrInvalidQuery, connect.CodeInvalidArgument, validationErr)
		}
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "user_group",
		StreamID:   id,
		EventType:  "UserGroupCreated",
		Data: map[string]any{
			"name":          req.Msg.Name,
			"description":   req.Msg.Description,
			"is_dynamic":    req.Msg.IsDynamic,
			"dynamic_query": req.Msg.DynamicQuery,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to create user group"); err != nil {
		return nil, err
	}

	group, err := h.store.Queries().GetUserGroupByID(ctx, id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to read user group")
	}

	h.enqueueUserGroupReindex(ctx, group)

	return connect.NewResponse(&pm.CreateUserGroupResponse{
		Group: userGroupToProto(group, nil, false),
	}), nil
}

// GetUserGroup returns a user group by ID with members and roles.
func (h *UserGroupHandler) GetUserGroup(ctx context.Context, req *connect.Request[pm.GetUserGroupRequest]) (*connect.Response[pm.GetUserGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	group, err := h.store.Queries().GetUserGroupByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserGroupNotFound, "user group not found")
	}

	roles, err := h.store.Queries().GetUserGroupRoles(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get group roles")
	}

	members, err := h.store.Queries().ListUserGroupMembers(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get group members")
	}

	protoMembers := make([]*pm.UserGroupMember, len(members))
	for i, m := range members {
		protoMembers[i] = &pm.UserGroupMember{
			UserId: m.UserID,
			Email:  m.Email,
		}
		protoMembers[i].AddedAt = timestamppb.New(m.AddedAt)
	}

	isScimManaged, _ := h.store.Queries().IsUserGroupSCIMManaged(ctx, req.Msg.Id)

	return connect.NewResponse(&pm.GetUserGroupResponse{
		Group:   userGroupToProto(group, roles, isScimManaged),
		Members: protoMembers,
	}), nil
}

// ListUserGroups returns a paginated list of user groups.
func (h *UserGroupHandler) ListUserGroups(ctx context.Context, req *connect.Request[pm.ListUserGroupsRequest]) (*connect.Response[pm.ListUserGroupsResponse], error) {
	pageSize, offset, err := parsePagination(int32(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, err
	}

	groups, err := h.store.Queries().ListUserGroups(ctx, db.ListUserGroupsParams{
		Limit:  pageSize,
		Offset: offset,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list user groups")
	}

	count, err := h.store.Queries().CountUserGroups(ctx)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count user groups")
	}

	nextPageToken := buildNextPageToken(int32(len(groups)), offset, pageSize, count)

	protoGroups := make([]*pm.UserGroup, len(groups))
	for i, g := range groups {
		roles, _ := h.store.Queries().GetUserGroupRoles(ctx, g.ID)
		isScimManaged, _ := h.store.Queries().IsUserGroupSCIMManaged(ctx, g.ID)
		protoGroups[i] = userGroupToProto(g, roles, isScimManaged)
	}

	return connect.NewResponse(&pm.ListUserGroupsResponse{
		Groups:        protoGroups,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// UpdateUserGroup updates a user group's name and description.
func (h *UserGroupHandler) UpdateUserGroup(ctx context.Context, req *connect.Request[pm.UpdateUserGroupRequest]) (*connect.Response[pm.UpdateUserGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	_, err := h.store.Queries().GetUserGroupByID(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserGroupNotFound, "user group not found")
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "user_group",
		StreamID:   req.Msg.GroupId,
		EventType:  "UserGroupUpdated",
		Data: map[string]any{
			"name":        req.Msg.Name,
			"description": req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to update user group"); err != nil {
		return nil, err
	}

	updated, err := h.store.Queries().GetUserGroupByID(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to read user group")
	}

	h.enqueueUserGroupReindex(ctx, updated)

	roles, _ := h.store.Queries().GetUserGroupRoles(ctx, req.Msg.GroupId)

	isScimManaged, _ := h.store.Queries().IsUserGroupSCIMManaged(ctx, req.Msg.GroupId)

	return connect.NewResponse(&pm.UpdateUserGroupResponse{
		Group: userGroupToProto(updated, roles, isScimManaged),
	}), nil
}

// DeleteUserGroup deletes a user group.
func (h *UserGroupHandler) DeleteUserGroup(ctx context.Context, req *connect.Request[pm.DeleteUserGroupRequest]) (*connect.Response[pm.DeleteUserGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	_, err := h.store.Queries().GetUserGroupByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserGroupNotFound, "user group not found")
	}

	// Prevent deletion of SCIM-managed groups
	isScimManaged, _ := h.store.Queries().IsUserGroupSCIMManaged(ctx, req.Msg.Id)
	if isScimManaged {
		return nil, apiErrorCtx(ctx, ErrSCIMManagedResource, connect.CodeFailedPrecondition, "cannot delete a SCIM-managed group — remove it from the identity provider instead")
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Bump session version for all members (they may lose permissions)
	h.bumpSessionVersionForGroupMembers(ctx, req.Msg.Id, userCtx.ID)

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "user_group",
		StreamID:   req.Msg.Id,
		EventType:  "UserGroupDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to delete user group"); err != nil {
		return nil, err
	}

	if h.searchIdx != nil {
		if err := h.searchIdx.EnqueueRemove(ctx, search.ScopeUserGroup, req.Msg.Id, nil); err != nil {
			h.logger.Warn("failed to enqueue search remove", "scope", "user_group", "error", err)
		}
	}

	return connect.NewResponse(&pm.DeleteUserGroupResponse{}), nil
}

// AddUserToGroup adds one or more users to a user group.
func (h *UserGroupHandler) AddUserToGroup(ctx context.Context, req *connect.Request[pm.AddUserToGroupRequest]) (*connect.Response[pm.AddUserToGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Collect user IDs from single + repeated fields
	userIDs := append([]string{}, req.Msg.UserIds...)
	if req.Msg.UserId != "" {
		userIDs = append(userIDs, req.Msg.UserId)
	}
	if len(userIDs) == 0 {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "at least one user_id or user_ids must be set")
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	q := h.store.Queries()

	// Verify group exists
	group, err := q.GetUserGroupByID(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserGroupNotFound, "user group not found")
	}

	if group.IsDynamic {
		return nil, apiErrorCtx(ctx, ErrDynamicGroupManualModify, connect.CodeFailedPrecondition, "cannot manually modify members of a dynamic group")
	}

	for _, userID := range userIDs {
		// Verify user exists
		_, err = q.GetUserByID(ctx, userID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeNotFound, "user not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
		}

		// Check if already a member — skip silently in batch
		isMember, err := q.IsUserInGroup(ctx, db.IsUserInGroupParams{
			GroupID: req.Msg.GroupId,
			UserID:  userID,
		})
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to check membership")
		}
		if isMember {
			continue
		}

		streamID := req.Msg.GroupId + ":" + userID
		if err := appendEvent(ctx, h.store, h.logger, store.Event{
			StreamType: "user_group",
			StreamID:   streamID,
			EventType:  "UserGroupMemberAdded",
			Data: map[string]any{
				"group_id": req.Msg.GroupId,
				"user_id":  userID,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		}, "failed to add user to group"); err != nil {
			return nil, err
		}

		// Bump user's session version (they may gain new permissions from group roles)
		h.bumpUserSessionVersion(ctx, userID, userCtx.ID)
	}

	// Re-read group for updated member_count and enqueue reindex
	if updatedGroup, err := q.GetUserGroupByID(ctx, req.Msg.GroupId); err == nil {
		h.enqueueUserGroupReindex(ctx, updatedGroup)
	}

	return connect.NewResponse(&pm.AddUserToGroupResponse{}), nil
}

// RemoveUserFromGroup removes a user from a user group.
func (h *UserGroupHandler) RemoveUserFromGroup(ctx context.Context, req *connect.Request[pm.RemoveUserFromGroupRequest]) (*connect.Response[pm.RemoveUserFromGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Verify group exists and is not dynamic
	group, err := h.store.Queries().GetUserGroupByID(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserGroupNotFound, "user group not found")
	}

	if group.IsDynamic {
		return nil, apiErrorCtx(ctx, ErrDynamicGroupManualModify, connect.CodeFailedPrecondition, "cannot manually modify members of a dynamic group")
	}

	// Verify membership
	isMember, err := h.store.Queries().IsUserInGroup(ctx, db.IsUserInGroupParams{
		GroupID: req.Msg.GroupId,
		UserID:  req.Msg.UserId,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to check membership")
	}
	if !isMember {
		return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeNotFound, "user is not a member of this group")
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	streamID := req.Msg.GroupId + ":" + req.Msg.UserId
	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "user_group",
		StreamID:   streamID,
		EventType:  "UserGroupMemberRemoved",
		Data: map[string]any{
			"group_id": req.Msg.GroupId,
			"user_id":  req.Msg.UserId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to remove user from group"); err != nil {
		return nil, err
	}

	// Bump user's session version (they may lose permissions from group roles)
	h.bumpUserSessionVersion(ctx, req.Msg.UserId, userCtx.ID)

	// Re-read group for updated member_count and enqueue reindex
	if updatedGroup, err := h.store.Queries().GetUserGroupByID(ctx, req.Msg.GroupId); err == nil {
		h.enqueueUserGroupReindex(ctx, updatedGroup)
	}

	return connect.NewResponse(&pm.RemoveUserFromGroupResponse{}), nil
}

// AssignRoleToUserGroup assigns one or more roles to a user group.
func (h *UserGroupHandler) AssignRoleToUserGroup(ctx context.Context, req *connect.Request[pm.AssignRoleToUserGroupRequest]) (*connect.Response[pm.AssignRoleToUserGroupResponse], error) {
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

	// Verify group exists
	_, err = q.GetUserGroupByID(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserGroupNotFound, "user group not found")
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
		hasRole, err := q.UserGroupHasRole(ctx, db.UserGroupHasRoleParams{
			GroupID: req.Msg.GroupId,
			RoleID:  roleID,
		})
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to check role assignment")
		}
		if hasRole {
			continue
		}

		streamID := req.Msg.GroupId + ":role:" + roleID
		if err := appendEvent(ctx, h.store, h.logger, store.Event{
			StreamType: "user_group",
			StreamID:   streamID,
			EventType:  "UserGroupRoleAssigned",
			Data: map[string]any{
				"group_id": req.Msg.GroupId,
				"role_id":  roleID,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		}, "failed to assign role to user group"); err != nil {
			return nil, err
		}
	}

	// Bump session version for all group members once (they gain new permissions)
	h.bumpSessionVersionForGroupMembers(ctx, req.Msg.GroupId, userCtx.ID)

	return connect.NewResponse(&pm.AssignRoleToUserGroupResponse{}), nil
}

// RevokeRoleFromUserGroup revokes a role from a user group.
func (h *UserGroupHandler) RevokeRoleFromUserGroup(ctx context.Context, req *connect.Request[pm.RevokeRoleFromUserGroupRequest]) (*connect.Response[pm.RevokeRoleFromUserGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Check if the role is assigned
	hasRole, err := h.store.Queries().UserGroupHasRole(ctx, db.UserGroupHasRoleParams{
		GroupID: req.Msg.GroupId,
		RoleID:  req.Msg.RoleId,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to check role assignment")
	}
	if !hasRole {
		return nil, apiErrorCtx(ctx, ErrRoleNotFound, connect.CodeNotFound, "user group does not have this role")
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	streamID := req.Msg.GroupId + ":role:" + req.Msg.RoleId
	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "user_group",
		StreamID:   streamID,
		EventType:  "UserGroupRoleRevoked",
		Data: map[string]any{
			"group_id": req.Msg.GroupId,
			"role_id":  req.Msg.RoleId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to revoke role from user group"); err != nil {
		return nil, err
	}

	// Bump session version for all group members (they may lose permissions)
	h.bumpSessionVersionForGroupMembers(ctx, req.Msg.GroupId, userCtx.ID)

	return connect.NewResponse(&pm.RevokeRoleFromUserGroupResponse{}), nil
}

// ListUserGroupsForUser returns all groups a user belongs to.
func (h *UserGroupHandler) ListUserGroupsForUser(ctx context.Context, req *connect.Request[pm.ListUserGroupsForUserRequest]) (*connect.Response[pm.ListUserGroupsForUserResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Verify user exists
	_, err := h.store.Queries().GetUserByID(ctx, req.Msg.UserId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserNotFound, "user not found")
	}

	groups, err := h.store.Queries().ListUserGroupsForUser(ctx, req.Msg.UserId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list user groups")
	}

	protoGroups := make([]*pm.UserGroup, len(groups))
	for i, g := range groups {
		roles, _ := h.store.Queries().GetUserGroupRoles(ctx, g.ID)
		isScimManaged, _ := h.store.Queries().IsUserGroupSCIMManaged(ctx, g.ID)
		protoGroups[i] = userGroupToProto(g, roles, isScimManaged)
	}

	return connect.NewResponse(&pm.ListUserGroupsForUserResponse{
		Groups: protoGroups,
	}), nil
}

// UpdateUserGroupQuery updates the dynamic query settings for a user group.
func (h *UserGroupHandler) UpdateUserGroupQuery(ctx context.Context, req *connect.Request[pm.UpdateUserGroupQueryRequest]) (*connect.Response[pm.UpdateUserGroupQueryResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Validate dynamic query if provided
	if req.Msg.IsDynamic && req.Msg.DynamicQuery != "" {
		validationErr, err := h.store.Queries().ValidateUserGroupQuery(ctx, req.Msg.DynamicQuery)
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to validate query")
		}
		if validationErr != "" {
			return nil, apiErrorCtx(ctx, ErrInvalidQuery, connect.CodeInvalidArgument, validationErr)
		}
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "user_group",
		StreamID:   req.Msg.Id,
		EventType:  "UserGroupQueryUpdated",
		Data: map[string]any{
			"is_dynamic":    req.Msg.IsDynamic,
			"dynamic_query": req.Msg.DynamicQuery,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to update query"); err != nil {
		return nil, err
	}

	group, err := h.store.Queries().GetUserGroupByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserGroupNotFound, "user group not found")
	}

	h.enqueueUserGroupReindex(ctx, group)

	roles, _ := h.store.Queries().GetUserGroupRoles(ctx, req.Msg.Id)
	isScimManaged, _ := h.store.Queries().IsUserGroupSCIMManaged(ctx, req.Msg.Id)

	return connect.NewResponse(&pm.UpdateUserGroupQueryResponse{
		Group: userGroupToProto(group, roles, isScimManaged),
	}), nil
}

// ValidateUserGroupQuery validates a user group dynamic query without creating a group.
func (h *UserGroupHandler) ValidateUserGroupQuery(ctx context.Context, req *connect.Request[pm.ValidateUserGroupQueryRequest]) (*connect.Response[pm.ValidateUserGroupQueryResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	validationErr, err := h.store.Queries().ValidateUserGroupQuery(ctx, req.Msg.Query)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to validate query")
	}

	if validationErr != "" {
		return connect.NewResponse(&pm.ValidateUserGroupQueryResponse{
			Valid: false,
			Error: validationErr,
		}), nil
	}

	// Count matching users
	matchingCount, err := h.store.Queries().CountMatchingUsersForQuery(ctx, req.Msg.Query)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count matching users")
	}

	return connect.NewResponse(&pm.ValidateUserGroupQueryResponse{
		Valid:             true,
		MatchingUserCount: int32(matchingCount),
	}), nil
}

// EvaluateDynamicUserGroup triggers re-evaluation of a dynamic user group.
func (h *UserGroupHandler) EvaluateDynamicUserGroup(ctx context.Context, req *connect.Request[pm.EvaluateDynamicUserGroupRequest]) (*connect.Response[pm.EvaluateDynamicUserGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Verify group exists and is dynamic
	group, err := h.store.Queries().GetUserGroupByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserGroupNotFound, "user group not found")
	}

	if !group.IsDynamic {
		return nil, apiErrorCtx(ctx, ErrGroupNotDynamic, connect.CodeFailedPrecondition, "group is not dynamic")
	}

	// Get current member count before evaluation
	membersBefore := group.MemberCount

	// Trigger evaluation
	err = h.store.Queries().EvaluateDynamicUserGroup(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to evaluate dynamic user group")
	}

	// Get updated group
	group, err = h.store.Queries().GetUserGroupByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user group")
	}

	// Calculate added/removed
	usersAdded := int32(0)
	usersRemoved := int32(0)
	if group.MemberCount > membersBefore {
		usersAdded = group.MemberCount - membersBefore
	} else if group.MemberCount < membersBefore {
		usersRemoved = membersBefore - group.MemberCount
	}

	h.enqueueUserGroupReindex(ctx, group)

	roles, _ := h.store.Queries().GetUserGroupRoles(ctx, req.Msg.Id)
	isScimManaged, _ := h.store.Queries().IsUserGroupSCIMManaged(ctx, req.Msg.Id)

	// Bump session versions for all current members (permissions may have changed)
	if userCtx, ok := auth.UserFromContext(ctx); ok {
		h.bumpSessionVersionForGroupMembers(ctx, req.Msg.Id, userCtx.ID)
	}

	return connect.NewResponse(&pm.EvaluateDynamicUserGroupResponse{
		Group:        userGroupToProto(group, roles, isScimManaged),
		UsersAdded:   usersAdded,
		UsersRemoved: usersRemoved,
	}), nil
}

// bumpUserSessionVersion increments a user's session_version to invalidate JWT/permission cache.
func (h *UserGroupHandler) bumpUserSessionVersion(ctx context.Context, userID, actorID string) {
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
			"request_id", middleware.RequestIDFromContext(ctx),
			"stream_type", "user",
			"stream_id", userID,
			"event_type", "UserSessionInvalidated",
		)
	}
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
func userGroupToProto(g db.UserGroupsProjection, roles []db.RolesProjection, isScimManaged bool) *pm.UserGroup {
	group := &pm.UserGroup{
		Id:            g.ID,
		Name:          g.Name,
		Description:   g.Description,
		MemberCount:   g.MemberCount,
		IsDynamic:     g.IsDynamic,
		IsScimManaged: isScimManaged,
	}

	if g.DynamicQuery != nil {
		group.DynamicQuery = *g.DynamicQuery
	}

	group.CreatedAt = timestamppb.New(g.CreatedAt)

	for _, r := range roles {
		group.Roles = append(group.Roles, roleToProto(r))
	}

	return group
}

// Suppress unused import warning
var _ = fmt.Sprintf
