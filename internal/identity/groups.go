package identity

import (
	"context"
	"errors"
	"math"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/encoding/protojson"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/maintenance"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/dynamicquery"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

const maxUserGroupBatch = 256

var (
	errUserGroupNoChange     = errors.New("user group mutation made no change")
	errUserGroupDynamic      = errors.New("dynamic user group membership is evaluator-owned")
	errUserGroupSCIMManaged  = errors.New("SCIM-managed user group")
	errUserGroupMemberAbsent = errors.New("user group member not found")
)

// CreateUserGroup creates one static or dynamic group in direct state.
func (h *Handlers) CreateUserGroup(ctx context.Context, req *connect.Request[pmv1.CreateUserGroupRequest]) (*connect.Response[pmv1.CreateUserGroupResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	permission := PermCreateStaticUserGroup
	var query *string
	if req.Msg.IsDynamic {
		permission = PermCreateDynamicUserGroup
		if err := dynamicquery.ValidateUserQuery(req.Msg.DynamicQuery); err != nil {
			return nil, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "invalid dynamic query")
		}
		query = &req.Msg.DynamicQuery
	} else if req.Msg.DynamicQuery != "" {
		return nil, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "static groups cannot carry a dynamic query")
	}
	if err := h.authorize(ctx, permission, ""); err != nil {
		return nil, err
	}

	id, at := ulid.Make().String(), h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, permission),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			if _, err := tx.InsertUserGroup(ctx, db.InsertUserGroupParams{
				ID: id, Name: req.Msg.Name, Description: req.Msg.Description,
				CreatedAt: at, CreatedBy: actor.ID, IsDynamic: req.Msg.IsDynamic, DynamicQuery: query,
			}); err != nil {
				return err
			}
			rec.Effect(userGroupEffect(id, "CREATE", "name", "description", "is_dynamic", "dynamic_query"))
			return nil
		})
	if err != nil {
		if store.IsConflict(err) {
			return nil, rpcError(ctx, ErrUserGroupNameExists, connect.CodeAlreadyExists, "user group name already exists")
		}
		return nil, internalError(ctx, "failed to create user group")
	}
	group, err := h.loadUserGroupProto(ctx, id, false)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.CreateUserGroupResponse{Group: group}), nil
}

// GetUserGroup returns one visible group and its live members.
func (h *Handlers) GetUserGroup(ctx context.Context, req *connect.Request[pmv1.GetUserGroupRequest]) (*connect.Response[pmv1.GetUserGroupResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if _, err := h.requireActor(ctx); err != nil {
		return nil, err
	}
	if err := h.enforceUserGroupScope(ctx, PermGetUserGroup, req.Msg.Id, true); err != nil {
		return nil, err
	}
	group, err := h.loadUserGroupProto(ctx, req.Msg.Id, true)
	if err != nil {
		return nil, err
	}
	rows, err := h.store.ListUserGroupMembers(ctx, req.Msg.Id)
	if err != nil {
		return nil, internalError(ctx, "failed to list user group members")
	}
	members := make([]*pmv1.UserGroupMember, len(rows))
	for i, row := range rows {
		members[i] = &pmv1.UserGroupMember{
			UserId: row.UserID, Email: row.Email, AddedAt: timestampValue(row.AddedAt),
		}
	}
	return connect.NewResponse(&pmv1.GetUserGroupResponse{Group: group, Members: members}), nil
}

// ListUserGroups returns one scoped keyset page.
func (h *Handlers) ListUserGroups(ctx context.Context, req *connect.Request[pmv1.ListUserGroupsRequest]) (*connect.Response[pmv1.ListUserGroupsResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if _, err := h.requireActor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermListUserGroups, ""); err != nil {
		return nil, err
	}
	if req.Msg.PageToken != "" {
		if _, err := ulid.ParseStrict(req.Msg.PageToken); err != nil {
			return nil, rpcError(ctx, ErrInvalidPageToken, connect.CodeInvalidArgument, "invalid page token")
		}
	}

	limit := pageLimit(req.Msg.PageSize)
	groups, restricted := auth.UserScopeListFilter(ctx, PermListUserGroups)
	filter := store.UserGroupListFilter{
		AfterID: req.Msg.PageToken, Limit: limit + 1,
		ScopeRestricted: restricted, ScopeGroupIDs: groups,
	}
	rows, err := h.store.ListUserGroups(ctx, filter)
	if err != nil {
		return nil, internalError(ctx, "failed to list user groups")
	}
	hasMore := len(rows) > int(limit)
	if hasMore {
		rows = rows[:limit]
	}
	count, err := h.store.CountUserGroups(ctx, filter)
	if err != nil {
		return nil, internalError(ctx, "failed to count user groups")
	}
	resp := &pmv1.ListUserGroupsResponse{TotalCount: boundedIdentityCount(count)}
	for _, row := range rows {
		group, err := userGroupToProto(row, nil)
		if err != nil {
			return nil, internalError(ctx, "failed to decode user group")
		}
		resp.Groups = append(resp.Groups, group)
	}
	if hasMore {
		resp.NextPageToken = rows[len(rows)-1].ID
	}
	return connect.NewResponse(resp), nil
}

// UpdateUserGroup replaces the editable group metadata.
func (h *Handlers) UpdateUserGroup(ctx context.Context, req *connect.Request[pmv1.UpdateUserGroupRequest]) (*connect.Response[pmv1.UpdateUserGroupResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.enforceUserGroupScope(ctx, PermUpdateUserGroup, req.Msg.GroupId, false); err != nil {
		return nil, err
	}
	at := h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermUpdateUserGroup),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			if _, err := tx.UpdateUserGroup(ctx, db.UpdateUserGroupParams{
				ID: req.Msg.GroupId, Name: req.Msg.Name, Description: req.Msg.Description, UpdatedAt: at,
			}); err != nil {
				return err
			}
			rec.Effect(userGroupEffect(req.Msg.GroupId, "UPDATE", "name", "description"))
			return nil
		})
	if err != nil {
		if store.IsConflict(err) {
			return nil, rpcError(ctx, ErrUserGroupNameExists, connect.CodeAlreadyExists, "user group name already exists")
		}
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrUserGroupNotFound, "user group not found")
		}
		return nil, internalError(ctx, "failed to update user group")
	}
	group, err := h.loadUserGroupProto(ctx, req.Msg.GroupId, true)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.UpdateUserGroupResponse{Group: group}), nil
}

// SetUserGroupMaintenanceWindow replaces one validated dispatch window.
func (h *Handlers) SetUserGroupMaintenanceWindow(ctx context.Context, req *connect.Request[pmv1.SetUserGroupMaintenanceWindowRequest]) (*connect.Response[pmv1.UpdateUserGroupResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if err := maintenance.Validate(req.Msg.MaintenanceWindow); err != nil {
		return nil, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "invalid maintenance window")
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.enforceUserGroupScope(ctx, PermSetUserGroupMaintenance, req.Msg.Id, false); err != nil {
		return nil, err
	}
	raw := []byte("{}")
	if req.Msg.MaintenanceWindow != nil && len(req.Msg.MaintenanceWindow.Schedule) > 0 {
		raw, err = protojson.Marshal(req.Msg.MaintenanceWindow)
		if err != nil {
			return nil, internalError(ctx, "failed to encode maintenance window")
		}
	}
	at := h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermSetUserGroupMaintenance),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			if _, err := tx.SetUserGroupMaintenanceWindow(ctx, db.SetUserGroupMaintenanceWindowParams{
				ID: req.Msg.Id, MaintenanceWindow: raw, UpdatedAt: at,
			}); err != nil {
				return err
			}
			rec.Effect(userGroupEffect(req.Msg.Id, "UPDATE", "maintenance_window"))
			return nil
		})
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrUserGroupNotFound, "user group not found")
		}
		return nil, internalError(ctx, "failed to set user group maintenance window")
	}
	group, err := h.loadUserGroupProto(ctx, req.Msg.Id, true)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.UpdateUserGroupResponse{Group: group}), nil
}

// DeleteUserGroup retires a group and removes its ordinary dependent state.
func (h *Handlers) DeleteUserGroup(ctx context.Context, req *connect.Request[pmv1.DeleteUserGroupRequest]) (*connect.Response[pmv1.DeleteUserGroupResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.enforceUserGroupScope(ctx, PermDeleteUserGroup, req.Msg.Id, false); err != nil {
		return nil, err
	}
	at := h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermDeleteUserGroup),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			if _, err := tx.GetUserGroup(ctx, req.Msg.Id); err != nil {
				return err
			}
			memberIDs, err := tx.ListUserGroupMemberIDs(ctx, req.Msg.Id)
			if err != nil {
				return err
			}
			managed, err := tx.IsUserGroupSCIMManaged(ctx, req.Msg.Id)
			if err != nil {
				return err
			}
			if managed {
				return errUserGroupSCIMManaged
			}
			affected, err := tx.BumpSessionsAffectedByUserGroupDelete(ctx, db.BumpSessionsAffectedByUserGroupDeleteParams{
				UpdatedAt: &at, GroupID: req.Msg.Id,
			})
			if err != nil {
				return err
			}
			if _, err := tx.DeleteUserGroupMembers(ctx, req.Msg.Id); err != nil {
				return err
			}
			if _, err := tx.DeleteUserGroupAssignments(ctx, req.Msg.Id); err != nil {
				return err
			}
			if _, err := tx.DeleteUserGroupRoleGrants(ctx, req.Msg.Id); err != nil {
				return err
			}
			if _, err := tx.DeleteUserGroupUserRoleScopes(ctx, &req.Msg.Id); err != nil {
				return err
			}
			if _, err := tx.DeleteUserGroupUserGroupRoleScopes(ctx, &req.Msg.Id); err != nil {
				return err
			}
			if _, err := tx.SoftDeleteUserGroup(ctx, db.SoftDeleteUserGroupParams{ID: req.Msg.Id, UpdatedAt: at}); err != nil {
				return err
			}
			rec.Effect(userGroupEffect(req.Msg.Id, "DELETE", "is_deleted"))
			if affected > 0 {
				effect := userGroupEffect(req.Msg.Id, "INVALIDATE_SESSIONS", "session_version")
				effect.AfterCount = &affected
				rec.Effect(effect)
			}
			for _, userID := range memberIDs {
				rec.RefreshSearch("user", userID)
			}
			return nil
		})
	if err != nil {
		switch {
		case errors.Is(err, errUserGroupSCIMManaged):
			return nil, rpcError(ctx, ErrSCIMManagedResource, connect.CodeFailedPrecondition, "SCIM-managed groups are deleted through their identity provider")
		case store.IsNotFound(err):
			return nil, notFound(ctx, ErrUserGroupNotFound, "user group not found")
		default:
			return nil, internalError(ctx, "failed to delete user group")
		}
	}
	return connect.NewResponse(&pmv1.DeleteUserGroupResponse{}), nil
}

// AddUserToGroup adds each requested user once to a static group.
func (h *Handlers) AddUserToGroup(ctx context.Context, req *connect.Request[pmv1.AddUserToGroupRequest]) (*connect.Response[pmv1.AddUserToGroupResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	ids := requestedUserIDs(req.Msg.UserId, req.Msg.UserIds)
	if len(ids) == 0 || len(ids) > maxUserGroupBatch {
		return nil, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "at least one user is required")
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.enforceUserGroupScope(ctx, PermAddUserToGroup, req.Msg.GroupId, false); err != nil {
		return nil, err
	}
	group, err := h.store.GetUserGroupView(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, h.userGroupReadError(ctx, err)
	}
	if group.IsDynamic {
		return nil, rpcError(ctx, ErrDynamicGroupMembership, connect.CodeFailedPrecondition, "dynamic group membership is evaluator-managed")
	}
	for _, id := range ids {
		if err := auth.EnforceUserScopeOrSelf(ctx, h.scopeResolver(), PermAddUserToGroup, id); err != nil {
			return nil, rpcError(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "permission denied")
		}
		if _, err := h.store.GetUser(ctx, id); err != nil {
			if store.IsNotFound(err) {
				return nil, notFound(ctx, ErrUserNotFound, "user not found")
			}
			return nil, internalError(ctx, "failed to load membership target")
		}
	}
	current, err := h.store.ListUserGroupMembers(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, internalError(ctx, "failed to list user group members")
	}
	present := make(map[string]struct{}, len(current))
	for _, member := range current {
		present[member.UserID] = struct{}{}
	}
	missing := ids[:0]
	for _, id := range ids {
		if _, ok := present[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		return connect.NewResponse(&pmv1.AddUserToGroupResponse{}), nil
	}

	at := h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermAddUserToGroup),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			stored, err := tx.GetUserGroup(ctx, req.Msg.GroupId)
			if err != nil {
				return err
			}
			if stored.IsDynamic {
				return errUserGroupDynamic
			}
			added := int64(0)
			for _, id := range missing {
				rows, err := tx.AddStaticUserGroupMember(ctx, db.AddStaticUserGroupMemberParams{
					GroupID: req.Msg.GroupId, UserID: id, AddedAt: at, AddedBy: actor.ID,
				})
				if err != nil {
					return err
				}
				if rows == 0 {
					continue
				}
				added += rows
				version, err := tx.BumpUserSessionVersion(ctx, db.BumpUserSessionVersionParams{ID: id, UpdatedAt: &at})
				if err != nil {
					return err
				}
				groupID := req.Msg.GroupId
				effect := store.AuditEffect{
					ResourceType: "user_group_member", ResourceID: id, Action: "ADD",
					Outcome: store.EffectApplied, ChangedFields: []string{"membership"}, AfterRef: &groupID,
				}
				rec.Effect(effect)
				v := int64(version)
				rec.Effect(store.AuditEffect{
					ResourceType: "user", ResourceID: id, Action: "INVALIDATE_SESSIONS",
					Outcome: store.EffectApplied, ChangedFields: []string{"session_version"}, AfterCount: &v,
				})
			}
			if added == 0 {
				return errUserGroupNoChange
			}
			rec.RefreshSearch("user_group", req.Msg.GroupId)
			return nil
		})
	if errors.Is(err, errUserGroupNoChange) {
		return connect.NewResponse(&pmv1.AddUserToGroupResponse{}), nil
	}
	if err != nil {
		if errors.Is(err, errUserGroupDynamic) {
			return nil, rpcError(ctx, ErrDynamicGroupMembership, connect.CodeFailedPrecondition, "dynamic group membership is evaluator-managed")
		}
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrUserGroupNotFound, "user group not found")
		}
		return nil, internalError(ctx, "failed to add user group members")
	}
	return connect.NewResponse(&pmv1.AddUserToGroupResponse{}), nil
}

// RemoveUserFromGroup removes one static membership.
func (h *Handlers) RemoveUserFromGroup(ctx context.Context, req *connect.Request[pmv1.RemoveUserFromGroupRequest]) (*connect.Response[pmv1.RemoveUserFromGroupResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.enforceUserGroupScope(ctx, PermRemoveUserFromGroup, req.Msg.GroupId, false); err != nil {
		return nil, err
	}
	group, err := h.store.GetUserGroupView(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, h.userGroupReadError(ctx, err)
	}
	if group.IsDynamic {
		return nil, rpcError(ctx, ErrDynamicGroupMembership, connect.CodeFailedPrecondition, "dynamic group membership is evaluator-managed")
	}
	at := h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermRemoveUserFromGroup),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			stored, err := tx.GetUserGroup(ctx, req.Msg.GroupId)
			if err != nil {
				return err
			}
			if stored.IsDynamic {
				return errUserGroupDynamic
			}
			rows, err := tx.RemoveStaticUserGroupMember(ctx, db.RemoveStaticUserGroupMemberParams{
				GroupID: req.Msg.GroupId, UserID: req.Msg.UserId,
			})
			if err != nil {
				return err
			}
			if rows == 0 {
				return errUserGroupMemberAbsent
			}
			version, err := tx.BumpUserSessionVersion(ctx, db.BumpUserSessionVersionParams{ID: req.Msg.UserId, UpdatedAt: &at})
			if err != nil {
				return err
			}
			groupID := req.Msg.GroupId
			rec.Effect(store.AuditEffect{
				ResourceType: "user_group_member", ResourceID: req.Msg.UserId, Action: "REMOVE",
				Outcome: store.EffectApplied, ChangedFields: []string{"membership"}, BeforeRef: &groupID,
			})
			v := int64(version)
			rec.Effect(store.AuditEffect{
				ResourceType: "user", ResourceID: req.Msg.UserId, Action: "INVALIDATE_SESSIONS",
				Outcome: store.EffectApplied, ChangedFields: []string{"session_version"}, AfterCount: &v,
			})
			rec.RefreshSearch("user_group", req.Msg.GroupId)
			return nil
		})
	if err != nil {
		switch {
		case errors.Is(err, errUserGroupDynamic):
			return nil, rpcError(ctx, ErrDynamicGroupMembership, connect.CodeFailedPrecondition, "dynamic group membership is evaluator-managed")
		case errors.Is(err, errUserGroupMemberAbsent):
			return nil, notFound(ctx, ErrUserGroupMemberNotFound, "user group member not found")
		case store.IsNotFound(err):
			return nil, notFound(ctx, ErrUserGroupNotFound, "user group not found")
		default:
			return nil, internalError(ctx, "failed to remove user group member")
		}
	}
	return connect.NewResponse(&pmv1.RemoveUserFromGroupResponse{}), nil
}

// ListUserGroupsForUser returns visible groups containing one subject.
func (h *Handlers) ListUserGroupsForUser(ctx context.Context, req *connect.Request[pmv1.ListUserGroupsForUserRequest]) (*connect.Response[pmv1.ListUserGroupsForUserResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if _, err := h.resolveUserTarget(ctx, PermListUserGroupsForUser, req.Msg.UserId); err != nil {
		return nil, err
	}
	groups, restricted := auth.UserScopeListFilter(ctx, PermListUserGroupsForUser)
	rows, err := h.store.ListUserGroupsForUser(ctx, req.Msg.UserId, store.UserGroupListFilter{
		ScopeRestricted: restricted, ScopeGroupIDs: groups,
	})
	if err != nil {
		return nil, internalError(ctx, "failed to list user groups for user")
	}
	resp := &pmv1.ListUserGroupsForUserResponse{}
	for _, row := range rows {
		group, err := userGroupToProto(row, nil)
		if err != nil {
			return nil, internalError(ctx, "failed to decode user group")
		}
		resp.Groups = append(resp.Groups, group)
	}
	return connect.NewResponse(resp), nil
}

// UpdateUserGroupQuery changes the query or materializes an existing dynamic
// group as static. Static groups cannot be converted through this RPC.
func (h *Handlers) UpdateUserGroupQuery(ctx context.Context, req *connect.Request[pmv1.UpdateUserGroupQueryRequest]) (*connect.Response[pmv1.UpdateUserGroupQueryResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermUpdateDynamicUserGroup, req.Msg.Id); err != nil {
		return nil, err
	}
	var query *string
	if req.Msg.IsDynamic {
		if dynamicquery.ValidateUserQuery(req.Msg.DynamicQuery) != nil {
			return nil, rpcError(ctx, ErrInvalidDynamicQuery, connect.CodeInvalidArgument, "invalid dynamic query")
		}
		query = &req.Msg.DynamicQuery
	} else if req.Msg.DynamicQuery != "" {
		return nil, rpcError(ctx, ErrInvalidDynamicQuery, connect.CodeInvalidArgument, "static groups cannot carry a dynamic query")
	}

	at := h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermUpdateDynamicUserGroup),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			current, err := tx.GetDynamicUserGroupQueryForUpdate(ctx, req.Msg.Id)
			if err != nil {
				return err
			}
			if !current.IsDynamic {
				return errUserGroupNotDynamic
			}
			if _, err := tx.UpdateUserGroupQuery(ctx, db.UpdateUserGroupQueryParams{
				ID: req.Msg.Id, IsDynamic: req.Msg.IsDynamic, DynamicQuery: query, UpdatedAt: at,
			}); err != nil {
				return err
			}
			rec.Effect(userGroupEffect(req.Msg.Id, "UPDATE", "is_dynamic", "dynamic_query"))
			return nil
		})
	if err != nil {
		switch {
		case errors.Is(err, errUserGroupNotDynamic):
			return nil, rpcError(ctx, ErrGroupNotDynamic, connect.CodeFailedPrecondition, "group is not dynamic")
		case store.IsNotFound(err):
			return nil, notFound(ctx, ErrUserGroupNotFound, "user group not found")
		default:
			return nil, internalError(ctx, "failed to update user group query")
		}
	}
	group, err := h.loadUserGroupProto(ctx, req.Msg.Id, true)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.UpdateUserGroupQueryResponse{Group: group}), nil
}

// ValidateUserGroupQuery validates a query and previews its current match count.
func (h *Handlers) ValidateUserGroupQuery(ctx context.Context, req *connect.Request[pmv1.ValidateUserGroupQueryRequest]) (*connect.Response[pmv1.ValidateUserGroupQueryResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if _, err := h.requireActor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermValidateUserGroupQuery, ""); err != nil {
		return nil, err
	}
	if dynamicquery.ValidateUserQuery(req.Msg.Query) != nil {
		return connect.NewResponse(&pmv1.ValidateUserGroupQueryResponse{Valid: false, Error: "invalid query"}), nil
	}
	count, err := h.countMatchingUsers(ctx, req.Msg.Query)
	if err != nil {
		return nil, internalError(ctx, "failed to count dynamic user group matches")
	}
	return connect.NewResponse(&pmv1.ValidateUserGroupQueryResponse{
		Valid: true, MatchingUserCount: boundedIdentityCount(count),
	}), nil
}

// EvaluateDynamicUserGroup reconciles one dynamic group's membership.
func (h *Handlers) EvaluateDynamicUserGroup(ctx context.Context, req *connect.Request[pmv1.EvaluateDynamicUserGroupRequest]) (*connect.Response[pmv1.EvaluateDynamicUserGroupResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermEvaluateDynamicGroup, req.Msg.Id); err != nil {
		return nil, err
	}
	result, err := h.evaluateDynamicUserGroup(ctx, h.mutationOp(req, actor, PermEvaluateDynamicGroup), req.Msg.Id, actor.ID)
	if err != nil {
		switch {
		case errors.Is(err, errUserGroupNotDynamic):
			return nil, rpcError(ctx, ErrGroupNotDynamic, connect.CodeFailedPrecondition, "group is not dynamic")
		case errors.Is(err, errUserGroupInvalidQuery):
			return nil, rpcError(ctx, ErrInvalidDynamicQuery, connect.CodeFailedPrecondition, "dynamic group query is invalid")
		case store.IsNotFound(err):
			return nil, notFound(ctx, ErrUserGroupNotFound, "user group not found")
		default:
			return nil, internalError(ctx, "failed to evaluate dynamic user group")
		}
	}
	group, err := h.loadUserGroupProto(ctx, req.Msg.Id, true)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.EvaluateDynamicUserGroupResponse{
		Group: group, UsersAdded: boundedIdentityCount(result.added), UsersRemoved: boundedIdentityCount(result.removed),
	}), nil
}

func (h *Handlers) enforceUserGroupScope(ctx context.Context, permission, groupID string, hide bool) error {
	if err := auth.EnforceUserGroupScope(ctx, permission, groupID); err != nil {
		if hide {
			return notFound(ctx, ErrUserGroupNotFound, "user group not found")
		}
		return rpcError(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "permission denied")
	}
	return nil
}

func (h *Handlers) loadUserGroupProto(ctx context.Context, id string, includeGrants bool) (*pmv1.UserGroup, error) {
	row, err := h.store.GetUserGroupView(ctx, id)
	if err != nil {
		return nil, h.userGroupReadError(ctx, err)
	}
	var grants []store.GroupRoleGrantRow
	if includeGrants {
		grants, err = h.store.ListUserGroupRoleGrants(ctx, id)
		if err != nil {
			return nil, internalError(ctx, "failed to list user group role grants")
		}
	}
	group, err := userGroupToProto(row, grants)
	if err != nil {
		return nil, internalError(ctx, "failed to decode user group")
	}
	return group, nil
}

func (h *Handlers) userGroupReadError(ctx context.Context, err error) error {
	if store.IsNotFound(err) {
		return notFound(ctx, ErrUserGroupNotFound, "user group not found")
	}
	return internalError(ctx, "failed to load user group")
}

func requestedUserIDs(single string, many []string) []string {
	out := make([]string, 0, len(many)+1)
	seen := make(map[string]struct{}, len(many)+1)
	for _, id := range append([]string{single}, many...) {
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func boundedIdentityCount(n int64) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(n)
}

func userGroupEffect(id, action string, fields ...string) store.AuditEffect {
	return store.AuditEffect{
		ResourceType: "user_group", ResourceID: id, Action: action,
		Outcome: store.EffectApplied, ChangedFields: fields,
	}
}
