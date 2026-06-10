package api

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
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

	// Check name uniqueness — distinguishing NotFound from a transient
	// DB error matters: silently treating any error as "name available"
	// would let a concurrent CreateRole succeed twice on a flaky DB.
	_, err := h.store.Repos().Role.GetByName(ctx, req.Msg.Name)
	if err == nil {
		return nil, apiErrorCtx(ctx, ErrRoleNameExists, connect.CodeAlreadyExists, "role name already exists")
	}
	if !store.IsNotFound(err) {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to check role name uniqueness")
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Privilege ceiling: a caller can only create a role with permissions they
	// themselves hold, else any role-management holder could mint an Admin-level
	// role and escalate (#365).
	if err := assertCanGrant(ctx, req.Msg.Permissions); err != nil {
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
		EventType:  string(eventtypes.RoleCreated),
		Data: payloads.RoleCreated{
			Name:        req.Msg.Name,
			Description: req.Msg.Description,
			Permissions: perms,
			IsSystem:    false,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to create role"); err != nil {
		return nil, err
	}

	role, err := h.store.Repos().Role.Get(ctx, id)
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

	role, err := h.store.Repos().Role.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrRoleNotFound, "role not found")
	}

	userCount, err := h.store.Repos().Role.CountUsersWithRole(ctx, req.Msg.Id)
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
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	pageSize, offset, err := parsePagination(int32(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, err
	}

	roles, err := h.store.Repos().Role.List(ctx, store.ListRolesFilter{
		Limit:  pageSize,
		Offset: offset,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list roles")
	}

	count, err := h.store.Repos().Role.Count(ctx)
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

	role, err := h.store.Repos().Role.Get(ctx, req.Msg.RoleId)
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

	// Privilege ceiling: a caller can only set a role's permissions to ones
	// they themselves hold, else a role-management holder could rewrite a role
	// to confer Admin-level permissions and escalate (#365).
	if err := assertCanGrant(ctx, req.Msg.Permissions); err != nil {
		return nil, err
	}

	perms := req.Msg.Permissions
	if perms == nil {
		perms = []string{}
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "role",
		StreamID:   req.Msg.RoleId,
		EventType:  string(eventtypes.RoleUpdated),
		Data: payloads.RoleUpdated{
			Name:        req.Msg.Name,
			Description: req.Msg.Description,
			Permissions: perms,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to update role"); err != nil {
		return nil, err
	}

	// Bump session_version for all users with this role to invalidate cached permissions
	h.bumpSessionVersionForRole(ctx, req.Msg.RoleId, userCtx.ID)

	updated, err := h.store.Repos().Role.Get(ctx, req.Msg.RoleId)
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

	role, err := h.store.Repos().Role.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrRoleNotFound, "role not found")
	}

	if role.IsSystem {
		return nil, apiErrorCtx(ctx, ErrCannotDeleteSystemRole, connect.CodeFailedPrecondition, "cannot delete system role")
	}

	userCount, err := h.store.Repos().Role.CountUsersWithRole(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count users")
	}
	if userCount > 0 {
		return nil, apiErrorCtx(ctx, ErrRoleInUse, connect.CodeFailedPrecondition, fmt.Sprintf("role still has %d assigned users", userCount))
	}

	groupCount, err := h.store.Repos().Role.CountGroupsWithRole(ctx, req.Msg.Id)
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
		EventType:  string(eventtypes.RoleDeleted),
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

	// Validate the optional grant scope (paired-or-neither, AssignRoleScope
	// gate + escalation bound, group existence). Role-independent (#7 S5).
	scopeKind, scopeID, err := validateAssignGrantScope(ctx, q, req.Msg.ScopeKind, req.Msg.ScopeId)
	if err != nil {
		return nil, err
	}

	assignedAny := false
	for _, roleID := range roleIDs {
		// Verify role exists
		role, err := q.GetRoleByID(ctx, roleID)
		if err != nil {
			if store.IsNotFound(err) {
				return nil, apiErrorCtx(ctx, ErrRoleNotFound, connect.CodeNotFound, "role not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get role")
		}

		// Privilege ceiling (UNSCOPED/global grants only): a caller can only
		// globally assign a role whose permissions they hold, else any
		// AssignRoleToUser holder could grant themselves an Admin-level role and
		// escalate (#365). SCOPED grants are governed by the #7 device-group
		// scope model (AssignRoleScope + escalation bound); their full
		// enforcement lands in 2026.08, so the ceiling does not further restrict
		// them here.
		if scopeKind == "" {
			if err := assertCanGrant(ctx, role.Permissions); err != nil {
				return nil, err
			}
		}

		// Every permission in a scoped grant's role must accept this
		// scope kind (target_kind match) — a no-op for unscoped grants.
		if err := rejectUnscopableRole(ctx, scopeKind, role.Permissions); err != nil {
			return nil, err
		}

		// Unscoped grants are unique per (user, role) — skip a redundant
		// re-assign. Use the scope-aware UserHasUnscopedRole, NOT the
		// 2-tuple UserHasRole: an UNSCOPED grant must still be created when
		// a SCOPED grant of the same role already exists (#7 grants are
		// independent — global and per-scope coexist). Scoped grants skip
		// the pre-check entirely: the projector's INSERT ... ON CONFLICT
		// DO NOTHING (both partial unique indexes) makes a redundant scoped
		// re-assign an idempotent no-op.
		if scopeKind == "" {
			hasRole, err := q.UserHasUnscopedRole(ctx, db.UserHasUnscopedRoleParams{
				UserID: req.Msg.UserId,
				RoleID: roleID,
			})
			if err != nil {
				return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to check role assignment")
			}
			if hasRole {
				continue
			}
		}

		sk, si := scopePtrs(scopeKind, scopeID)
		streamID := req.Msg.UserId + ":" + roleID
		if scopeKind != "" {
			streamID += ":" + scopeID
		}
		if err := appendEvent(ctx, h.store, h.logger, store.Event{
			StreamType: "user_role",
			StreamID:   streamID,
			EventType:  string(eventtypes.UserRoleAssigned),
			Data: payloads.UserRoleAssigned{
				UserID:    req.Msg.UserId,
				RoleID:    roleID,
				ScopeKind: sk,
				ScopeID:   si,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		}, "failed to assign role"); err != nil {
			return nil, err
		}
		assignedAny = true
	}

	// Only bump the session version if we actually assigned at least
	// one role. Idempotent no-op retries (all roles already assigned)
	// should not force an unnecessary re-login.
	if assignedAny {
		if err := h.bumpUserSessionVersion(ctx, req.Msg.UserId, userCtx.ID); err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to invalidate user session after role assignment")
		}
	}

	return connect.NewResponse(&pm.AssignRoleToUserResponse{}), nil
}

// RevokeRoleFromUser removes a role from a user.
func (h *RoleHandler) RevokeRoleFromUser(ctx context.Context, req *connect.Request[pm.RevokeRoleFromUserRequest]) (*connect.Response[pm.RevokeRoleFromUserResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Check if the role is the Admin system role
	role, err := h.store.Repos().Role.Get(ctx, req.Msg.RoleId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrRoleNotFound, "role not found")
	}

	// Prevent removing the last user from the Admin system role
	if role.IsSystem && role.Name == "Admin" {
		userCount, err := h.store.Repos().Role.CountUsersWithRole(ctx, req.Msg.RoleId)
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count users")
		}
		if userCount <= 1 {
			return nil, apiErrorCtx(ctx, ErrCannotRemoveLastAdmin, connect.CodeFailedPrecondition, "cannot remove last user from Admin role")
		}
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Resolve the scope tuple identifying WHICH grant to revoke.
	scopeKind, ok := scopeKindString(req.Msg.ScopeKind)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "unknown scope_kind")
	}
	scopeID := req.Msg.ScopeId
	if (scopeKind == "") != (scopeID == "") {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "scope_kind and scope_id must be set together")
	}
	sk, si := scopePtrs(scopeKind, scopeID)

	q := h.store.Queries()
	// Does the SPECIFIC targeted grant exist?
	hasScoped, err := q.UserHasScopedRole(ctx, db.UserHasScopedRoleParams{
		UserID: req.Msg.UserId, RoleID: req.Msg.RoleId, ScopeKind: sk, ScopeID: si,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to check role assignment")
	}

	if hasScoped {
		streamID := req.Msg.UserId + ":" + req.Msg.RoleId
		if scopeKind != "" {
			streamID += ":" + scopeID
		}
		if err := appendEvent(ctx, h.store, h.logger, store.Event{
			StreamType: "user_role",
			StreamID:   streamID,
			EventType:  string(eventtypes.UserRoleRevoked),
			Data: payloads.UserRoleRevoked{
				UserID:    req.Msg.UserId,
				RoleID:    req.Msg.RoleId,
				ScopeKind: sk,
				ScopeID:   si,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		}, "failed to revoke role"); err != nil {
			return nil, err
		}
	} else {
		// The targeted grant doesn't exist. If the role IS assigned at a
		// different scope, the caller targeted the wrong grant — surface
		// that rather than silently no-op (#7 S5).
		hasAny, err := h.store.Repos().Role.UserHasRole(ctx, req.Msg.UserId, req.Msg.RoleId)
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to check role assignment")
		}
		if hasAny {
			return nil, apiErrorCtx(ctx, ErrRoleNotFound, connect.CodeFailedPrecondition,
				"role is not assigned at the specified scope (it is assigned at a different scope)")
		}
		// Nothing assigned anywhere — idempotent no-op: no event, and no
		// session bump (nothing changed). Matches RevokeRoleFromUserGroup.
		return connect.NewResponse(&pm.RevokeRoleFromUserResponse{}), nil
	}

	// A grant was revoked — bump the user's session version to invalidate
	// cached permissions.
	if err := h.bumpUserSessionVersion(ctx, req.Msg.UserId, userCtx.ID); err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to invalidate user session after role revocation")
	}

	return connect.NewResponse(&pm.RevokeRoleFromUserResponse{}), nil
}

// ListPermissions returns all available permissions.
func (h *RoleHandler) ListPermissions(ctx context.Context, req *connect.Request[pm.ListPermissionsRequest]) (*connect.Response[pm.ListPermissionsResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	allPerms := auth.AllPermissions()
	protoPerms := make([]*pm.PermissionInfo, len(allPerms))
	for i, p := range allPerms {
		protoPerms[i] = &pm.PermissionInfo{
			Key:         p.Key,
			Group:       p.Group,
			Description: p.Description,
			TargetKind:  targetKindToProto(p.TargetKind),
		}
	}

	return connect.NewResponse(&pm.ListPermissionsResponse{
		Permissions: protoPerms,
	}), nil
}

// targetKindToProto maps the auth-package PermissionTargetKind to
// its proto wire form. server #7.
func targetKindToProto(k auth.PermissionTargetKind) pm.PermissionTargetKind {
	switch k {
	case auth.TargetDevice:
		return pm.PermissionTargetKind_PERMISSION_TARGET_KIND_DEVICE
	case auth.TargetUser:
		return pm.PermissionTargetKind_PERMISSION_TARGET_KIND_USER
	default:
		return pm.PermissionTargetKind_PERMISSION_TARGET_KIND_UNSPECIFIED
	}
}

// bumpUserSessionVersion increments a user's session_version to
// invalidate JWT/permission cache. This is a primary CQRS mutation:
// if the event fails to persist, the session is NOT invalidated and
// existing JWTs keep working. Returns an error so callers can
// surface the failure.
func (h *RoleHandler) bumpUserSessionVersion(ctx context.Context, userID, actorID string) error {
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  string(eventtypes.UserSessionInvalidated),
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    actorID,
	}); err != nil {
		h.logger.Error("failed to invalidate user session",
			"user_id", userID, "error", err)
		return err
	}
	h.logger.Debug("event appended",
		"stream_type", "user",
		"stream_id", userID,
		"event_type", "UserSessionInvalidated",
	)
	return nil
}

// bumpSessionVersionForRole bumps session_version for all users with
// a given role (directly assigned or via user groups). Best-effort
// across all members: logs failures but does not stop on the first
// one, because a partial invalidation (some members bumped, some
// not) is better than invalidating nobody. The callers that trigger
// this (UpdateRole) are already committed — the role change event
// is persisted. The session bumps are a follow-up consistency step.
func (h *RoleHandler) bumpSessionVersionForRole(ctx context.Context, roleID, actorID string) {
	seen := make(map[string]bool)

	// Direct role assignments
	userIDs, err := h.store.Repos().Role.ListUserIDsWithRole(ctx, roleID)
	if err != nil {
		h.logger.Error("failed to list users with role for session invalidation",
			"role_id", roleID, "error", err)
	} else {
		for _, uid := range userIDs {
			if !seen[uid] {
				if err := h.bumpUserSessionVersion(ctx, uid, actorID); err != nil {
					// Logged inside bumpUserSessionVersion. Continue
					// to the next member — partial > none.
				}
				seen[uid] = true
			}
		}
	}

	// User group role assignments
	groupUserIDs, err := h.store.Repos().Role.ListUserIDsWithGroupRole(ctx, roleID)
	if err != nil {
		h.logger.Error("failed to list group users with role for session invalidation",
			"role_id", roleID, "error", err)
	} else {
		for _, uid := range groupUserIDs {
			if !seen[uid] {
				if err := h.bumpUserSessionVersion(ctx, uid, actorID); err != nil {
					// Same — partial > none.
				}
				seen[uid] = true
			}
		}
	}
}

// roleToProto converts a domain Role to a protobuf Role.
func roleToProto(r store.Role) *pm.Role {
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
