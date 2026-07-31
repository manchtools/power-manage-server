package identity

import (
	"context"
	"slices"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// ListPermissions returns the permission registry, so a role builder
// can show what a role may contain and which scopes each key accepts.
func (h *Handlers) ListPermissions(ctx context.Context, req *connect.Request[pmv1.ListPermissionsRequest]) (*connect.Response[pmv1.ListPermissionsResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if _, err := h.requireActor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermListPermissions, ""); err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.ListPermissionsResponse{Permissions: permissionsToProto()}), nil
}

// CreateRole defines a new role.
//
// Every requested permission must be a registered key. An unknown key
// would sit in the array doing nothing — invisible dead weight in the
// role builder, and a silent authorization gap if it was a typo for a
// real one.
func (h *Handlers) CreateRole(ctx context.Context, req *connect.Request[pmv1.CreateRoleRequest]) (*connect.Response[pmv1.CreateRoleResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermCreateRole, ""); err != nil {
		return nil, err
	}
	perms, err := h.checkPermissionKeys(ctx, req.Msg.Permissions)
	if err != nil {
		return nil, err
	}

	roleID := ulid.Make().String()
	at := h.now().UTC()
	var created store.RoleRow
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermCreateRole),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			var err error
			created, err = tx.InsertRole(ctx, db.InsertRoleParams{
				ID:          roleID,
				Name:        req.Msg.Name,
				Description: req.Msg.Description,
				Permissions: perms,
				CreatedAt:   at,
				CreatedBy:   actor.ID,
			})
			if err != nil {
				return err
			}
			count := int64(len(perms))
			rec.Effect(store.AuditEffect{
				ResourceType:  "role",
				ResourceID:    roleID,
				Action:        "CREATE",
				Outcome:       store.EffectApplied,
				ChangedFields: []string{"name", "description", "permissions"},
				AfterCount:    &count,
			})
			return nil
		})
	if err != nil {
		if store.IsConflict(err) {
			return nil, rpcError(ctx, ErrRoleNameExists, connect.CodeAlreadyExists, "a role with that name already exists")
		}
		return nil, internalError(ctx, "failed to create role")
	}
	return connect.NewResponse(&pmv1.CreateRoleResponse{Role: roleToProto(created)}), nil
}

// GetRole returns one role and how many subjects hold it.
func (h *Handlers) GetRole(ctx context.Context, req *connect.Request[pmv1.GetRoleRequest]) (*connect.Response[pmv1.GetRoleResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if _, err := h.requireActor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermGetRole, req.Msg.Id); err != nil {
		return nil, err
	}
	role, err := h.store.GetRole(ctx, req.Msg.Id)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrRoleNotFound, "role not found")
		}
		return nil, internalError(ctx, "failed to load role")
	}
	holders, err := h.store.CountRoleHolders(ctx, role.ID)
	if err != nil {
		return nil, internalError(ctx, "failed to count role holders")
	}
	return connect.NewResponse(&pmv1.GetRoleResponse{
		Role:      roleToProto(role),
		UserCount: int32(holders),
	}), nil
}

// ListRoles pages the role catalogue.
func (h *Handlers) ListRoles(ctx context.Context, req *connect.Request[pmv1.ListRolesRequest]) (*connect.Response[pmv1.ListRolesResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if _, err := h.requireActor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermListRoles, ""); err != nil {
		return nil, err
	}
	limit := pageLimit(req.Msg.PageSize)
	rows, err := h.store.ListRoles(ctx, req.Msg.PageToken, limit)
	if err != nil {
		return nil, internalError(ctx, "failed to list roles")
	}
	total, err := h.store.CountRoles(ctx)
	if err != nil {
		return nil, internalError(ctx, "failed to count roles")
	}
	resp := &pmv1.ListRolesResponse{TotalCount: int32(total)}
	for _, r := range rows {
		resp.Roles = append(resp.Roles, roleToProto(r))
	}
	if len(rows) == int(limit) {
		resp.NextPageToken = rows[len(rows)-1].ID
	}
	return connect.NewResponse(resp), nil
}

// UpdateRole rewrites a role's name, description and permission set.
//
// System roles are refused: the reconciler rewrites their permissions
// from the code registry on every boot, so an edit here would be
// silently undone rather than rejected.
func (h *Handlers) UpdateRole(ctx context.Context, req *connect.Request[pmv1.UpdateRoleRequest]) (*connect.Response[pmv1.UpdateRoleResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermUpdateRole, req.Msg.RoleId); err != nil {
		return nil, err
	}
	before, err := h.store.GetRole(ctx, req.Msg.RoleId)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrRoleNotFound, "role not found")
		}
		return nil, internalError(ctx, "failed to load role")
	}
	if before.IsSystem {
		return nil, rpcError(ctx, ErrCannotModifySystemRole, connect.CodeFailedPrecondition, "system roles are managed by the server")
	}
	perms, err := h.checkPermissionKeys(ctx, req.Msg.Permissions)
	if err != nil {
		return nil, err
	}

	at := h.now().UTC()
	var updated store.RoleRow
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermUpdateRole),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			var err error
			updated, err = tx.UpdateRole(ctx, db.UpdateRoleParams{
				ID:          before.ID,
				Name:        req.Msg.Name,
				Description: req.Msg.Description,
				Permissions: perms,
				UpdatedAt:   &at,
			})
			if err != nil {
				return err
			}
			// Changing what a role may do changes what everyone holding
			// it may do, so every session minted under the old
			// permission set is invalidated in the same transaction.
			if err := h.invalidateRoleHolderSessions(ctx, tx, rec, before.ID); err != nil {
				return err
			}
			beforeCount := int64(len(before.Permissions))
			afterCount := int64(len(perms))
			rec.Effect(store.AuditEffect{
				ResourceType:  "role",
				ResourceID:    before.ID,
				Action:        "UPDATE",
				Outcome:       store.EffectApplied,
				ChangedFields: []string{"name", "description", "permissions"},
				BeforeCount:   &beforeCount,
				AfterCount:    &afterCount,
			})
			return nil
		})
	if err != nil {
		if store.IsConflict(err) {
			return nil, rpcError(ctx, ErrRoleNameExists, connect.CodeAlreadyExists, "a role with that name already exists")
		}
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrRoleNotFound, "role not found")
		}
		return nil, internalError(ctx, "failed to update role")
	}
	return connect.NewResponse(&pmv1.UpdateRoleResponse{Role: roleToProto(updated)}), nil
}

// DeleteRole retires a role.
//
// A role that anyone still holds is refused rather than deleted out
// from under them: silently dropping a grant is an authorization change
// disguised as a catalogue edit.
func (h *Handlers) DeleteRole(ctx context.Context, req *connect.Request[pmv1.DeleteRoleRequest]) (*connect.Response[pmv1.DeleteRoleResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermDeleteRole, req.Msg.Id); err != nil {
		return nil, err
	}
	before, err := h.store.GetRole(ctx, req.Msg.Id)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrRoleNotFound, "role not found")
		}
		return nil, internalError(ctx, "failed to load role")
	}
	if before.IsSystem {
		return nil, rpcError(ctx, ErrCannotModifySystemRole, connect.CodeFailedPrecondition, "system roles cannot be deleted")
	}
	holders, err := h.store.CountRoleHolders(ctx, before.ID)
	if err != nil {
		return nil, internalError(ctx, "failed to count role holders")
	}
	if holders > 0 {
		return nil, rpcError(ctx, ErrRoleInUse, connect.CodeFailedPrecondition, "the role is still granted to subjects")
	}

	at := h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermDeleteRole),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			n, err := tx.SoftDeleteRole(ctx, db.SoftDeleteRoleParams{ID: before.ID, UpdatedAt: &at})
			if err != nil {
				return err
			}
			if n == 0 {
				return store.ErrNotFound
			}
			yes := true
			rec.Effect(store.AuditEffect{
				ResourceType:  "role",
				ResourceID:    before.ID,
				Action:        "DELETE",
				Outcome:       store.EffectApplied,
				ChangedFields: []string{"is_deleted"},
				AfterFlag:     &yes,
			})
			return nil
		})
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrRoleNotFound, "role not found")
		}
		return nil, internalError(ctx, "failed to delete role")
	}
	return connect.NewResponse(&pmv1.DeleteRoleResponse{}), nil
}

// AssignRoleToUser grants a role to a subject, optionally at a scope.
func (h *Handlers) AssignRoleToUser(ctx context.Context, req *connect.Request[pmv1.AssignRoleToUserRequest]) (*connect.Response[pmv1.AssignRoleToUserResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermAssignRoleToUser, ""); err != nil {
		return nil, err
	}

	roleIDs := requestedRoleIDs(req.Msg.RoleId, req.Msg.RoleIds)
	if len(roleIDs) == 0 {
		return nil, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "role_id or role_ids is required")
	}
	target, err := h.store.GetUser(ctx, req.Msg.UserId)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrUserNotFound, "user not found")
		}
		return nil, internalError(ctx, "failed to load user")
	}

	scopeKind, scopeID, err := h.checkGrantScope(ctx, req.Msg.ScopeKind, req.Msg.ScopeId, roleIDs)
	if err != nil {
		return nil, err
	}

	at := h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermAssignRoleToUser),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			for _, roleID := range roleIDs {
				grantID := ulid.Make().String()
				if _, err := tx.InsertUserRoleGrant(ctx, db.InsertUserRoleGrantParams{
					GrantID:    grantID,
					UserID:     target.ID,
					RoleID:     roleID,
					AssignedAt: at,
					AssignedBy: actor.ID,
					ScopeKind:  scopeKind,
					ScopeID:    scopeID,
				}); err != nil {
					return err
				}
				rec.Effect(store.AuditEffect{
					ResourceType: "user_role",
					ResourceID:   grantID,
					Action:       "GRANT",
					Outcome:      store.EffectApplied,
					BeforeRef:    &target.ID,
					AfterRef:     &roleID,
				})
			}
			if _, err := h.invalidateSubjectSessions(ctx, tx, rec, target.ID); err != nil {
				return err
			}
			return nil
		})
	if err != nil {
		if store.IsConflict(err) {
			return nil, rpcError(ctx, ErrUserAlreadyHasRole, connect.CodeAlreadyExists, "the subject already holds that role at that scope")
		}
		return nil, internalError(ctx, "failed to assign role")
	}
	return connect.NewResponse(&pmv1.AssignRoleToUserResponse{}), nil
}

// RevokeRoleFromUser removes ONE named grant.
//
// The request describes which grant by its scope, and the delete is
// conditional on that description matching. Asking to revoke the
// unscoped grant when only scoped ones exist reports not-found rather
// than silently taking a scoped grant or silently doing nothing.
func (h *Handlers) RevokeRoleFromUser(ctx context.Context, req *connect.Request[pmv1.RevokeRoleFromUserRequest]) (*connect.Response[pmv1.RevokeRoleFromUserResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermRevokeRoleFromUser, ""); err != nil {
		return nil, err
	}
	target, err := h.store.GetUser(ctx, req.Msg.UserId)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrUserNotFound, "user not found")
		}
		return nil, internalError(ctx, "failed to load user")
	}
	scopeKind, scopeID, err := h.describedScope(ctx, req.Msg.ScopeKind, req.Msg.ScopeId)
	if err != nil {
		return nil, err
	}

	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermRevokeRoleFromUser),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			var (
				grant db.UserRole
				err   error
			)
			if scopeID == nil {
				grant, err = tx.DeleteUnscopedUserRoleGrant(ctx, db.DeleteUnscopedUserRoleGrantParams{
					UserID: target.ID, RoleID: req.Msg.RoleId,
				})
			} else {
				grant, err = tx.DeleteScopedUserRoleGrant(ctx, db.DeleteScopedUserRoleGrantParams{
					UserID: target.ID, RoleID: req.Msg.RoleId, ScopeKind: scopeKind, ScopeID: scopeID,
				})
			}
			if err != nil {
				return err
			}
			rec.Effect(store.AuditEffect{
				ResourceType: "user_role",
				ResourceID:   grant.GrantID,
				Action:       "REVOKE",
				Outcome:      store.EffectApplied,
				BeforeRef:    &target.ID,
				AfterRef:     &req.Msg.RoleId,
			})
			if _, err := h.invalidateSubjectSessions(ctx, tx, rec, target.ID); err != nil {
				return err
			}
			return nil
		})
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrGrantNotFound, "no such grant")
		}
		return nil, internalError(ctx, "failed to revoke role")
	}
	return connect.NewResponse(&pmv1.RevokeRoleFromUserResponse{}), nil
}

// AssignRoleToUserGroup grants a role to every member of a group.
func (h *Handlers) AssignRoleToUserGroup(ctx context.Context, req *connect.Request[pmv1.AssignRoleToUserGroupRequest]) (*connect.Response[pmv1.AssignRoleToUserGroupResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermAssignRoleToUserGroup, ""); err != nil {
		return nil, err
	}
	roleIDs := requestedRoleIDs(req.Msg.RoleId, req.Msg.RoleIds)
	if len(roleIDs) == 0 {
		return nil, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "role_id or role_ids is required")
	}
	scopeKind, scopeID, err := h.checkGrantScope(ctx, req.Msg.ScopeKind, req.Msg.ScopeId, roleIDs)
	if err != nil {
		return nil, err
	}

	at := h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermAssignRoleToUserGroup),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			for _, roleID := range roleIDs {
				grantID := ulid.Make().String()
				if _, err := tx.InsertUserGroupRoleGrant(ctx, db.InsertUserGroupRoleGrantParams{
					GrantID:    grantID,
					GroupID:    req.Msg.GroupId,
					RoleID:     roleID,
					AssignedAt: at,
					AssignedBy: actor.ID,
					ScopeKind:  scopeKind,
					ScopeID:    scopeID,
				}); err != nil {
					return err
				}
				rec.Effect(store.AuditEffect{
					ResourceType: "user_group_role",
					ResourceID:   grantID,
					Action:       "GRANT",
					Outcome:      store.EffectApplied,
					BeforeRef:    &req.Msg.GroupId,
					AfterRef:     &roleID,
				})
			}
			return nil
		})
	if err != nil {
		if store.IsConflict(err) {
			return nil, rpcError(ctx, ErrUserAlreadyHasRole, connect.CodeAlreadyExists, "the group already holds that role at that scope")
		}
		// A grant naming a group or role that does not exist violates a
		// foreign key; the caller is told the target is unknown rather
		// than shown a constraint name.
		return nil, notFound(ctx, ErrRoleNotFound, "group or role not found")
	}
	return connect.NewResponse(&pmv1.AssignRoleToUserGroupResponse{}), nil
}

// RevokeRoleFromUserGroup removes one named group grant.
func (h *Handlers) RevokeRoleFromUserGroup(ctx context.Context, req *connect.Request[pmv1.RevokeRoleFromUserGroupRequest]) (*connect.Response[pmv1.RevokeRoleFromUserGroupResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermRevokeRoleFromUserGroup, ""); err != nil {
		return nil, err
	}
	scopeKind, scopeID, err := h.describedScope(ctx, req.Msg.ScopeKind, req.Msg.ScopeId)
	if err != nil {
		return nil, err
	}

	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermRevokeRoleFromUserGroup),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			var (
				grant db.UserGroupRole
				err   error
			)
			if scopeID == nil {
				grant, err = tx.DeleteUnscopedUserGroupRoleGrant(ctx, db.DeleteUnscopedUserGroupRoleGrantParams{
					GroupID: req.Msg.GroupId, RoleID: req.Msg.RoleId,
				})
			} else {
				grant, err = tx.DeleteScopedUserGroupRoleGrant(ctx, db.DeleteScopedUserGroupRoleGrantParams{
					GroupID: req.Msg.GroupId, RoleID: req.Msg.RoleId, ScopeKind: scopeKind, ScopeID: scopeID,
				})
			}
			if err != nil {
				return err
			}
			rec.Effect(store.AuditEffect{
				ResourceType: "user_group_role",
				ResourceID:   grant.GrantID,
				Action:       "REVOKE",
				Outcome:      store.EffectApplied,
				BeforeRef:    &req.Msg.GroupId,
				AfterRef:     &req.Msg.RoleId,
			})
			return nil
		})
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrGrantNotFound, "no such grant")
		}
		return nil, internalError(ctx, "failed to revoke role")
	}
	return connect.NewResponse(&pmv1.RevokeRoleFromUserGroupResponse{}), nil
}

// checkPermissionKeys rejects any permission that is not in the
// registry and returns the set in a stable order.
func (h *Handlers) checkPermissionKeys(ctx context.Context, keys []string) ([]string, error) {
	valid := auth.ValidPermissionKeys()
	out := make([]string, 0, len(keys))
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		if !valid[k] {
			return nil, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "permissions contains an unknown permission key")
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	slices.Sort(out)
	return out, nil
}

// checkGrantScope validates a requested grant scope against the roles
// being granted, and against the actor's own authority to attach it.
//
// Three separate refusals, in order:
//
//  1. a role containing a PRIVILEGE-GRANTING permission cannot be
//     scoped at all. Such a permission mints or widens authority, and
//     the authority it mints is not itself confined to the scope, so a
//     scope on it would be a lie;
//  2. every permission in the role must accept this KIND of scope. A
//     device-group scope on a user-target permission would silently
//     fail to constrain it;
//  3. the actor must hold the authority to attach this particular
//     scope, and a scope-confined admin may not create an unscoped
//     grant at all — that would extend their reach to the whole fleet.
func (h *Handlers) checkGrantScope(
	ctx context.Context,
	kind pmv1.RoleGrantScopeKind,
	scopeID string,
	roleIDs []string,
) (*string, *string, error) {
	unscoped := kind == pmv1.RoleGrantScopeKind_ROLE_GRANT_SCOPE_KIND_UNSPECIFIED && scopeID == ""
	if unscoped {
		if err := auth.EnforceUnscopedGrantAuthority(ctx); err != nil {
			return nil, nil, rpcError(ctx, ErrPermissionDenied, connect.CodePermissionDenied,
				"a scope-limited administrator cannot create an unscoped grant")
		}
		return nil, nil, nil
	}

	// Paired-or-neither. A half-set scope is a request whose meaning is
	// undefined, and guessing which half was intended is how an
	// unscoped grant gets minted by accident.
	if kind == pmv1.RoleGrantScopeKind_ROLE_GRANT_SCOPE_KIND_UNSPECIFIED || scopeID == "" {
		return nil, nil, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument,
			"scope_kind and scope_id must be set together or both omitted")
	}
	storedKind, ok := scopeKindFromProto(kind)
	if !ok {
		return nil, nil, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "unknown scope_kind")
	}

	// Attaching a scope is its own authority, separate from the
	// authority to grant the role. Checked explicitly here rather than
	// left to fall out of the scope-bound check below, so a caller who
	// holds no scope authority at all is refused by a branch that says
	// so instead of by the shape of an empty filter.
	if !auth.HasPermission(ctx, auth.AssignRoleScopePermission) {
		return nil, nil, rpcError(ctx, ErrPermissionDenied, connect.CodePermissionDenied,
			"attaching a scope to a role grant requires the scope-assignment authority")
	}

	for _, roleID := range roleIDs {
		role, err := h.store.GetRole(ctx, roleID)
		if err != nil {
			if store.IsNotFound(err) {
				return nil, nil, notFound(ctx, ErrRoleNotFound, "role not found")
			}
			return nil, nil, internalError(ctx, "failed to load role")
		}
		if _, found := auth.FirstPrivilegeGranting(role.Permissions); found {
			return nil, nil, rpcError(ctx, ErrScopeNotPermitted, connect.CodeInvalidArgument,
				"the role contains a permission that can grant or widen privilege; such a role can only be granted globally")
		}
		if _, scopable := auth.RolePermissionsScopableWith(role.Permissions, storedKind); !scopable {
			return nil, nil, rpcError(ctx, ErrScopeNotPermitted, connect.CodeInvalidArgument,
				"the role contains a permission that does not accept this scope kind")
		}
	}

	if err := auth.EnforceGrantScopeAuthority(ctx, storedKind, scopeID); err != nil {
		return nil, nil, rpcError(ctx, ErrPermissionDenied, connect.CodePermissionDenied,
			"cannot grant a scope outside your own scope authority")
	}
	return &storedKind, &scopeID, nil
}

// describedScope parses the scope a revoke request names. Unlike a
// grant it validates only the shape: the caller is describing which
// existing grant to remove, and whether that description matches is
// decided by the conditional delete.
func (h *Handlers) describedScope(ctx context.Context, kind pmv1.RoleGrantScopeKind, scopeID string) (*string, *string, error) {
	if kind == pmv1.RoleGrantScopeKind_ROLE_GRANT_SCOPE_KIND_UNSPECIFIED && scopeID == "" {
		return nil, nil, nil
	}
	if kind == pmv1.RoleGrantScopeKind_ROLE_GRANT_SCOPE_KIND_UNSPECIFIED || scopeID == "" {
		return nil, nil, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument,
			"scope_kind and scope_id must be set together or both omitted")
	}
	storedKind, ok := scopeKindFromProto(kind)
	if !ok {
		return nil, nil, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "unknown scope_kind")
	}
	return &storedKind, &scopeID, nil
}

// invalidateSubjectSessions bumps a subject's session version so every
// token minted under their previous authority stops validating.
func (h *Handlers) invalidateSubjectSessions(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder, userID string) (int32, error) {
	at := h.now().UTC()
	version, err := tx.BumpUserSessionVersion(ctx, db.BumpUserSessionVersionParams{ID: userID, UpdatedAt: &at})
	if err != nil {
		if store.IsNotFound(err) {
			return 0, nil
		}
		return 0, err
	}
	after := int64(version)
	rec.Effect(store.AuditEffect{
		ResourceType:  "user",
		ResourceID:    userID,
		Action:        "INVALIDATE_SESSIONS",
		Outcome:       store.EffectApplied,
		ChangedFields: []string{"session_version"},
		AfterCount:    &after,
	})
	return version, nil
}

// invalidateRoleHolderSessions bumps the session version of every
// subject that holds the role, directly or through a group, so no
// session outlives the authority it was minted under.
func (h *Handlers) invalidateRoleHolderSessions(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder, roleID string) error {
	at := h.now().UTC()
	affected, err := tx.BumpSessionVersionForRoleHolders(ctx, db.BumpSessionVersionForRoleHoldersParams{
		RoleID:    roleID,
		UpdatedAt: &at,
	})
	if err != nil {
		return err
	}
	rec.Effect(store.AuditEffect{
		ResourceType:  "role",
		ResourceID:    roleID,
		Action:        "INVALIDATE_HOLDER_SESSIONS",
		Outcome:       store.EffectApplied,
		ChangedFields: []string{"session_version"},
		AfterCount:    &affected,
	})
	return nil
}

// requestedRoleIDs merges the singular and repeated role fields the
// contract offers, dropping duplicates and preserving request order.
func requestedRoleIDs(single string, many []string) []string {
	out := make([]string, 0, len(many)+1)
	seen := make(map[string]bool, len(many)+1)
	for _, id := range append([]string{single}, many...) {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}
