package auth

import (
	"context"
	"errors"

	"connectrpc.com/connect"
)

// Scope kinds. A grant carries at most one. Empty = unscoped (global).
const (
	ScopeKindDeviceGroup = "device_group"
	ScopeKindUserGroup   = "user_group"
)

// ScopedGrant is one (permission, scope) tuple the caller holds.
// ScopeKind/ScopeID are empty together for an unscoped (global) grant.
// When set, ScopeKind is ScopeKindDeviceGroup or ScopeKindUserGroup and
// ScopeID is the group's id. The permission is constrained to that
// scope. Carried in the JWT `sgrants` claim and the UserContext (#7).
type ScopedGrant struct {
	Permission string `json:"p"`
	ScopeKind  string `json:"k,omitempty"`
	ScopeID    string `json:"i,omitempty"`
}

// ScopeFilter describes how a permission is scoped for the caller, for
// list/query narrowing. Global means the caller holds the permission
// unscoped, so no row filtering applies. Otherwise GroupIDs is the set
// of scope-group ids (device_group ids for device targets, user_group
// ids for user targets) the caller is limited to; an empty GroupIDs
// with Global=false means the caller holds the permission only via
// irrelevant scopes (or not at all) and may see nothing.
type ScopeFilter struct {
	Global   bool
	GroupIDs []string
}

// ScopeResolver answers group-membership questions the scope helpers
// need. Implemented over the device-group / user-group projections at
// the call site; kept as an interface so the helpers stay free
// functions (mirroring EnforceSelfScope) and are unit-testable with a
// fake.
type ScopeResolver interface {
	// DeviceGroupsForDevice returns the ids of every device group the
	// device belongs to (static + dynamic-materialized).
	DeviceGroupsForDevice(ctx context.Context, deviceID string) ([]string, error)
	// UserGroupsForUser returns the ids of every user group the user
	// belongs to.
	UserGroupsForUser(ctx context.Context, userID string) ([]string, error)
}

// scopeFilterFor reduces the caller's scoped grants for `permission` to
// a ScopeFilter, considering only grants whose ScopeKind matches
// wantKind (the kind relevant to the target type) plus unscoped grants.
// A grant of `permission` under a different scope kind grants no access
// to this target type and is therefore ignored.
func scopeFilterFor(ctx context.Context, permission, wantKind string) ScopeFilter {
	user, ok := UserFromContext(ctx)
	if !ok {
		return ScopeFilter{}
	}
	var groupIDs []string
	for _, g := range user.ScopedGrants {
		if g.Permission != permission {
			continue
		}
		if g.ScopeKind == "" {
			// An unscoped grant of the permission is fleet-wide.
			return ScopeFilter{Global: true}
		}
		if g.ScopeKind == wantKind {
			groupIDs = append(groupIDs, g.ScopeID)
		}
	}
	return ScopeFilter{Global: false, GroupIDs: groupIDs}
}

// DeviceScopeFilterFor returns the device-group scoping for a
// device-target permission. Global=true ⇒ no device narrowing;
// otherwise restrict device queries to GroupIDs.
func DeviceScopeFilterFor(ctx context.Context, permission string) ScopeFilter {
	return scopeFilterFor(ctx, permission, ScopeKindDeviceGroup)
}

// UserScopeFilterFor returns the user-group scoping for a user-target
// permission. Global=true ⇒ no user narrowing; otherwise restrict user
// queries to GroupIDs.
func UserScopeFilterFor(ctx context.Context, permission string) ScopeFilter {
	return scopeFilterFor(ctx, permission, ScopeKindUserGroup)
}

// EnforceDeviceScope authorizes a device-target action. It allows when
// the caller holds `permission` unscoped (global) OR scoped to a device
// group that contains deviceID; otherwise it denies. Self-contained:
// when the caller holds no relevant grant for `permission` (including
// holding it only via a user_group scope, which grants no device
// access), it denies.
func EnforceDeviceScope(ctx context.Context, resolver ScopeResolver, permission, deviceID string) error {
	if _, ok := UserFromContext(ctx); !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}
	f := DeviceScopeFilterFor(ctx, permission)
	if f.Global {
		return nil
	}
	if len(f.GroupIDs) == 0 {
		return connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
	}
	deviceGroups, err := resolver.DeviceGroupsForDevice(ctx, deviceID)
	if err != nil {
		return connect.NewError(connect.CodeInternal, errors.New("scope resolution failed"))
	}
	if intersects(f.GroupIDs, deviceGroups) {
		return nil
	}
	return connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
}

// EnforceUserScope authorizes a user-target action. It allows when the
// caller holds `permission` unscoped OR scoped to a user group that
// contains targetUserID; otherwise it denies.
func EnforceUserScope(ctx context.Context, resolver ScopeResolver, permission, targetUserID string) error {
	if _, ok := UserFromContext(ctx); !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}
	f := UserScopeFilterFor(ctx, permission)
	if f.Global {
		return nil
	}
	if len(f.GroupIDs) == 0 {
		return connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
	}
	userGroups, err := resolver.UserGroupsForUser(ctx, targetUserID)
	if err != nil {
		return connect.NewError(connect.CodeInternal, errors.New("scope resolution failed"))
	}
	if intersects(f.GroupIDs, userGroups) {
		return nil
	}
	return connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
}

// AssignRoleScopePermission is the org-tier authority required to attach
// a scope to a role grant. Holding it scoped (rather than global) limits
// which scopes the actor may attach (see EnforceGrantScopeAuthority).
const AssignRoleScopePermission = "AssignRoleScope"

// targetKindForScopeKind maps a grant scope kind to the permission
// target kind a permission must have to be scopable with it.
func targetKindForScopeKind(scopeKind string) (PermissionTargetKind, bool) {
	switch scopeKind {
	case ScopeKindDeviceGroup:
		return TargetDevice, true
	case ScopeKindUserGroup:
		return TargetUser, true
	default:
		return TargetUnspecified, false
	}
}

// RolePermissionsScopableWith reports whether every permission in perms
// can be scoped with scopeKind. ok=false returns the first offending
// permission (a target-kind mismatch, including a TargetUnspecified
// permission, which is never scopable). An unknown scopeKind is not
// scopable. The cascade requires the WHOLE role to be scopable: a single
// non-matching permission rejects the scoped grant, because the scope
// would otherwise silently fail to constrain that permission (#7 S5).
func RolePermissionsScopableWith(perms []string, scopeKind string) (badPerm string, ok bool) {
	want, valid := targetKindForScopeKind(scopeKind)
	if !valid {
		return "", false
	}
	for _, p := range perms {
		if TargetKindFor(p) != want {
			return p, false
		}
	}
	return "", true
}

// EnforceGrantScopeAuthority checks that the caller may ATTACH the given
// scope to a role grant. The caller must already hold AssignRoleScope
// (gate that separately); this enforces the escalation bound:
//   - AssignRoleScope held unscoped (global) ⇒ may attach any scope;
//   - held only scoped ⇒ may attach ONLY a scope whose id is among the
//     caller's own AssignRoleScope scope ids of the SAME kind (equal
//     match; sub-group "narrower" containment is a future refinement).
//
// This stops a scope-limited admin from minting grants outside their own
// scope.
func EnforceGrantScopeAuthority(ctx context.Context, scopeKind, scopeID string) error {
	if _, ok := UserFromContext(ctx); !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}
	f := scopeFilterFor(ctx, AssignRoleScopePermission, scopeKind)
	if f.Global {
		return nil
	}
	for _, id := range f.GroupIDs {
		if id == scopeID {
			return nil
		}
	}
	return connect.NewError(connect.CodePermissionDenied,
		errors.New("cannot grant a scope outside your own scope authority"))
}

// EnforceUnscopedGrantAuthority checks that the caller may create an
// UNSCOPED (global) role grant. A scope-limited admin — one who holds
// AssignRoleScope only scoped, never globally — may not: granting
// unscoped would escalate their reach to the whole fleet. A caller with
// no scope authority at all (the ordinary AssignRoleToUser admin) or one
// holding AssignRoleScope globally (the org admin) may grant unscoped.
func EnforceUnscopedGrantAuthority(ctx context.Context) error {
	if _, ok := UserFromContext(ctx); !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}
	dg := DeviceScopeFilterFor(ctx, AssignRoleScopePermission)
	ug := UserScopeFilterFor(ctx, AssignRoleScopePermission)
	if dg.Global || ug.Global {
		return nil // org admin — unrestricted
	}
	if len(dg.GroupIDs) > 0 || len(ug.GroupIDs) > 0 {
		return connect.NewError(connect.CodePermissionDenied,
			errors.New("a scope-limited admin cannot create an unscoped grant"))
	}
	return nil // no scope authority — ordinary admin, allowed
}

// EnforceUserScopeOrSelf authorizes a user-target action across every grant
// tier, for handlers that previously used EnforceSelfScope:
//   - caller holds `permission` as the base — unrestricted OR user-group-scoped:
//     defer to EnforceUserScope (global ⇒ any target; scoped ⇒ only targets in a
//     covered user group). The base appears in the flat permission set for BOTH
//     unrestricted and scoped grants (the scope lives on the grant, not the
//     permission string), so HasPermission catches a scoped holder and confines
//     them here rather than waving them through;
//   - caller holds only `permission:self`: allow only when targetUserID is the
//     caller's own id;
//   - otherwise deny.
func EnforceUserScopeOrSelf(ctx context.Context, resolver ScopeResolver, permission, targetUserID string) error {
	user, ok := UserFromContext(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}
	if HasPermission(ctx, permission) {
		// Holds the base. The flat permission set IS the authority; the scoped
		// grants only CONFINE. If there is a user_group-scoped grant for this
		// permission, restrict to it; an unscoped grant (Global) or no scoping
		// grant at all means unrestricted.
		f := UserScopeFilterFor(ctx, permission)
		if f.Global || len(f.GroupIDs) == 0 {
			return nil
		}
		return EnforceUserScope(ctx, resolver, permission, targetUserID)
	}
	if HasPermission(ctx, permission+":self") && targetUserID == user.ID {
		return nil
	}
	return connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
}

// EnforceDeviceScopeOnBaseTier applies #7 device-group scope confinement ONLY on
// the base-permission tier — when the caller holds `permission` unrestricted or
// device-group-scoped (the base is present in the flat permission set for both).
// A caller holding only `permission:assigned` is left to the assigned-owner SQL
// filter (the OwnerScope/userFilterID path) and passes through here unblocked.
// This is the StartTerminal gate, generalized for reuse across device handlers.
func EnforceDeviceScopeOnBaseTier(ctx context.Context, resolver ScopeResolver, permission, deviceID string) error {
	if _, ok := UserFromContext(ctx); !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}
	if !HasPermission(ctx, permission) {
		return nil // :assigned-only tier — confined by the owner SQL filter, not here
	}
	// Holds the base. Confine only if a device_group-scoped grant is attached;
	// an unscoped grant (Global) or no scoping grant means unrestricted.
	f := DeviceScopeFilterFor(ctx, permission)
	if f.Global || len(f.GroupIDs) == 0 {
		return nil
	}
	return EnforceDeviceScope(ctx, resolver, permission, deviceID)
}

// intersects reports whether a and b share any element.
func intersects(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, x := range a {
		set[x] = struct{}{}
	}
	for _, y := range b {
		if _, ok := set[y]; ok {
			return true
		}
	}
	return false
}
