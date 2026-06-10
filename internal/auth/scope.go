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
