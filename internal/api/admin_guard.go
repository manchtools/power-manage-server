package api

import (
	"context"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/server/internal/store"
)

// assertOtherEnabledAdminExists rejects an operation that would remove the LAST
// enabled administrator. It verifies at least one ENABLED admin OTHER than
// affectedUserID remains — an admin being a user who holds the Admin system
// role directly OR via a group. Used by DeleteUser, SetUserDisabled and
// RevokeRoleFromUser so the sole administrator cannot be locked out (#365).
//
// Conservative by design: it requires a *different* enabled admin to remain
// rather than recomputing the affected user's post-operation admin paths. For a
// lockout guard, refusing to remove the only OTHER admin is the safe bound, and
// it counts group-inherited admins (which the prior RevokeRoleFromUser check
// ignored) and excludes disabled/deleted ones (which it also ignored).
//
// LIMITATION (pre-existing): this is a read-side preflight, NOT atomic with the
// delete/disable/revoke event it guards. Two concurrent admin-removing requests
// for *different* admins can both observe "another enabled admin exists" and
// both proceed, racing to zero enabled admins. The prior CountUsersWithRole
// check had the identical race. The outcome is recoverable — the bootstrap
// admin (CONTROL_ADMIN_EMAIL/PASSWORD) is re-created on server start — so this
// strict-improvement guard does not close the race; atomic enforcement in the
// projection/transaction is a tracked follow-up.
func assertOtherEnabledAdminExists(ctx context.Context, st *store.Store, affectedUserID string) error {
	adminRole, err := st.Repos().Role.GetByName(ctx, "Admin")
	if err != nil {
		return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to resolve Admin role")
	}
	direct, err := st.Repos().Role.ListUserIDsWithRole(ctx, adminRole.ID)
	if err != nil {
		return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list admins")
	}
	viaGroup, err := st.Repos().Role.ListUserIDsWithGroupRole(ctx, adminRole.ID)
	if err != nil {
		return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list group admins")
	}

	candidates := make([]string, 0, len(direct)+len(viaGroup))
	candidates = append(candidates, direct...)
	candidates = append(candidates, viaGroup...)

	seen := make(map[string]bool, len(candidates))
	for _, id := range candidates {
		if id == affectedUserID || seen[id] {
			continue
		}
		seen[id] = true
		u, err := st.Repos().User.Get(ctx, id)
		if err != nil {
			if store.IsNotFound(err) {
				continue
			}
			return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to load admin user")
		}
		if !u.Disabled && !u.IsDeleted {
			return nil // at least one other enabled admin remains
		}
	}
	return apiErrorCtx(ctx, ErrCannotRemoveLastAdmin, connect.CodeFailedPrecondition,
		"cannot remove the last enabled administrator")
}

// permissionSetsEqual reports whether two permission lists contain the same set
// of keys, ignoring order and duplicates.
func permissionSetsEqual(a, b []string) bool {
	set := make(map[string]struct{}, len(a))
	for _, p := range a {
		set[p] = struct{}{}
	}
	bset := make(map[string]struct{}, len(b))
	for _, p := range b {
		bset[p] = struct{}{}
	}
	if len(set) != len(bset) {
		return false
	}
	for p := range set {
		if _, ok := bset[p]; !ok {
			return false
		}
	}
	return true
}
