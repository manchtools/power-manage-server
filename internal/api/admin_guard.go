package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/server/internal/store"
)

// advisoryKeyAdminMutation serializes every last-admin-guarded mutation
// (disable / delete / admin-role-revoke) so the read-side guard and its
// mutating event append are atomic against a concurrent admin-removing request
// — closing the TOCTOU where two requests for different admins both observe
// "another admin exists" and race to zero (#369). The value is "admin" in hex;
// it only needs to be a stable constant distinct from any other advisory lock.
const advisoryKeyAdminMutation int64 = 0x61646d696e

// guardedAdminMutation runs the last-admin guard and the mutating append under
// one advisory lock, so two concurrent admin-removing requests cannot both pass
// the guard and lock everyone out (#369). affectedUserID is the admin being
// removed; appendFn performs the mutation and MUST return a connect-coded error
// (or nil). Guard/append errors pass through unchanged; only a lock-
// infrastructure failure is re-coded Internal.
func guardedAdminMutation(ctx context.Context, st *store.Store, affectedUserID string, appendFn func() error) error {
	err := st.WithAdvisoryLock(ctx, advisoryKeyAdminMutation, func() error {
		if gerr := assertOtherEnabledAdminExists(ctx, st, affectedUserID); gerr != nil {
			return gerr
		}
		return appendFn()
	})
	if err == nil {
		return nil
	}
	var ce *connect.Error
	if errors.As(err, &ce) {
		return err
	}
	return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to serialize admin mutation")
}

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
// This is a read-side preflight and is NOT atomic with the mutating event on
// its own. Callers MUST run it together with that append via guardedAdminMutation
// (below), which holds an advisory lock across both so two concurrent admin-
// removing requests for *different* admins can't both observe "another enabled
// admin exists" and race to zero (#369). Calling it standalone reintroduces that
// TOCTOU.
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
