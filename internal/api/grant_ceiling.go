package api

import (
	"context"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/server/internal/auth"
)

// assertCanGrant enforces the "grant only what you hold" privilege ceiling: the
// authenticated caller must hold every permission in `granted` (holding an
// unrestricted permission covers its :self/:assigned scoped forms). The
// role/group management handlers call this so a delegated manager cannot
// escalate by creating/updating a role or assigning a role/group that confers
// permissions they lack (#365). Admins hold every permission, so they are never
// blocked.
func assertCanGrant(ctx context.Context, granted []string) error {
	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}
	if missing := auth.UncoveredPermissions(userCtx.Permissions, granted); len(missing) > 0 {
		return apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied,
			"cannot grant permissions you do not hold")
	}
	return nil
}
