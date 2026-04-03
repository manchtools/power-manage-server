package auth

import (
	"context"
	"fmt"
	"log/slog"

	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// System role IDs (matching the seed in migrations).
const (
	AdminRoleID = "00000000000000000000000001"
	UserRoleID  = "00000000000000000000000002"
)

// RoleReconciler updates system roles to match current permission definitions.
type RoleReconciler interface {
	UpdateSystemRolePermissions(ctx context.Context, arg db.UpdateSystemRolePermissionsParams) (int64, error)
}

// ReconcileSystemRoles updates the Admin and User system roles to match
// the current permission definitions. This ensures new permissions added
// in code are reflected in the database without requiring a manual toggle.
func ReconcileSystemRoles(ctx context.Context, q RoleReconciler, logger *slog.Logger) error {
	adminPerms := AdminPermissions()
	n, err := q.UpdateSystemRolePermissions(ctx, db.UpdateSystemRolePermissionsParams{
		Permissions: adminPerms,
		ID:          AdminRoleID,
	})
	if err != nil {
		return fmt.Errorf("update admin role: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("admin role %s not found in database", AdminRoleID)
	}

	userPerms := DefaultUserPermissions()
	n, err = q.UpdateSystemRolePermissions(ctx, db.UpdateSystemRolePermissionsParams{
		Permissions: userPerms,
		ID:          UserRoleID,
	})
	if err != nil {
		return fmt.Errorf("update user role: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("user role %s not found in database", UserRoleID)
	}

	logger.Info("system roles reconciled", "admin_permissions", len(adminPerms), "user_permissions", len(userPerms))
	return nil
}
