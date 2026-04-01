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
	UpdateSystemRolePermissions(ctx context.Context, arg db.UpdateSystemRolePermissionsParams) error
}

// ReconcileSystemRoles updates the Admin and User system roles to match
// the current permission definitions. This ensures new permissions added
// in code are reflected in the database without requiring a manual toggle.
func ReconcileSystemRoles(ctx context.Context, q RoleReconciler, logger *slog.Logger) error {
	adminPerms := AdminPermissions()
	if err := q.UpdateSystemRolePermissions(ctx, db.UpdateSystemRolePermissionsParams{
		Permissions: adminPerms,
		ID:          AdminRoleID,
	}); err != nil {
		return fmt.Errorf("update admin role: %w", err)
	}

	userPerms := DefaultUserPermissions()
	if err := q.UpdateSystemRolePermissions(ctx, db.UpdateSystemRolePermissionsParams{
		Permissions: userPerms,
		ID:          UserRoleID,
	}); err != nil {
		return fmt.Errorf("update user role: %w", err)
	}

	logger.Info("system roles reconciled", "admin_permissions", len(adminPerms), "user_permissions", len(userPerms))
	return nil
}
