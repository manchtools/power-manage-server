package auth

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// System role IDs, matching the seed in the migrations.
const (
	AdminRoleID = "00000000000000000000000001"
	UserRoleID  = "00000000000000000000000002"
)

// RoleReconcilerStore is the audited mutation door the reconciler
// needs. Satisfied by *store.Store.
type RoleReconcilerStore interface {
	WithAudit(ctx context.Context, op store.AuditOperation, mutate func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error) (store.AuditRecord, error)
}

// ReconcileSystemRoles refreshes the Admin and User system roles from
// the code registry, so a permission added in code takes effect on the
// next boot without an operator step.
//
// It is a background writer, not an RPC, so it records its own
// operation under the background-writer class in the same transaction
// as the two updates. Either both roles are refreshed and the evidence
// lands, or neither is.
func ReconcileSystemRoles(ctx context.Context, st RoleReconcilerStore, now time.Time, logger *slog.Logger) error {
	adminPerms := AdminPermissions()
	userPerms := DefaultUserPermissions()
	at := now.UTC()

	_, err := st.WithAudit(ctx, store.AuditOperation{
		Class:     store.ClassBackgroundWriter,
		ActorType: "system",
		// No actor id: the audit log's actor id names the SUBJECT who
		// acted, and nobody asked for this — it is the process
		// starting. The writer is identified by its actor type and its
		// request descriptor, both code-derived constants.
		Origin:               "internal",
		RequestDescriptor:    "auth.ReconcileSystemRoles",
		AuthorizationOutcome: store.AuthorizationNotApplicable,
		Result:               store.ResultSuccess,
	}, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		for _, role := range []struct {
			id    string
			perms []string
		}{
			{AdminRoleID, adminPerms},
			{UserRoleID, userPerms},
		} {
			before, err := tx.GetRole(ctx, role.id)
			if err != nil {
				return fmt.Errorf("load system role %s: %w", role.id, err)
			}
			n, err := tx.UpdateSystemRolePermissions(ctx, db.UpdateSystemRolePermissionsParams{ID: role.id, Permissions: role.perms, UpdatedAt: &at})
			if err != nil {
				return fmt.Errorf("update system role %s: %w", role.id, err)
			}
			if n == 0 {
				return fmt.Errorf("system role %s is missing from the database", role.id)
			}
			beforeCount := int64(len(before.Permissions))
			afterCount := int64(len(role.perms))
			rec.Effect(store.AuditEffect{
				ResourceType:  "role",
				ResourceID:    role.id,
				Action:        "RECONCILE_PERMISSIONS",
				Outcome:       store.EffectApplied,
				ChangedFields: []string{"permissions"},
				BeforeCount:   &beforeCount,
				AfterCount:    &afterCount,
			})
		}
		return nil
	})
	if err != nil {
		return err
	}

	logger.Info("system roles reconciled",
		"admin_permissions", len(adminPerms),
		"user_permissions", len(userPerms))
	return nil
}
