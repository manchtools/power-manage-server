package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/manchtools/power-manage/server/internal/auth"
)

// scopeGroupClause (#7 spec 14) confines a scope-restricted caller's Search.
// Devices key off the caller's ListDevices device-group scope, users off the
// ListUsers user-group scope, and the four object scopes off the union
// ObjectScopeListFilter — all read from the JWT-backed context, no DB.
func TestScopeGroupClause(t *testing.T) {
	deviceScoped := auth.WithUser(context.Background(), &auth.UserContext{
		ID:           "c",
		Permissions:  []string{"ListDevices"},
		ScopedGrants: []auth.ScopedGrant{{Permission: "ListDevices", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: "dg1"}},
	})
	userScoped := auth.WithUser(context.Background(), &auth.UserContext{
		ID:           "c",
		Permissions:  []string{"ListUsers"},
		ScopedGrants: []auth.ScopedGrant{{Permission: "ListUsers", ScopeKind: auth.ScopeKindUserGroup, ScopeID: "ug1"}},
	})
	objectScoped := auth.WithUser(context.Background(), &auth.UserContext{
		ID:           "c",
		ScopedGrants: []auth.ScopedGrant{{Permission: "ListDevices", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: "dg9"}},
	})
	unrestricted := auth.WithUser(context.Background(), &auth.UserContext{ID: "admin"})

	t.Run("devices use the caller's device-group scope", func(t *testing.T) {
		assert.Equal(t, "@scope_group_ids:{dg1}", scopeGroupClause(deviceScoped, "devices"))
	})
	t.Run("users use the caller's user-group scope", func(t *testing.T) {
		assert.Equal(t, "@scope_group_ids:{ug1}", scopeGroupClause(userScoped, "users"))
	})
	t.Run("object scopes use the union object filter", func(t *testing.T) {
		assert.Equal(t, "@scope_group_ids:{dg9}", scopeGroupClause(objectScoped, "actions"))
	})
	t.Run("a device-scoped caller is unrestricted on the USERS scope", func(t *testing.T) {
		// Wrong-axis: device-group scope must not confine user Search.
		assert.Equal(t, "", scopeGroupClause(deviceScoped, "users"))
	})
	t.Run("unrestricted caller gets no clause", func(t *testing.T) {
		assert.Equal(t, "", scopeGroupClause(unrestricted, "devices"))
		assert.Equal(t, "", scopeGroupClause(unrestricted, "actions"))
	})
	t.Run("device_groups, user_groups and executions now confine (H4)", func(t *testing.T) {
		// Pre-H4 these three carried no scope_group_ids field, so scopeGroupClause
		// returned "" — a scope-restricted caller's Search leaked every group/
		// execution fleet-wide. They now confine via the union ObjectScopeListFilter,
		// exactly like the object scopes. (The user_groups clause here matches no
		// row for a device-scoped caller — fail closed, correct.)
		assert.Equal(t, "@scope_group_ids:{dg1}", scopeGroupClause(deviceScoped, "executions"))
		assert.Equal(t, "@scope_group_ids:{dg1}", scopeGroupClause(deviceScoped, "device_groups"))
		assert.Equal(t, "@scope_group_ids:{dg1}", scopeGroupClause(deviceScoped, "user_groups"))
	})
	t.Run("audit_events carries no scope field, so no clause (gated by ListAuditEvents instead)", func(t *testing.T) {
		assert.Equal(t, "", scopeGroupClause(deviceScoped, "audit_events"))
	})
}
