package api_test

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

const deviceGroupScope = pm.RoleGrantScopeKind_ROLE_GRANT_SCOPE_KIND_DEVICE_GROUP

// scopeLimitedAdminCtx models an admin whose AssignRoleScope authority is
// confined to a single device group — the escalation-prevention subject.
func scopeLimitedAdminCtx(id, dgID string) context.Context {
	return testutil.AuthContextScoped(id, "scoped-admin@test.com",
		[]string{"AssignRoleToUser", "AssignRoleToUserGroup", "AssignRoleScope"},
		[]auth.ScopedGrant{{Permission: "AssignRoleScope", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: dgID}})
}

func TestAssignRoleToUser_DeviceGroupScopedGrant(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	target := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	role := testutil.CreateTestRole(t, st, adminID, "Device Role", []string{"ListDevices", "GetDevice"})
	dg := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant 2")

	_, err := h.AssignRoleToUser(ctx, connect.NewRequest(&pm.AssignRoleToUserRequest{
		UserId: target, RoleId: role, ScopeKind: deviceGroupScope, ScopeId: dg,
	}))
	require.NoError(t, err)

	grants, err := st.Repos().User.ScopedGrants(context.Background(), target)
	require.NoError(t, err)
	assert.Contains(t, grants, store.ScopedGrant{Permission: "ListDevices", ScopeKind: "device_group", ScopeID: dg})
	assert.Contains(t, grants, store.ScopedGrant{Permission: "GetDevice", ScopeKind: "device_group", ScopeID: dg})
}

func TestAssignRoleToUser_ScopedRequiresAssignRoleScope(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	target := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	role := testutil.CreateTestRole(t, st, adminID, "Device Role", []string{"ListDevices"})
	dg := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant 2")

	// Actor can assign roles but lacks AssignRoleScope.
	ctx := testutil.AuthContextScoped(adminID, "a@t.com", []string{"AssignRoleToUser"}, nil)
	_, err := h.AssignRoleToUser(ctx, connect.NewRequest(&pm.AssignRoleToUserRequest{
		UserId: target, RoleId: role, ScopeKind: deviceGroupScope, ScopeId: dg,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestAssignRoleToUser_TargetKindMismatchRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	target := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	// GetUser is a user-target permission — not scopable with a device group.
	role := testutil.CreateTestRole(t, st, adminID, "Mixed Role", []string{"ListDevices", "GetUser"})
	dg := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant 2")

	_, err := h.AssignRoleToUser(ctx, connect.NewRequest(&pm.AssignRoleToUserRequest{
		UserId: target, RoleId: role, ScopeKind: deviceGroupScope, ScopeId: dg,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestAssignRoleToUser_ScopeGroupMustExist(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	target := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	role := testutil.CreateTestRole(t, st, adminID, "Device Role", []string{"ListDevices"})

	_, err := h.AssignRoleToUser(ctx, connect.NewRequest(&pm.AssignRoleToUserRequest{
		UserId: target, RoleId: role, ScopeKind: deviceGroupScope, ScopeId: testutil.NewID(),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestAssignRoleToUser_PairedOrNeither(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	target := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	role := testutil.CreateTestRole(t, st, adminID, "Device Role", []string{"ListDevices"})

	// scope_kind set, scope_id absent.
	_, err := h.AssignRoleToUser(ctx, connect.NewRequest(&pm.AssignRoleToUserRequest{
		UserId: target, RoleId: role, ScopeKind: deviceGroupScope,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestAssignRoleToUser_EscalationOutsideOwnScopeDenied(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	target := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	role := testutil.CreateTestRole(t, st, adminID, "Device Role", []string{"ListDevices"})
	dg1 := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant 1")
	dg2 := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant 2")

	// Admin scoped to dg1 may not grant scoped to dg2.
	ctx := scopeLimitedAdminCtx(adminID, dg1)
	_, err := h.AssignRoleToUser(ctx, connect.NewRequest(&pm.AssignRoleToUserRequest{
		UserId: target, RoleId: role, ScopeKind: deviceGroupScope, ScopeId: dg2,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	// ...but may grant scoped to dg1 (its own scope).
	_, err = h.AssignRoleToUser(ctx, connect.NewRequest(&pm.AssignRoleToUserRequest{
		UserId: target, RoleId: role, ScopeKind: deviceGroupScope, ScopeId: dg1,
	}))
	require.NoError(t, err)
}

func TestAssignRoleToUser_ScopeLimitedAdminCannotGrantUnscoped(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	target := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	role := testutil.CreateTestRole(t, st, adminID, "Device Role", []string{"ListDevices"})
	dg1 := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant 1")

	ctx := scopeLimitedAdminCtx(adminID, dg1)
	_, err := h.AssignRoleToUser(ctx, connect.NewRequest(&pm.AssignRoleToUserRequest{
		UserId: target, RoleId: role, // unscoped
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

// An out-of-range / future scope_kind enum must fail closed as
// InvalidArgument, never silently degrade to an unscoped (fleet-wide)
// grant. Regression for CodeRabbit #337 finding 1.
func TestAssignRoleToUser_UnknownScopeKindRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	target := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	role := testutil.CreateTestRole(t, st, adminID, "Device Role", []string{"ListDevices"})

	// An unknown enum value with no scope_id must NOT become an unscoped grant.
	_, err := h.AssignRoleToUser(ctx, connect.NewRequest(&pm.AssignRoleToUserRequest{
		UserId: target, RoleId: role, ScopeKind: pm.RoleGrantScopeKind(99),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	// No grant must have been created.
	grants, gErr := st.Repos().User.ScopedGrants(context.Background(), target)
	require.NoError(t, gErr)
	for _, g := range grants {
		assert.NotEqual(t, "ListDevices", g.Permission, "an unknown scope_kind must not create any grant")
	}
}

// A scope-limited caller probing a scope_id outside its authority must
// get PermissionDenied regardless of whether that group exists — the
// authority check must precede the existence check so group existence
// isn't an oracle. Regression for CodeRabbit #337 finding 2.
func TestAssignRoleToUser_ScopeAuthorityCheckedBeforeExistence(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	target := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	role := testutil.CreateTestRole(t, st, adminID, "Device Role", []string{"ListDevices"})
	dg1 := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant 1")

	// Admin scoped to dg1 targets a group it has no authority over AND
	// which does not exist — must be PermissionDenied, not NotFound.
	ctx := scopeLimitedAdminCtx(adminID, dg1)
	_, err := h.AssignRoleToUser(ctx, connect.NewRequest(&pm.AssignRoleToUserRequest{
		UserId: target, RoleId: role, ScopeKind: deviceGroupScope, ScopeId: testutil.NewID(),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

// Revoking a role the user doesn't have at all is an idempotent no-op
// (success) — aligned with RevokeRoleFromUserGroup. Pins the parity that
// CodeRabbit flagged. The wrong-scope case stays FailedPrecondition (see
// TestRevokeRoleFromUser_ScopeTargeted).
func TestRevokeRoleFromUser_NotAssignedIsNoop(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	target := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	role := testutil.CreateTestRole(t, st, adminID, "Unassigned Role", []string{"ListDevices"})

	_, err := h.RevokeRoleFromUser(ctx, connect.NewRequest(&pm.RevokeRoleFromUserRequest{
		UserId: target, RoleId: role,
	}))
	require.NoError(t, err)
}

func TestRevokeRoleFromUser_ScopeTargeted(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	target := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	role := testutil.CreateTestRole(t, st, adminID, "Device Role", []string{"ListDevices"})
	dg := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant 2")

	// Assign scoped.
	_, err := h.AssignRoleToUser(ctx, connect.NewRequest(&pm.AssignRoleToUserRequest{
		UserId: target, RoleId: role, ScopeKind: deviceGroupScope, ScopeId: dg,
	}))
	require.NoError(t, err)

	// Revoking the UNSCOPED grant must fail — the role is assigned at a
	// different (scoped) shape; surface it rather than silently no-op.
	_, err = h.RevokeRoleFromUser(ctx, connect.NewRequest(&pm.RevokeRoleFromUserRequest{
		UserId: target, RoleId: role,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))

	// Revoking the exact scoped grant succeeds.
	_, err = h.RevokeRoleFromUser(ctx, connect.NewRequest(&pm.RevokeRoleFromUserRequest{
		UserId: target, RoleId: role, ScopeKind: deviceGroupScope, ScopeId: dg,
	}))
	require.NoError(t, err)

	grants, err := st.Repos().User.ScopedGrants(context.Background(), target)
	require.NoError(t, err)
	for _, g := range grants {
		assert.NotEqual(t, "ListDevices", g.Permission, "the scoped grant must be gone")
	}
}
