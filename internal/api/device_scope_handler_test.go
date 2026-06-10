package api_test

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// deviceScopedAdminCtx models an admin holding the given permissions
// scoped to a single device group (#7 S6).
func deviceScopedAdminCtx(id string, dgID string, perms ...string) context.Context {
	grants := make([]auth.ScopedGrant, len(perms))
	for i, p := range perms {
		grants[i] = auth.ScopedGrant{Permission: p, ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: dgID}
	}
	return testutil.AuthContextScoped(id, "scoped-admin@test.com", perms, grants)
}

// TestDeviceScope_GetDevice covers the per-item device enforcement: a
// device-group-scoped admin sees devices in their group, is denied
// outside it, and an unscoped admin sees all.
func TestDeviceScope_GetDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")

	dgA := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant A")
	dgB := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant B")
	devA := testutil.CreateTestDevice(t, st, "host-a")
	devB := testutil.CreateTestDevice(t, st, "host-b")
	testutil.AddDeviceToTestGroup(t, st, adminID, dgA, devA)
	testutil.AddDeviceToTestGroup(t, st, adminID, dgB, devB)

	scopedToA := deviceScopedAdminCtx(adminID, dgA, "GetDevice")

	t.Run("scoped admin sees a device in their group", func(t *testing.T) {
		_, err := h.GetDevice(scopedToA, connect.NewRequest(&pm.GetDeviceRequest{Id: devA}))
		require.NoError(t, err)
	})
	t.Run("scoped admin is denied a device outside their group", func(t *testing.T) {
		_, err := h.GetDevice(scopedToA, connect.NewRequest(&pm.GetDeviceRequest{Id: devB}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})
	t.Run("scoped admin is denied a non-existent device (no existence oracle)", func(t *testing.T) {
		_, err := h.GetDevice(scopedToA, connect.NewRequest(&pm.GetDeviceRequest{Id: testutil.NewID()}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})
	t.Run("unscoped admin sees any device", func(t *testing.T) {
		ctx := testutil.AdminContext(adminID)
		_, err := h.GetDevice(ctx, connect.NewRequest(&pm.GetDeviceRequest{Id: devB}))
		require.NoError(t, err)
	})
}

func TestDeviceScope_DeleteDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")

	dgA := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant A")
	devB := testutil.CreateTestDevice(t, st, "host-b") // not in dgA

	scopedToA := deviceScopedAdminCtx(adminID, dgA, "DeleteDevice")
	_, err := h.DeleteDevice(scopedToA, connect.NewRequest(&pm.DeleteDeviceRequest{Id: devB}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestDeviceScope_SetDeviceSyncInterval(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")

	dgA := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant A")
	devA := testutil.CreateTestDevice(t, st, "host-a")
	testutil.AddDeviceToTestGroup(t, st, adminID, dgA, devA)

	scopedToA := deviceScopedAdminCtx(adminID, dgA, "SetDeviceSyncInterval")

	t.Run("in-scope allowed", func(t *testing.T) {
		_, err := h.SetDeviceSyncInterval(scopedToA, connect.NewRequest(&pm.SetDeviceSyncIntervalRequest{
			Id: devA, SyncIntervalMinutes: 30,
		}))
		require.NoError(t, err)
	})
	t.Run("out-of-scope denied", func(t *testing.T) {
		devB := testutil.CreateTestDevice(t, st, "host-b")
		_, err := h.SetDeviceSyncInterval(scopedToA, connect.NewRequest(&pm.SetDeviceSyncIntervalRequest{
			Id: devB, SyncIntervalMinutes: 30,
		}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})
}

// TestDeviceScope_GroupKeyed covers the first-class group-id match: a
// scoped admin may act on the group it is scoped to, and is denied on
// any other group.
func TestDeviceScope_GroupKeyed(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")

	dgA := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant A")
	dgB := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant B")

	t.Run("GetDeviceGroup: own group allowed, other denied", func(t *testing.T) {
		ctx := deviceScopedAdminCtx(adminID, dgA, "GetDeviceGroup")
		_, err := h.GetDeviceGroup(ctx, connect.NewRequest(&pm.GetDeviceGroupRequest{Id: dgA}))
		require.NoError(t, err)

		_, err = h.GetDeviceGroup(ctx, connect.NewRequest(&pm.GetDeviceGroupRequest{Id: dgB}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})
	t.Run("RenameDeviceGroup: own group allowed, other denied", func(t *testing.T) {
		ctx := deviceScopedAdminCtx(adminID, dgA, "RenameDeviceGroup")
		_, err := h.RenameDeviceGroup(ctx, connect.NewRequest(&pm.RenameDeviceGroupRequest{Id: dgA, Name: "Plant A2"}))
		require.NoError(t, err)

		_, err = h.RenameDeviceGroup(ctx, connect.NewRequest(&pm.RenameDeviceGroupRequest{Id: dgB, Name: "nope"}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})
	t.Run("unscoped admin may act on any group", func(t *testing.T) {
		ctx := testutil.AdminContext(adminID)
		_, err := h.GetDeviceGroup(ctx, connect.NewRequest(&pm.GetDeviceGroupRequest{Id: dgB}))
		require.NoError(t, err)
	})
}
