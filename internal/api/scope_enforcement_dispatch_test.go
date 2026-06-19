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
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// Finding #3 (dispatch fan-out): the multi-device dispatch RPCs must scope-check
// EACH target device against the caller's device-group scope, failing the whole
// request closed if any target is out of scope. Before enforcement they relied
// on the per-device DispatchAction gate, which waves through a caller who holds
// the fan-out permission but not DispatchAction — leaving the fan-out unscoped.
func TestDispatchFanout_DeviceScopeEnforced(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	dgX := testutil.CreateTestDeviceGroup(t, st, actor, "Plant X") // in scope
	dgY := testutil.CreateTestDeviceGroup(t, st, actor, "Plant Y") // out of scope
	devIn := testutil.CreateTestDevice(t, st, "in-scope")
	devOut := testutil.CreateTestDevice(t, st, "out-of-scope")
	testutil.AddDeviceToTestGroup(t, st, actor, dgX, devIn)
	testutil.AddDeviceToTestGroup(t, st, actor, dgY, devOut)

	// Caller holds each dispatch permission scoped ONLY to dgX.
	perms := []string{"DispatchToMultiple", "DispatchActionSet", "DispatchDefinition", "DispatchToGroup"}
	grants := make([]auth.ScopedGrant, len(perms))
	for i, p := range perms {
		grants[i] = auth.ScopedGrant{Permission: p, ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: dgX}
	}
	scoped := func() context.Context {
		return testutil.AuthContextScoped(testutil.NewID(), "scoped@test.com", perms, grants)
	}

	t.Run("DispatchToMultiple denies an out-of-scope device", func(t *testing.T) {
		_, err := h.DispatchToMultiple(scoped(), connect.NewRequest(&pm.DispatchToMultipleRequest{
			DeviceIds:    []string{devOut},
			ActionSource: &pm.DispatchToMultipleRequest_ActionId{ActionId: testutil.NewID()},
		}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})

	t.Run("DispatchToMultiple denies a mixed in/out batch (fail closed)", func(t *testing.T) {
		_, err := h.DispatchToMultiple(scoped(), connect.NewRequest(&pm.DispatchToMultipleRequest{
			DeviceIds:    []string{devIn, devOut},
			ActionSource: &pm.DispatchToMultipleRequest_ActionId{ActionId: testutil.NewID()},
		}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})

	t.Run("DispatchActionSet denies an out-of-scope device", func(t *testing.T) {
		_, err := h.DispatchActionSet(scoped(), connect.NewRequest(&pm.DispatchActionSetRequest{
			DeviceId: devOut, ActionSetId: testutil.NewID(),
		}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})

	t.Run("DispatchDefinition denies an out-of-scope device", func(t *testing.T) {
		_, err := h.DispatchDefinition(scoped(), connect.NewRequest(&pm.DispatchDefinitionRequest{
			DeviceId: devOut, DefinitionId: testutil.NewID(),
		}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})

	t.Run("DispatchToGroup denies a group of out-of-scope devices", func(t *testing.T) {
		_, err := h.DispatchToGroup(scoped(), connect.NewRequest(&pm.DispatchToGroupRequest{
			GroupId:      dgY,
			ActionSource: &pm.DispatchToGroupRequest_ActionId{ActionId: testutil.NewID()},
		}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})

	// In-scope targets must NOT be denied by scope (they may no-op for unrelated
	// reasons — missing action set, no task queue — but never PermissionDenied).
	t.Run("DispatchToGroup allows a group of in-scope devices", func(t *testing.T) {
		_, err := h.DispatchToGroup(scoped(), connect.NewRequest(&pm.DispatchToGroupRequest{
			GroupId:      dgX,
			ActionSource: &pm.DispatchToGroupRequest_ActionId{ActionId: testutil.NewID()},
		}))
		if err != nil {
			assert.NotEqual(t, connect.CodePermissionDenied, connect.CodeOf(err))
		}
	})

	t.Run("DispatchToMultiple allows in-scope devices", func(t *testing.T) {
		_, err := h.DispatchToMultiple(scoped(), connect.NewRequest(&pm.DispatchToMultipleRequest{
			DeviceIds:    []string{devIn},
			ActionSource: &pm.DispatchToMultipleRequest_ActionId{ActionId: testutil.NewID()},
		}))
		if err != nil {
			assert.NotEqual(t, connect.CodePermissionDenied, connect.CodeOf(err))
		}
	})
}
