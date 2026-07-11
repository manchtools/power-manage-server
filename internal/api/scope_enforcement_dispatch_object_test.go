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

// spec 29 S1: a dispatch RPC must enforce OBJECT read-scope on the referenced
// action/set/definition, not only DEVICE scope. Here the caller's device scope
// INCLUDES the target device, but the object is assigned only to a group OUTSIDE
// the caller's scope — so only the object-scope check can deny it. Out of scope →
// NotFound (no existence leak), matching GetAction. Without the object-scope
// gate, device scope alone would let a scoped admin execute an object it cannot
// even read.
func TestDispatchObjectScope_OutOfScopeObjectDenied(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	dgIn := testutil.CreateTestDeviceGroup(t, st, actor, "In Scope")
	dgObj := testutil.CreateTestDeviceGroup(t, st, actor, "Object Group") // caller NOT scoped here
	devIn := testutil.CreateTestDevice(t, st, "in-scope-device")
	testutil.AddDeviceToTestGroup(t, st, actor, dgIn, devIn)

	// Objects assigned ONLY to dgObj (outside the caller's scope).
	actionID := testutil.CreateTestAction(t, st, actor, "secret-script", int(pm.ActionType_ACTION_TYPE_SHELL))
	testutil.CreateTestAssignment(t, st, actor, "action", actionID, "device_group", dgObj, 0)
	setID := testutil.CreateTestActionSet(t, st, actor, "secret-set")
	testutil.CreateTestAssignment(t, st, actor, "action_set", setID, "device_group", dgObj, 0)
	defID := testutil.CreateTestDefinition(t, st, actor, "secret-def")
	testutil.CreateTestAssignment(t, st, actor, "definition", defID, "device_group", dgObj, 0)

	// Caller scoped to dgIn (device IS in scope) but NOT dgObj (object out of
	// scope), holding every dispatch permission scoped to dgIn.
	perms := []string{"DispatchAction", "DispatchActionSet", "DispatchDefinition", "DispatchToGroup"}
	grants := make([]auth.ScopedGrant, len(perms))
	for i, p := range perms {
		grants[i] = auth.ScopedGrant{Permission: p, ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: dgIn}
	}
	scoped := func() context.Context {
		return testutil.AuthContextScoped(testutil.NewID(), "scoped@test.com", perms, grants)
	}

	t.Run("DispatchAction on out-of-scope action → NotFound", func(t *testing.T) {
		_, err := h.DispatchAction(scoped(), connect.NewRequest(&pm.DispatchActionRequest{
			DeviceId:     devIn, // device IS in scope; only the object is out
			ActionSource: &pm.DispatchActionRequest_ActionId{ActionId: actionID},
		}))
		require.Error(t, err)
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err),
			"object-scope must deny an out-of-scope action even when the device is in scope")
	})

	t.Run("DispatchActionSet on out-of-scope set → NotFound", func(t *testing.T) {
		_, err := h.DispatchActionSet(scoped(), connect.NewRequest(&pm.DispatchActionSetRequest{
			DeviceId: devIn, ActionSetId: setID,
		}))
		require.Error(t, err)
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	})

	t.Run("DispatchDefinition on out-of-scope definition → NotFound", func(t *testing.T) {
		_, err := h.DispatchDefinition(scoped(), connect.NewRequest(&pm.DispatchDefinitionRequest{
			DeviceId: devIn, DefinitionId: defID,
		}))
		require.Error(t, err)
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	})

	t.Run("DispatchToGroup with out-of-scope action → NotFound", func(t *testing.T) {
		_, err := h.DispatchToGroup(scoped(), connect.NewRequest(&pm.DispatchToGroupRequest{
			GroupId:      dgIn, // group's devices are in scope
			ActionSource: &pm.DispatchToGroupRequest_ActionId{ActionId: actionID},
		}))
		require.Error(t, err)
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	})
}
