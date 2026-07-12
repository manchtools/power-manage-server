package api_test

import (
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

// TestExecLogHandlers_ScopeExistenceOracleClosed pins spec 29 S10 for the
// load-then-scope execution/log handlers. Unlike the user-group handlers (whose
// scope keys on the id straight from the auth context), these must load the row
// to learn its device before they can scope-check — so "scope-check first" is
// impossible. The fix instead makes BOTH an out-of-scope existing object and an
// unknown id return the SAME code for a scope-restricted caller
// (PermissionDenied, matching the out-of-scope path), while a global caller —
// who can see every device — still gets an honest NotFound.
func TestExecLogHandlers_ScopeExistenceOracleClosed(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ah := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})
	ah.SetTaskQueueClient(&api.NoOpEnqueuer{})
	lh := api.NewLogsHandler(st, slog.Default(), api.NoOpSigner{})

	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")
	dgX := testutil.CreateTestDeviceGroup(t, st, actor, "In Scope")
	dgY := testutil.CreateTestDeviceGroup(t, st, actor, "Out Of Scope")
	devOut := testutil.CreateTestDevice(t, st, "out-of-scope-host")
	testutil.AddDeviceToTestGroup(t, st, actor, dgY, devOut)

	// Seed an execution on the out-of-scope device.
	actionID := testutil.CreateTestAction(t, st, actor, "Exec", int(pm.ActionType_ACTION_TYPE_SHELL))
	dispatch, err := ah.DispatchAction(testutil.AdminContext(actor), connect.NewRequest(&pm.DispatchActionRequest{
		DeviceId:     devOut,
		ActionSource: &pm.DispatchActionRequest_ActionId{ActionId: actionID},
	}))
	require.NoError(t, err)
	execOut := dispatch.Msg.Execution.Id

	// A caller scoped to dgX (which does NOT contain devOut) — restricted.
	perms := []string{"GetExecution", "CancelExecution", "GetDeviceLogResult"}
	grants := make([]auth.ScopedGrant, len(perms))
	for i, p := range perms {
		grants[i] = auth.ScopedGrant{Permission: p, ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: dgX}
	}
	scoped := testutil.AuthContextScoped(testutil.NewID(), "scoped@test.com", perms, grants)
	// A caller holding the same permissions UNSCOPED — not restricted.
	global := testutil.AuthContext(testutil.NewID(), "global@test.com", perms)
	nonexistent := testutil.NewID()

	t.Run("GetExecution", func(t *testing.T) {
		_, outErr := ah.GetExecution(scoped, connect.NewRequest(&pm.GetExecutionRequest{Id: execOut}))
		require.Error(t, outErr)
		_, missErr := ah.GetExecution(scoped, connect.NewRequest(&pm.GetExecutionRequest{Id: nonexistent}))
		require.Error(t, missErr)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(outErr), "out-of-scope existing execution")
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(missErr),
			"unknown id must not leak NotFound to a scoped caller")
		_, gErr := ah.GetExecution(global, connect.NewRequest(&pm.GetExecutionRequest{Id: nonexistent}))
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(gErr), "global caller still gets an honest NotFound")
	})

	t.Run("CancelExecution", func(t *testing.T) {
		_, outErr := ah.CancelExecution(scoped, connect.NewRequest(&pm.CancelExecutionRequest{ExecutionId: execOut}))
		require.Error(t, outErr)
		_, missErr := ah.CancelExecution(scoped, connect.NewRequest(&pm.CancelExecutionRequest{ExecutionId: nonexistent}))
		require.Error(t, missErr)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(outErr), "out-of-scope existing execution")
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(missErr),
			"unknown id must not leak NotFound to a scoped caller")
		_, gErr := ah.CancelExecution(global, connect.NewRequest(&pm.CancelExecutionRequest{ExecutionId: nonexistent}))
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(gErr), "global caller still gets an honest NotFound")
	})

	t.Run("GetDeviceLogResult", func(t *testing.T) {
		// Seeding a real log-query result is heavy; the unknown-id case is the
		// one that carries the oracle, so it is sufficient here.
		_, missErr := lh.GetDeviceLogResult(scoped, connect.NewRequest(&pm.GetDeviceLogResultRequest{QueryId: nonexistent}))
		require.Error(t, missErr)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(missErr),
			"unknown id must not leak NotFound to a scoped caller")
		_, gErr := lh.GetDeviceLogResult(global, connect.NewRequest(&pm.GetDeviceLogResultRequest{QueryId: nonexistent}))
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(gErr), "global caller still gets an honest NotFound")
	})
}
