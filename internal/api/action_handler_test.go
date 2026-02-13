package api_test

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestCreateAction_Shell(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateAction(ctx, connect.NewRequest(&pm.CreateActionRequest{
		Name: "Run Script",
		Type: pm.ActionType_ACTION_TYPE_SHELL,
		Params: &pm.CreateActionRequest_Shell{
			Shell: &pm.ShellParams{
				Script: "echo hello",
			},
		},
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.Action.Id)
	assert.Equal(t, "Run Script", resp.Msg.Action.Name)
	assert.Equal(t, pm.ActionType_ACTION_TYPE_SHELL, resp.Msg.Action.Type)
}

func TestCreateAction_DefaultTimeout(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateAction(ctx, connect.NewRequest(&pm.CreateActionRequest{
		Name: "Default Timeout",
		Type: pm.ActionType_ACTION_TYPE_SHELL,
		Params: &pm.CreateActionRequest_Shell{
			Shell: &pm.ShellParams{Script: "true"},
		},
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(300), resp.Msg.Action.TimeoutSeconds)
}

func TestGetAction(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, adminID, "Test Action", int(pm.ActionType_ACTION_TYPE_SHELL))
	ctx := testutil.AdminContext(adminID)

	resp, err := h.GetAction(ctx, connect.NewRequest(&pm.GetActionRequest{Id: actionID}))
	require.NoError(t, err)
	assert.Equal(t, actionID, resp.Msg.Action.Id)
	assert.Equal(t, "Test Action", resp.Msg.Action.Name)
}

func TestGetAction_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.GetAction(ctx, connect.NewRequest(&pm.GetActionRequest{Id: testutil.NewID()}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestListActions(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	for i := 0; i < 3; i++ {
		testutil.CreateTestAction(t, st, adminID, testutil.NewID(), int(pm.ActionType_ACTION_TYPE_SHELL))
	}

	resp, err := h.ListActions(ctx, connect.NewRequest(&pm.ListActionsRequest{}))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.Msg.Actions), 3)
}

func TestRenameAction(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, adminID, "Old", int(pm.ActionType_ACTION_TYPE_SHELL))
	ctx := testutil.AdminContext(adminID)

	resp, err := h.RenameAction(ctx, connect.NewRequest(&pm.RenameActionRequest{
		Id:   actionID,
		Name: "New",
	}))
	require.NoError(t, err)
	assert.Equal(t, "New", resp.Msg.Action.Name)
}

func TestDeleteAction(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, adminID, "To Delete", int(pm.ActionType_ACTION_TYPE_SHELL))
	ctx := testutil.AdminContext(adminID)

	_, err := h.DeleteAction(ctx, connect.NewRequest(&pm.DeleteActionRequest{Id: actionID}))
	require.NoError(t, err)

	_, err = h.GetAction(ctx, connect.NewRequest(&pm.GetActionRequest{Id: actionID}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestDispatchAction_ByID(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, adminID, "Dispatch Test", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "dispatch-host")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.DispatchAction(ctx, connect.NewRequest(&pm.DispatchActionRequest{
		DeviceId: deviceID,
		ActionSource: &pm.DispatchActionRequest_ActionId{
			ActionId: actionID,
		},
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.Execution.Id)
	assert.Equal(t, deviceID, resp.Msg.Execution.DeviceId)
}

func TestDispatchAction_DeviceNotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, adminID, "Test", int(pm.ActionType_ACTION_TYPE_SHELL))
	ctx := testutil.AdminContext(adminID)

	_, err := h.DispatchAction(ctx, connect.NewRequest(&pm.DispatchActionRequest{
		DeviceId: testutil.NewID(),
		ActionSource: &pm.DispatchActionRequest_ActionId{
			ActionId: actionID,
		},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestListExecutions(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, adminID, "Exec Test", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "exec-host")
	ctx := testutil.AdminContext(adminID)

	// Dispatch to create an execution
	_, err := h.DispatchAction(ctx, connect.NewRequest(&pm.DispatchActionRequest{
		DeviceId: deviceID,
		ActionSource: &pm.DispatchActionRequest_ActionId{
			ActionId: actionID,
		},
	}))
	require.NoError(t, err)

	resp, err := h.ListExecutions(ctx, connect.NewRequest(&pm.ListExecutionsRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.Msg.Executions), 1)
}

func TestGetExecution(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, adminID, "Get Exec", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "get-exec-host")
	ctx := testutil.AdminContext(adminID)

	dispatchResp, err := h.DispatchAction(ctx, connect.NewRequest(&pm.DispatchActionRequest{
		DeviceId: deviceID,
		ActionSource: &pm.DispatchActionRequest_ActionId{
			ActionId: actionID,
		},
	}))
	require.NoError(t, err)

	resp, err := h.GetExecution(ctx, connect.NewRequest(&pm.GetExecutionRequest{
		Id: dispatchResp.Msg.Execution.Id,
	}))
	require.NoError(t, err)
	assert.Equal(t, dispatchResp.Msg.Execution.Id, resp.Msg.Execution.Id)
	assert.Equal(t, deviceID, resp.Msg.Execution.DeviceId)
}

func TestDispatchInstantAction(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "instant-host")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.DispatchInstantAction(ctx, connect.NewRequest(&pm.DispatchInstantActionRequest{
		DeviceId:      deviceID,
		InstantAction: pm.ActionType_ACTION_TYPE_REBOOT,
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.Execution.Id)
	assert.Equal(t, deviceID, resp.Msg.Execution.DeviceId)
	assert.Equal(t, pm.ActionType_ACTION_TYPE_REBOOT, resp.Msg.Execution.Type)
}
