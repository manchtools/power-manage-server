package api_test

import (
	"log/slog"
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
	h := api.NewActionHandler(st, slog.Default(), nil)

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

// AdminPolicy custom_config carries the raw sudoers / doas.conf
// fragment the admin wants rendered on the device. The proto pins a
// `validate:"required_if=AccessLevel 3"` rule that refuses
// ADMIN_ACCESS_LEVEL_CUSTOM with an empty custom_config — otherwise
// the agent would end up rendering an empty policy file, which on
// sudoers means "no rules" and on doas means the rule set silently
// disappears. Pin the rejection here so a future refactor of Validate()
// can't silently drop the guard.
//
// Syntax validation of the policy content itself lives on the agent
// side (visudo -c / doas -C) — the server has no business parsing
// either grammar, especially since the target distro's version of
// sudo or doas may accept syntax the server's vendored parser
// wouldn't. This test deliberately only covers the "empty-config"
// rejection, which is a pure proto-level constraint.
func TestCreateAction_AdminPolicy_CustomRequiresConfig(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.CreateAction(ctx, connect.NewRequest(&pm.CreateActionRequest{
		Name: "Admin Policy CUSTOM with no config",
		Type: pm.ActionType_ACTION_TYPE_ADMIN_POLICY,
		Params: &pm.CreateActionRequest_AdminPolicy{
			AdminPolicy: &pm.AdminPolicyParams{
				AccessLevel:  pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_CUSTOM,
				Users:        []string{"opsuser"},
				CustomConfig: "", // intentionally empty — should be rejected
			},
		},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	// Sanity check the complementary path: CUSTOM + non-empty config
	// passes validation, so the rule really is firing on empty-string
	// and not on some unrelated precondition.
	resp, err := h.CreateAction(ctx, connect.NewRequest(&pm.CreateActionRequest{
		Name: "Admin Policy CUSTOM with config",
		Type: pm.ActionType_ACTION_TYPE_ADMIN_POLICY,
		Params: &pm.CreateActionRequest_AdminPolicy{
			AdminPolicy: &pm.AdminPolicyParams{
				AccessLevel:  pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_CUSTOM,
				Users:        []string{"opsuser"},
				CustomConfig: "{group} ALL=(ALL) NOPASSWD: /usr/bin/systemctl *",
			},
		},
	}))
	require.NoError(t, err)
	assert.Equal(t, pm.ActionType_ACTION_TYPE_ADMIN_POLICY, resp.Msg.Action.Type)
}

func TestCreateAction_DefaultTimeout(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), nil)

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
	h := api.NewActionHandler(st, slog.Default(), nil)

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
	h := api.NewActionHandler(st, slog.Default(), nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.GetAction(ctx, connect.NewRequest(&pm.GetActionRequest{Id: testutil.NewID()}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestListActions(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), nil)

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
	h := api.NewActionHandler(st, slog.Default(), nil)

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
	h := api.NewActionHandler(st, slog.Default(), nil)

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
	h := api.NewActionHandler(st, slog.Default(), nil)

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
	h := api.NewActionHandler(st, slog.Default(), nil)

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
	h := api.NewActionHandler(st, slog.Default(), nil)

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
	h := api.NewActionHandler(st, slog.Default(), nil)

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
	h := api.NewActionHandler(st, slog.Default(), nil)

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
