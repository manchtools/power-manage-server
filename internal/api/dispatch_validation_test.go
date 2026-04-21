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

// TestDispatchAction_InlineNilRejected is the panic-guard the audit
// called out: the inline branch dereferenced source.InlineAction
// without a nil check, so a caller sending an empty InlineAction
// oneof would crash the handler. The new validateInlineActionPayload
// must reject nil before extractActionParamsMsg runs.
func TestDispatchAction_InlineNilRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "dispatch-inline-nil-host")
	ctx := testutil.AdminContext(adminID)

	_, err := h.DispatchAction(ctx, connect.NewRequest(&pm.DispatchActionRequest{
		DeviceId: deviceID,
		ActionSource: &pm.DispatchActionRequest_InlineAction{
			InlineAction: nil,
		},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

// TestDispatchAction_InlineShellMissingScriptRejected pins the
// parity fix: DispatchAction's inline branch must run the same
// shell "at least one of script or detection_script" rule that
// Create applies, otherwise an inline dispatch can smuggle an
// empty-script shell action that would never run.
func TestDispatchAction_InlineShellMissingScriptRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "dispatch-inline-shell-host")
	ctx := testutil.AdminContext(adminID)

	_, err := h.DispatchAction(ctx, connect.NewRequest(&pm.DispatchActionRequest{
		DeviceId: deviceID,
		ActionSource: &pm.DispatchActionRequest_InlineAction{
			InlineAction: &pm.Action{
				Type:         pm.ActionType_ACTION_TYPE_SHELL,
				DesiredState: pm.DesiredState_DESIRED_STATE_PRESENT,
				Params: &pm.Action_Shell{
					Shell: &pm.ShellParams{
						// Neither Script nor DetectionScript set.
					},
				},
			},
		},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

// TestUpdateActionParams_ShellMissingScriptRejected pins the
// Update-path parity fix: the original Update handler only ran
// struct-tag Validate, skipping the "script OR detection_script
// required" rule that Create applies. An operator editing a valid
// shell action to wipe both scripts would otherwise silently turn
// it into a no-op signed action that does nothing on dispatch.
func TestUpdateActionParams_ShellMissingScriptRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	// Seed a valid shell action first.
	created, err := h.CreateAction(ctx, connect.NewRequest(&pm.CreateActionRequest{
		Name: "Shell-that-will-be-broken",
		Type: pm.ActionType_ACTION_TYPE_SHELL,
		Params: &pm.CreateActionRequest_Shell{
			Shell: &pm.ShellParams{Script: "echo ok"},
		},
	}))
	require.NoError(t, err)

	_, err = h.UpdateActionParams(ctx, connect.NewRequest(&pm.UpdateActionParamsRequest{
		Id: created.Msg.Action.Id,
		Params: &pm.UpdateActionParamsRequest_Shell{
			Shell: &pm.ShellParams{
				// Both scripts blanked — must be rejected.
			},
		},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}
