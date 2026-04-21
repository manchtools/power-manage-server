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
// oneof would crash the handler. The new validateInlineAction
// must reject nil before extractActionParamsMsg runs.
func TestDispatchAction_InlineNilRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})

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
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})

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

// TestDispatchAction_InlineUnspecifiedTypeRejected pins one of the
// invariants validateInlineAction enforces beyond the per-oneof
// validation: ACTION_TYPE_UNSPECIFIED must be refused. Without the
// guard, an inline dispatch with no Type set would reach the
// agent and confuse the dispatch path.
func TestDispatchAction_InlineUnspecifiedTypeRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "dispatch-inline-unspec-host")
	ctx := testutil.AdminContext(adminID)

	_, err := h.DispatchAction(ctx, connect.NewRequest(&pm.DispatchActionRequest{
		DeviceId: deviceID,
		ActionSource: &pm.DispatchActionRequest_InlineAction{
			InlineAction: &pm.Action{
				// Type intentionally omitted.
				Params: &pm.Action_Shell{Shell: &pm.ShellParams{Script: "echo x"}},
			},
		},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

// TestDispatchAction_InlineParamsMismatchTypeRejected pins the
// strictest of the invariants: action.Type and action.Params oneof
// must agree. A caller routing Type=USER through an Action_Ssh oneof
// would otherwise have the dispatch path treat it as a USER action
// while the agent receives Ssh-shaped params bytes — silent param
// corruption. The guard refuses the request server-side.
func TestDispatchAction_InlineParamsMismatchTypeRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "dispatch-inline-mismatch-host")
	ctx := testutil.AdminContext(adminID)

	_, err := h.DispatchAction(ctx, connect.NewRequest(&pm.DispatchActionRequest{
		DeviceId: deviceID,
		ActionSource: &pm.DispatchActionRequest_InlineAction{
			InlineAction: &pm.Action{
				Type: pm.ActionType_ACTION_TYPE_USER,
				Params: &pm.Action_Ssh{ // mismatched oneof
					Ssh: &pm.SshParams{Users: []string{"alice"}},
				},
			},
		},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

// TestDispatchAction_InlineTimeoutOutOfBoundsRejected pins the
// timeout-bounds invariant. validateInlineAction enforces
// 0 <= TimeoutSeconds <= 3600.
func TestDispatchAction_InlineTimeoutOutOfBoundsRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "dispatch-inline-timeout-host")
	ctx := testutil.AdminContext(adminID)

	_, err := h.DispatchAction(ctx, connect.NewRequest(&pm.DispatchActionRequest{
		DeviceId: deviceID,
		ActionSource: &pm.DispatchActionRequest_InlineAction{
			InlineAction: &pm.Action{
				Type:           pm.ActionType_ACTION_TYPE_SHELL,
				TimeoutSeconds: 99999, // way over the 3600 cap
				Params: &pm.Action_Shell{
					Shell: &pm.ShellParams{Script: "echo x"},
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
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})

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
