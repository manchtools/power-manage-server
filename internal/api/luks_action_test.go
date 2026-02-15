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

func TestCreateAction_Luks(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateAction(ctx, connect.NewRequest(&pm.CreateActionRequest{
		Name: "Encrypt Disk",
		Type: pm.ActionType_ACTION_TYPE_LUKS,
		Params: &pm.CreateActionRequest_Luks{
			Luks: &pm.LuksParams{
				PresharedKey:         "initial-psk-secret",
				RotationIntervalDays: 30,
				MinWords:             5,
				DeviceBoundKeyType:   pm.LuksDeviceBoundKeyType_LUKS_DEVICE_BOUND_KEY_TYPE_NONE,
			},
		},
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.Action.Id)
	assert.Equal(t, "Encrypt Disk", resp.Msg.Action.Name)
	assert.Equal(t, pm.ActionType_ACTION_TYPE_LUKS, resp.Msg.Action.Type)
}

func TestCreateAction_Luks_WithTPM(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateAction(ctx, connect.NewRequest(&pm.CreateActionRequest{
		Name: "LUKS with TPM",
		Type: pm.ActionType_ACTION_TYPE_LUKS,
		Params: &pm.CreateActionRequest_Luks{
			Luks: &pm.LuksParams{
				PresharedKey:         "tpm-psk",
				RotationIntervalDays: 90,
				MinWords:             7,
				DeviceBoundKeyType:   pm.LuksDeviceBoundKeyType_LUKS_DEVICE_BOUND_KEY_TYPE_TPM,
			},
		},
	}))
	require.NoError(t, err)
	assert.Equal(t, pm.ActionType_ACTION_TYPE_LUKS, resp.Msg.Action.Type)

	// Verify params round-trip
	luks := resp.Msg.Action.GetLuks()
	require.NotNil(t, luks)
	assert.Equal(t, "tpm-psk", luks.PresharedKey)
	assert.Equal(t, int32(90), luks.RotationIntervalDays)
	assert.Equal(t, int32(7), luks.MinWords)
	assert.Equal(t, pm.LuksDeviceBoundKeyType_LUKS_DEVICE_BOUND_KEY_TYPE_TPM, luks.DeviceBoundKeyType)
}

func TestCreateAction_Luks_WithUserPassphrase(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateAction(ctx, connect.NewRequest(&pm.CreateActionRequest{
		Name: "LUKS User Passphrase",
		Type: pm.ActionType_ACTION_TYPE_LUKS,
		Params: &pm.CreateActionRequest_Luks{
			Luks: &pm.LuksParams{
				PresharedKey:             "user-psk",
				RotationIntervalDays:     60,
				MinWords:                 5,
				DeviceBoundKeyType:       pm.LuksDeviceBoundKeyType_LUKS_DEVICE_BOUND_KEY_TYPE_USER_PASSPHRASE,
				UserPassphraseMinLength:  20,
				UserPassphraseComplexity: pm.LpsPasswordComplexity_LPS_PASSWORD_COMPLEXITY_COMPLEX,
			},
		},
	}))
	require.NoError(t, err)

	luks := resp.Msg.Action.GetLuks()
	require.NotNil(t, luks)
	assert.Equal(t, pm.LuksDeviceBoundKeyType_LUKS_DEVICE_BOUND_KEY_TYPE_USER_PASSPHRASE, luks.DeviceBoundKeyType)
	assert.Equal(t, int32(20), luks.UserPassphraseMinLength)
	assert.Equal(t, pm.LpsPasswordComplexity_LPS_PASSWORD_COMPLEXITY_COMPLEX, luks.UserPassphraseComplexity)
}

func TestCreateAction_Luks_GetAfterCreate(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	createResp, err := h.CreateAction(ctx, connect.NewRequest(&pm.CreateActionRequest{
		Name: "LUKS Get Test",
		Type: pm.ActionType_ACTION_TYPE_LUKS,
		Params: &pm.CreateActionRequest_Luks{
			Luks: &pm.LuksParams{
				PresharedKey:         "get-test-psk",
				RotationIntervalDays: 14,
				MinWords:             4,
			},
		},
	}))
	require.NoError(t, err)

	getResp, err := h.GetAction(ctx, connect.NewRequest(&pm.GetActionRequest{
		Id: createResp.Msg.Action.Id,
	}))
	require.NoError(t, err)
	assert.Equal(t, createResp.Msg.Action.Id, getResp.Msg.Action.Id)
	assert.Equal(t, pm.ActionType_ACTION_TYPE_LUKS, getResp.Msg.Action.Type)

	luks := getResp.Msg.Action.GetLuks()
	require.NotNil(t, luks)
	assert.Equal(t, "get-test-psk", luks.PresharedKey)
	assert.Equal(t, int32(14), luks.RotationIntervalDays)
	assert.Equal(t, int32(4), luks.MinWords)
}

func TestCreateAction_Luks_UpdateParams(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	createResp, err := h.CreateAction(ctx, connect.NewRequest(&pm.CreateActionRequest{
		Name: "LUKS Update Test",
		Type: pm.ActionType_ACTION_TYPE_LUKS,
		Params: &pm.CreateActionRequest_Luks{
			Luks: &pm.LuksParams{
				PresharedKey:         "update-psk",
				RotationIntervalDays: 30,
				MinWords:             5,
				DeviceBoundKeyType:   pm.LuksDeviceBoundKeyType_LUKS_DEVICE_BOUND_KEY_TYPE_NONE,
			},
		},
	}))
	require.NoError(t, err)

	updateResp, err := h.UpdateActionParams(ctx, connect.NewRequest(&pm.UpdateActionParamsRequest{
		Id: createResp.Msg.Action.Id,
		Params: &pm.UpdateActionParamsRequest_Luks{
			Luks: &pm.LuksParams{
				PresharedKey:         "update-psk",
				RotationIntervalDays: 7,
				MinWords:             8,
				DeviceBoundKeyType:   pm.LuksDeviceBoundKeyType_LUKS_DEVICE_BOUND_KEY_TYPE_TPM,
			},
		},
	}))
	require.NoError(t, err)

	luks := updateResp.Msg.Action.GetLuks()
	require.NotNil(t, luks)
	assert.Equal(t, int32(7), luks.RotationIntervalDays)
	assert.Equal(t, int32(8), luks.MinWords)
	assert.Equal(t, pm.LuksDeviceBoundKeyType_LUKS_DEVICE_BOUND_KEY_TYPE_TPM, luks.DeviceBoundKeyType)
}

func TestCreateAction_Luks_DeleteAction(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	createResp, err := h.CreateAction(ctx, connect.NewRequest(&pm.CreateActionRequest{
		Name: "LUKS Delete Test",
		Type: pm.ActionType_ACTION_TYPE_LUKS,
		Params: &pm.CreateActionRequest_Luks{
			Luks: &pm.LuksParams{
				PresharedKey:         "delete-psk",
				RotationIntervalDays: 30,
				MinWords:             5,
			},
		},
	}))
	require.NoError(t, err)

	_, err = h.DeleteAction(ctx, connect.NewRequest(&pm.DeleteActionRequest{
		Id: createResp.Msg.Action.Id,
	}))
	require.NoError(t, err)

	_, err = h.GetAction(ctx, connect.NewRequest(&pm.GetActionRequest{
		Id: createResp.Msg.Action.Id,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestCreateAction_Luks_ListIncludesLuks(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.CreateAction(ctx, connect.NewRequest(&pm.CreateActionRequest{
		Name: "LUKS List Test",
		Type: pm.ActionType_ACTION_TYPE_LUKS,
		Params: &pm.CreateActionRequest_Luks{
			Luks: &pm.LuksParams{
				PresharedKey:         "list-psk",
				RotationIntervalDays: 30,
				MinWords:             5,
			},
		},
	}))
	require.NoError(t, err)

	resp, err := h.ListActions(ctx, connect.NewRequest(&pm.ListActionsRequest{}))
	require.NoError(t, err)

	found := false
	for _, a := range resp.Msg.Actions {
		if a.Name == "LUKS List Test" && a.Type == pm.ActionType_ACTION_TYPE_LUKS {
			found = true
			break
		}
	}
	assert.True(t, found, "LUKS action should appear in list")
}
