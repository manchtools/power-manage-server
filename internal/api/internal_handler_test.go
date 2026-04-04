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
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestVerifyDevice_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	deviceID := testutil.CreateTestDevice(t, st, "verify-host")

	resp, err := h.VerifyDevice(context.Background(), connect.NewRequest(&pm.VerifyDeviceRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestVerifyDevice_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	_, err := h.VerifyDevice(context.Background(), connect.NewRequest(&pm.VerifyDeviceRequest{
		DeviceId: testutil.NewID(),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestVerifyDevice_EmptyID(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	_, err := h.VerifyDevice(context.Background(), connect.NewRequest(&pm.VerifyDeviceRequest{
		DeviceId: "",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestProxySyncActions_EmptyDeviceID(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	_, err := h.ProxySyncActions(context.Background(), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: "",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestProxySyncActions_DeviceNotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	_, err := h.ProxySyncActions(context.Background(), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: testutil.NewID(),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestProxySyncActions_NoAssignments(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	deviceID := testutil.CreateTestDevice(t, st, "sync-host")

	resp, err := h.ProxySyncActions(context.Background(), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.Actions)
}

func TestProxySyncActions_WithAssignment(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "sync-assigned-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Sync Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	// Assign action directly to device
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, int(pm.AssignmentMode_ASSIGNMENT_MODE_REQUIRED))

	resp, err := h.ProxySyncActions(context.Background(), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Len(t, resp.Msg.Actions, 1)
	assert.Equal(t, actionID, resp.Msg.Actions[0].Id.Value)
}

func TestProxyStoreLuksKey(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewInternalHandler(st, enc, slog.Default())

	deviceID := testutil.CreateTestDevice(t, st, "luks-store-host")

	resp, err := h.ProxyStoreLuksKey(context.Background(), connect.NewRequest(&pm.InternalStoreLuksKeyRequest{
		DeviceId:       deviceID,
		ActionId:       testutil.NewID(),
		DevicePath:     "/dev/sda1",
		Passphrase:     "super-secret-key",
		RotationReason: "initial",
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Success)
}

func TestProxyStoreLuksKey_MissingFields(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	_, err := h.ProxyStoreLuksKey(context.Background(), connect.NewRequest(&pm.InternalStoreLuksKeyRequest{
		DeviceId: "",
		ActionId: "",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestProxyValidateLuksToken_MissingFields(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	_, err := h.ProxyValidateLuksToken(context.Background(), connect.NewRequest(&pm.InternalValidateLuksTokenRequest{
		DeviceId: "",
		Token:    "",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestProxyGetLuksKey_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	_, err := h.ProxyGetLuksKey(context.Background(), connect.NewRequest(&pm.InternalGetLuksKeyRequest{
		DeviceId: testutil.NewID(),
		ActionId: testutil.NewID(),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestProxyStoreLpsPasswords(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewInternalHandler(st, enc, slog.Default())

	deviceID := testutil.CreateTestDevice(t, st, "lps-host")

	resp, err := h.ProxyStoreLpsPasswords(context.Background(), connect.NewRequest(&pm.InternalStoreLpsPasswordsRequest{
		DeviceId: deviceID,
		ActionId: testutil.NewID(),
		Rotations: []*pm.LpsPasswordRotation{
			{
				Username:  "admin",
				Password:  "new-pass-123",
				RotatedAt: "2026-03-31T12:00:00Z",
				Reason:    "scheduled",
			},
		},
	}))
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestProxyStoreLpsPasswords_MissingFields(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default())

	_, err := h.ProxyStoreLpsPasswords(context.Background(), connect.NewRequest(&pm.InternalStoreLpsPasswordsRequest{
		DeviceId: "",
		ActionId: "",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}
