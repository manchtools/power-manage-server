package handler

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

func TestSyncActions_MissingDeviceID(t *testing.T) {
	// The handler validates input before calling the control proxy,
	// so this test works without any external dependencies.
	h := &AgentHandler{}

	_, err := h.SyncActions(context.Background(), connect.NewRequest(&pm.SyncActionsRequest{}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestDeviceIDFromContext_Present(t *testing.T) {
	ctx := context.WithValue(context.Background(), DeviceIDContextKey, "device-123")

	id, ok := DeviceIDFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, "device-123", id)
}

func TestDeviceIDFromContext_Absent(t *testing.T) {
	_, ok := DeviceIDFromContext(context.Background())
	assert.False(t, ok)
}

func TestValidateLuksToken_MissingFields(t *testing.T) {
	h := &AgentHandler{}

	_, err := h.ValidateLuksToken(context.Background(), connect.NewRequest(&pm.ValidateLuksTokenRequest{}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}
