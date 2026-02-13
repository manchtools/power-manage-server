package handler

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func newTestHandler(t *testing.T) (*AgentHandler, *store.Store) {
	t.Helper()
	st := testutil.SetupPostgres(t)
	mgr := connection.NewManager()
	h := &AgentHandler{
		manager: mgr,
		store:   st,
		logger:  slog.Default(),
	}
	return h, st
}

func TestSyncActions_Empty(t *testing.T) {
	h, st := newTestHandler(t)
	ctx := context.Background()

	deviceID := testutil.CreateTestDevice(t, st, "empty-host")

	resp, err := h.SyncActions(ctx, connect.NewRequest(&pm.SyncActionsRequest{
		DeviceId: &pm.DeviceId{Value: deviceID},
	}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.Actions)
}

func TestSyncActions_WithAssigned(t *testing.T) {
	h, st := newTestHandler(t)
	ctx := context.Background()

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "sync-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Sync Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	// Create assignment action → device
	assignmentID := testutil.NewID()
	err := st.AppendEvent(ctx, store.Event{
		StreamType: "assignment",
		StreamID:   assignmentID,
		EventType:  "AssignmentCreated",
		Data: map[string]any{
			"source_type": "action",
			"source_id":   actionID,
			"target_type": "device",
			"target_id":   deviceID,
			"mode":        0,
		},
		ActorType: "user",
		ActorID:   adminID,
	})
	require.NoError(t, err)

	resp, err := h.SyncActions(ctx, connect.NewRequest(&pm.SyncActionsRequest{
		DeviceId: &pm.DeviceId{Value: deviceID},
	}))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.Msg.Actions), 1)
}

func TestSyncActions_MissingDeviceID(t *testing.T) {
	h, _ := newTestHandler(t)
	ctx := context.Background()

	_, err := h.SyncActions(ctx, connect.NewRequest(&pm.SyncActionsRequest{}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestHandleAgentMessage_Heartbeat(t *testing.T) {
	h, st := newTestHandler(t)
	ctx := context.Background()

	deviceID := testutil.CreateTestDevice(t, st, "heartbeat-host")

	err := h.handleAgentMessage(ctx, deviceID, &pm.AgentMessage{
		Payload: &pm.AgentMessage_Heartbeat{
			Heartbeat: &pm.Heartbeat{
				Uptime:        durationpb.New(3600 * time.Second),
				CpuPercent:    45.0,
				MemoryPercent: 60.0,
			},
		},
	})
	require.NoError(t, err)
}

func TestHandleAgentMessage_ActionResult_Success(t *testing.T) {
	h, st := newTestHandler(t)
	ctx := context.Background()

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "result-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Result Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	// Create execution via event
	execID := testutil.NewID()
	err := st.AppendEvent(ctx, store.Event{
		StreamType: "execution",
		StreamID:   execID,
		EventType:  "ExecutionCreated",
		Data: map[string]any{
			"device_id":       deviceID,
			"action_id":       actionID,
			"action_type":     int32(pm.ActionType_ACTION_TYPE_SHELL),
			"desired_state":   0,
			"params":          map[string]any{},
			"timeout_seconds": 300,
		},
		ActorType: "user",
		ActorID:   adminID,
	})
	require.NoError(t, err)

	// Send success result
	err = h.handleAgentMessage(ctx, deviceID, &pm.AgentMessage{
		Payload: &pm.AgentMessage_ActionResult{
			ActionResult: &pm.ActionResult{
				ActionId:    &pm.ActionId{Value: execID},
				Status:      pm.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
				DurationMs:  500,
				CompletedAt: timestamppb.Now(),
				Changed:     true,
				Output: &pm.CommandOutput{
					Stdout:   "hello world",
					ExitCode: 0,
				},
			},
		},
	})
	require.NoError(t, err)

	// Verify execution completed
	exec, err := st.Queries().GetExecutionByID(ctx, execID)
	require.NoError(t, err)
	assert.Equal(t, "success", exec.Status)
}

func TestHandleAgentMessage_ActionResult_Failed(t *testing.T) {
	h, st := newTestHandler(t)
	ctx := context.Background()

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "fail-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Fail Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	// Create execution
	execID := testutil.NewID()
	err := st.AppendEvent(ctx, store.Event{
		StreamType: "execution",
		StreamID:   execID,
		EventType:  "ExecutionCreated",
		Data: map[string]any{
			"device_id":       deviceID,
			"action_id":       actionID,
			"action_type":     int32(pm.ActionType_ACTION_TYPE_SHELL),
			"desired_state":   0,
			"params":          map[string]any{},
			"timeout_seconds": 300,
		},
		ActorType: "user",
		ActorID:   adminID,
	})
	require.NoError(t, err)

	err = h.handleAgentMessage(ctx, deviceID, &pm.AgentMessage{
		Payload: &pm.AgentMessage_ActionResult{
			ActionResult: &pm.ActionResult{
				ActionId:    &pm.ActionId{Value: execID},
				Status:      pm.ExecutionStatus_EXECUTION_STATUS_FAILED,
				DurationMs:  100,
				CompletedAt: timestamppb.Now(),
				Error:       "command failed",
			},
		},
	})
	require.NoError(t, err)

	exec, err := st.Queries().GetExecutionByID(ctx, execID)
	require.NoError(t, err)
	assert.Equal(t, "failed", exec.Status)
}

func TestHandleAgentMessage_AgentScheduled(t *testing.T) {
	h, st := newTestHandler(t)
	ctx := context.Background()

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "scheduled-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Scheduled Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	// Send result for agent-scheduled action (no existing execution)
	err := h.handleAgentMessage(ctx, deviceID, &pm.AgentMessage{
		Payload: &pm.AgentMessage_ActionResult{
			ActionResult: &pm.ActionResult{
				ActionId:    &pm.ActionId{Value: actionID},
				Status:      pm.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
				DurationMs:  200,
				CompletedAt: timestamppb.Now(),
				Changed:     false,
			},
		},
	})
	require.NoError(t, err)
}

func TestHandleAgentMessage_SecurityAlert(t *testing.T) {
	h, st := newTestHandler(t)
	ctx := context.Background()

	deviceID := testutil.CreateTestDevice(t, st, "alert-host")

	err := h.handleAgentMessage(ctx, deviceID, &pm.AgentMessage{
		Payload: &pm.AgentMessage_SecurityAlert{
			SecurityAlert: &pm.SecurityAlert{
				Message: "unauthorized access attempt",
				Details: map[string]string{"source": "SSH brute force detected"},
			},
		},
	})
	require.NoError(t, err)
}

func TestHandleAgentMessage_OutputChunk(t *testing.T) {
	h, st := newTestHandler(t)
	ctx := context.Background()

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "chunk-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Chunk Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	// Create execution
	execID := testutil.NewID()
	err := st.AppendEvent(ctx, store.Event{
		StreamType: "execution",
		StreamID:   execID,
		EventType:  "ExecutionCreated",
		Data: map[string]any{
			"device_id":       deviceID,
			"action_id":       actionID,
			"action_type":     int32(pm.ActionType_ACTION_TYPE_SHELL),
			"desired_state":   0,
			"params":          map[string]any{},
			"timeout_seconds": 300,
		},
		ActorType: "user",
		ActorID:   adminID,
	})
	require.NoError(t, err)

	err = h.handleAgentMessage(ctx, deviceID, &pm.AgentMessage{
		Payload: &pm.AgentMessage_OutputChunk{
			OutputChunk: &pm.OutputChunk{
				ExecutionId: execID,
				Stream:      pm.OutputStreamType_OUTPUT_STREAM_TYPE_STDOUT,
				Data:        []byte("line 1\n"),
				Sequence:    0,
			},
		},
	})
	require.NoError(t, err)
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
