package control_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/control"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// fakeSigner records Sign calls so tests can verify the signer
// was invoked with the correct arguments (execution ID, not action ID).
type fakeSigner struct {
	mu    sync.Mutex
	calls []fakeSignCall
}

type fakeSignCall struct {
	ActionID   string
	ActionType int32
	ParamsJSON []byte
}

func (s *fakeSigner) Sign(actionID string, actionType int32, paramsJSON []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, fakeSignCall{
		ActionID:   actionID,
		ActionType: actionType,
		ParamsJSON: append([]byte(nil), paramsJSON...),
	})
	return []byte("fake-sig-for-" + actionID), nil
}

func (s *fakeSigner) getCalls() []fakeSignCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]fakeSignCall(nil), s.calls...)
}

func newTask(t *testing.T, typeName string, payload any) *asynq.Task {
	t.Helper()
	data, err := json.Marshal(payload)
	require.NoError(t, err)
	return asynq.NewTask(typeName, data)
}

func TestHandleDeviceHeartbeat(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, nil, slog.Default())
	mux := worker.NewMux()

	deviceID := testutil.CreateTestDevice(t, st, "heartbeat-host")

	task := newTask(t, taskqueue.TypeDeviceHeartbeat, taskqueue.DeviceHeartbeatPayload{
		DeviceID:     deviceID,
		AgentVersion: "2.0.0",
	})

	err := mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)

	// Verify the device's last_seen was updated via the projection
	device, err := st.Queries().GetDeviceByID(context.Background(), db.GetDeviceByIDParams{ID: deviceID})
	require.NoError(t, err)
	assert.NotNil(t, device.LastSeenAt)
}

func TestHandleDeviceHeartbeat_DeletedDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, nil, slog.Default())
	mux := worker.NewMux()

	deviceID := testutil.CreateTestDevice(t, st, "deleted-heartbeat-host")

	// Delete the device
	err := st.AppendEvent(context.Background(), store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "DeviceDeleted",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	})
	require.NoError(t, err)

	task := newTask(t, taskqueue.TypeDeviceHeartbeat, taskqueue.DeviceHeartbeatPayload{
		DeviceID:     deviceID,
		AgentVersion: "2.0.0",
	})

	// Should succeed silently (skip deleted device)
	err = mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)
}

func TestHandleSecurityAlert(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, nil, slog.Default())
	mux := worker.NewMux()

	deviceID := testutil.CreateTestDevice(t, st, "alert-host")

	task := newTask(t, taskqueue.TypeSecurityAlert, taskqueue.SecurityAlertPayload{
		DeviceID:  deviceID,
		AlertType: "tamper_detected",
		Message:   "Agent binary modified",
		Details:   map[string]string{"path": "/usr/bin/pm-agent"},
	})

	err := mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)

	// Verify the event was stored by checking the events table
	events, err := st.Queries().LoadStream(context.Background(), db.LoadStreamParams{
		StreamType: "device",
		StreamID:   deviceID,
	})
	require.NoError(t, err)

	found := false
	for _, e := range events {
		if e.EventType == "SecurityAlert" {
			found = true
			break
		}
	}
	assert.True(t, found, "SecurityAlert event should be stored")
}

func TestHandleExecutionResult_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, nil, slog.Default())
	mux := worker.NewMux()

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "exec-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Test Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	// Create an execution via DispatchAction event
	executionID := testutil.NewID()
	err := st.AppendEvent(context.Background(), store.Event{
		StreamType: "execution",
		StreamID:   executionID,
		EventType:  "ExecutionCreated",
		Data: map[string]any{
			"device_id":       deviceID,
			"action_id":       actionID,
			"action_type":     int(pm.ActionType_ACTION_TYPE_SHELL),
			"desired_state":   0,
			"params":          map[string]any{},
			"timeout_seconds": 300,
			"executed_at":     time.Now().Format(time.RFC3339Nano),
		},
		ActorType: "user",
		ActorID:   adminID,
	})
	require.NoError(t, err)

	// Build action result with protojson
	result := &pm.ActionResult{
		ActionId:    &pm.ActionId{Value: executionID},
		Status:      pm.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
		DurationMs:  1500,
		CompletedAt: timestamppb.Now(),
		Changed:     true,
		Compliant:   true,
		Output: &pm.CommandOutput{
			Stdout:   "hello world",
			ExitCode: 0,
		},
	}
	resultJSON, err := protojson.Marshal(result)
	require.NoError(t, err)

	task := newTask(t, taskqueue.TypeExecutionResult, taskqueue.ExecutionResultPayload{
		DeviceID:         deviceID,
		ActionResultJSON: resultJSON,
	})

	err = mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)

	// Verify execution status was updated
	exec, err := st.Queries().GetExecutionByID(context.Background(), executionID)
	require.NoError(t, err)
	assert.Equal(t, "success", exec.Status)
}

// TestHandleExecutionResult_RejectsCrossDeviceSpoof pins the fix for
// cross-device result spoofing: an execution ID is non-secret, so a compromised
// agent must not be able to write a forged result onto ANOTHER device's
// execution by supplying its ID. The reporting device must own the execution.
func TestHandleExecutionResult_RejectsCrossDeviceSpoof(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, nil, slog.Default())
	mux := worker.NewMux()

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	victimDevice := testutil.CreateTestDevice(t, st, "victim-host")
	attackerDevice := testutil.CreateTestDevice(t, st, "attacker-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Test Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	// Execution owned by the VICTIM device.
	executionID := testutil.NewID()
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "execution",
		StreamID:   executionID,
		EventType:  "ExecutionCreated",
		Data: map[string]any{
			"device_id":       victimDevice,
			"action_id":       actionID,
			"action_type":     int(pm.ActionType_ACTION_TYPE_SHELL),
			"desired_state":   0,
			"params":          map[string]any{},
			"timeout_seconds": 300,
			"executed_at":     time.Now().Format(time.RFC3339Nano),
		},
		ActorType: "user",
		ActorID:   adminID,
	}))

	// The ATTACKER device reports a forged result for the victim's execution.
	result := &pm.ActionResult{
		ActionId:    &pm.ActionId{Value: executionID},
		Status:      pm.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
		CompletedAt: timestamppb.Now(),
		Output:      &pm.CommandOutput{Stdout: "FORGED", ExitCode: 0},
	}
	resultJSON, err := protojson.Marshal(result)
	require.NoError(t, err)
	task := newTask(t, taskqueue.TypeExecutionResult, taskqueue.ExecutionResultPayload{
		DeviceID:         attackerDevice,
		ActionResultJSON: resultJSON,
	})

	err = mux.ProcessTask(context.Background(), task)
	require.Error(t, err, "a device must not complete another device's execution")

	// The victim's execution must NOT have been completed by the forged result.
	exec, err := st.Queries().GetExecutionByID(context.Background(), executionID)
	require.NoError(t, err)
	assert.NotEqual(t, "success", exec.Status, "forged result must not update the victim's execution")
}

// TestHandleOSQueryResult_RejectsCrossDeviceSpoof pins that the device_id WHERE
// clause prevents a compromised agent from completing another device's pending
// osquery result by supplying its (non-secret) query_id.
func TestHandleOSQueryResult_RejectsCrossDeviceSpoof(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, nil, slog.Default())
	mux := worker.NewMux()

	victimDevice := testutil.CreateTestDevice(t, st, "victim-osq")
	attackerDevice := testutil.CreateTestDevice(t, st, "attacker-osq")
	queryID := testutil.NewID()
	require.NoError(t, st.Queries().CreateOSQueryResult(context.Background(), db.CreateOSQueryResultParams{
		QueryID:   queryID,
		DeviceID:  victimDevice,
		TableName: "processes",
	}))

	// The attacker device reports a forged result for the victim's query.
	task := newTask(t, taskqueue.TypeOSQueryResult, taskqueue.OSQueryResultPayload{
		DeviceID: attackerDevice,
		QueryID:  queryID,
		Success:  true,
		RowsJSON: []byte(`[{"forged":"1"}]`),
	})
	// Dropped (0 rows), not a retryable error.
	require.NoError(t, mux.ProcessTask(context.Background(), task))

	// The victim's query result must remain NOT completed.
	res, err := st.Queries().GetOSQueryResult(context.Background(), queryID)
	require.NoError(t, err)
	assert.False(t, res.Completed, "forged osquery result for another device must be dropped")
}

func TestHandleExecutionResult_Failed(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, nil, slog.Default())
	mux := worker.NewMux()

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "exec-fail-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Fail Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	executionID := testutil.NewID()
	err := st.AppendEvent(context.Background(), store.Event{
		StreamType: "execution",
		StreamID:   executionID,
		EventType:  "ExecutionCreated",
		Data: map[string]any{
			"device_id":       deviceID,
			"action_id":       actionID,
			"action_type":     int(pm.ActionType_ACTION_TYPE_SHELL),
			"desired_state":   0,
			"params":          map[string]any{},
			"timeout_seconds": 300,
			"executed_at":     time.Now().Format(time.RFC3339Nano),
		},
		ActorType: "user",
		ActorID:   adminID,
	})
	require.NoError(t, err)

	result := &pm.ActionResult{
		ActionId:    &pm.ActionId{Value: executionID},
		Status:      pm.ExecutionStatus_EXECUTION_STATUS_FAILED,
		Error:       "command exited with code 1",
		DurationMs:  500,
		CompletedAt: timestamppb.Now(),
		Output: &pm.CommandOutput{
			Stderr:   "error: not found",
			ExitCode: 1,
		},
	}
	resultJSON, err := protojson.Marshal(result)
	require.NoError(t, err)

	task := newTask(t, taskqueue.TypeExecutionResult, taskqueue.ExecutionResultPayload{
		DeviceID:         deviceID,
		ActionResultJSON: resultJSON,
	})

	err = mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)

	exec, err := st.Queries().GetExecutionByID(context.Background(), executionID)
	require.NoError(t, err)
	assert.Equal(t, "failed", exec.Status)
}

func TestHandleExecutionResult_CreatesExecutionIfNotExists(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, nil, slog.Default())
	mux := worker.NewMux()

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "offline-exec-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Offline Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	// Use the actionID as the result ID (not an existing execution ID).
	// The handler should create a new execution.
	result := &pm.ActionResult{
		ActionId:    &pm.ActionId{Value: actionID},
		Status:      pm.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
		DurationMs:  200,
		CompletedAt: timestamppb.Now(),
	}
	resultJSON, err := protojson.Marshal(result)
	require.NoError(t, err)

	task := newTask(t, taskqueue.TypeExecutionResult, taskqueue.ExecutionResultPayload{
		DeviceID:         deviceID,
		ActionResultJSON: resultJSON,
	})

	err = mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)
}

func TestHandleExecutionOutputChunk(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, nil, slog.Default())
	mux := worker.NewMux()

	deviceID := testutil.CreateTestDevice(t, st, "chunk-host")
	executionID := testutil.NewID()

	// Create the execution first
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	err := st.AppendEvent(context.Background(), store.Event{
		StreamType: "execution",
		StreamID:   executionID,
		EventType:  "ExecutionCreated",
		Data: map[string]any{
			"device_id":       deviceID,
			"action_id":       testutil.CreateTestAction(t, st, adminID, "Chunk Test", int(pm.ActionType_ACTION_TYPE_SHELL)),
			"action_type":     int(pm.ActionType_ACTION_TYPE_SHELL),
			"desired_state":   0,
			"params":          map[string]any{},
			"timeout_seconds": 300,
			"executed_at":     time.Now().Format(time.RFC3339Nano),
		},
		ActorType: "user",
		ActorID:   adminID,
	})
	require.NoError(t, err)

	task := newTask(t, taskqueue.TypeExecutionOutputChunk, taskqueue.ExecutionOutputChunkPayload{
		DeviceID:    deviceID,
		ExecutionID: executionID,
		Stream:      "stdout",
		Data:        "line 1 of output\n",
		Sequence:    1,
	})

	err = mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)
}

func TestHandleRevokeLuksDeviceKeyResult_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, nil, slog.Default())
	mux := worker.NewMux()

	deviceID := testutil.CreateTestDevice(t, st, "luks-host")
	actionID := testutil.NewID()

	task := newTask(t, taskqueue.TypeRevokeLuksDeviceKeyResult, taskqueue.RevokeLuksDeviceKeyResultPayload{
		DeviceID: deviceID,
		ActionID: actionID,
		Success:  true,
	})

	err := mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)
}

func TestHandleRevokeLuksDeviceKeyResult_Failure(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, nil, slog.Default())
	mux := worker.NewMux()

	deviceID := testutil.CreateTestDevice(t, st, "luks-fail-host")
	actionID := testutil.NewID()

	task := newTask(t, taskqueue.TypeRevokeLuksDeviceKeyResult, taskqueue.RevokeLuksDeviceKeyResultPayload{
		DeviceID: deviceID,
		ActionID: actionID,
		Success:  false,
		Error:    "device busy",
	})

	err := mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)
}

func TestHandleDeviceHello(t *testing.T) {
	st := testutil.SetupPostgres(t)
	// handleDeviceHello calls dispatchPendingActions which needs aqClient.
	// Passing nil is safe here because there are no pending executions to dispatch.
	worker := control.NewInboxWorker(st, nil, nil, nil, slog.Default())
	mux := worker.NewMux()

	deviceID := testutil.CreateTestDevice(t, st, "hello-host")

	task := newTask(t, taskqueue.TypeDeviceHello, taskqueue.DeviceHelloPayload{
		DeviceID:     deviceID,
		Hostname:     "hello-host-updated",
		AgentVersion: "3.0.0",
	})

	err := mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)

	// Verify the heartbeat event was recorded (updates last_seen)
	device, err := st.Queries().GetDeviceByID(context.Background(), db.GetDeviceByIDParams{ID: deviceID})
	require.NoError(t, err)
	assert.NotNil(t, device.LastSeenAt)
}

func TestHandleDeviceHello_DeletedDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, nil, slog.Default())
	mux := worker.NewMux()

	deviceID := testutil.CreateTestDevice(t, st, "hello-deleted-host")

	// Delete the device
	err := st.AppendEvent(context.Background(), store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "DeviceDeleted",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	})
	require.NoError(t, err)

	task := newTask(t, taskqueue.TypeDeviceHello, taskqueue.DeviceHelloPayload{
		DeviceID:     deviceID,
		Hostname:     "hello-deleted-host",
		AgentVersion: "1.0.0",
	})

	// Should succeed silently (skip deleted device)
	err = mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)
}

// TestDispatchPendingActions_ReSignsWithExecutionID verifies that when
// dispatchPendingActions dispatches a pending execution, it re-signs
// the action payload with the execution ID (not the original action ID).
// This is critical because the gateway sets Action.Id = executionID,
// so the agent verifies the signature against the execution ID.
func TestDispatchPendingActions_ReSignsWithExecutionID(t *testing.T) {
	st := testutil.SetupPostgres(t)
	mr := miniredis.RunT(t)
	aqClient := taskqueue.NewClient(mr.Addr(), "", 0)
	defer aqClient.Close()

	signer := &fakeSigner{}
	worker := control.NewInboxWorker(st, aqClient, signer, nil, slog.Default())
	mux := worker.NewMux()

	ctx := context.Background()

	// Setup: create user, device, action, and a pending execution
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "resign-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Resign Test", int(pm.ActionType_ACTION_TYPE_USER))

	// Sign the action with the action ID (as the real system does)
	err := st.Queries().UpdateActionSignature(ctx, db.UpdateActionSignatureParams{
		ID:              actionID,
		Signature:       []byte("original-sig-for-action"),
		ParamsCanonical: []byte(`{"username":"test"}`),
	})
	require.NoError(t, err)

	// Create a pending execution for this device+action
	executionID := testutil.NewID()
	err = st.AppendEvent(ctx, store.Event{
		StreamType: "execution",
		StreamID:   executionID,
		EventType:  "ExecutionCreated",
		Data: map[string]any{
			"device_id":       deviceID,
			"action_id":       actionID,
			"action_type":     int(pm.ActionType_ACTION_TYPE_USER),
			"desired_state":   0,
			"params":          map[string]any{"username": "test"},
			"timeout_seconds": 300,
			"executed_at":     time.Now().Format(time.RFC3339Nano),
		},
		ActorType: "user",
		ActorID:   adminID,
	})
	require.NoError(t, err)

	// Verify execution is pending
	exec, err := st.Queries().GetExecutionByID(ctx, executionID)
	require.NoError(t, err)
	assert.Equal(t, "pending", exec.Status)

	// Trigger device hello — this calls dispatchPendingActions internally
	task := newTask(t, taskqueue.TypeDeviceHello, taskqueue.DeviceHelloPayload{
		DeviceID:     deviceID,
		Hostname:     "resign-host",
		AgentVersion: "1.0.0",
	})
	err = mux.ProcessTask(ctx, task)
	require.NoError(t, err)

	// Verify the signer was called with the EXECUTION ID, not the action ID,
	// and with the correct canonical params and action type.
	calls := signer.getCalls()
	require.Len(t, calls, 1, "signer should be called exactly once for the pending execution")
	assert.Equal(t, executionID, calls[0].ActionID,
		"signer must be called with the execution ID (not action ID %s)", actionID)
	assert.Equal(t, int32(pm.ActionType_ACTION_TYPE_USER), calls[0].ActionType)
	assert.JSONEq(t, `{"username":"test"}`, string(calls[0].ParamsJSON),
		"signer must receive the canonical params from the action")
}

// createPendingExecutionAt emits an ExecutionCreated event whose created_at is
// backdated to `at` (the projection takes created_at from executed_at), so
// time-based expiry can be tested deterministically. Returns the execution ID.
func createPendingExecutionAt(t *testing.T, st *store.Store, deviceID, actionID string, at time.Time) string {
	t.Helper()
	id := testutil.NewID()
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "execution",
		StreamID:   id,
		EventType:  "ExecutionCreated",
		Data: map[string]any{
			"device_id":       deviceID,
			"action_id":       actionID,
			"action_type":     int(pm.ActionType_ACTION_TYPE_SHELL),
			"desired_state":   0,
			"params":          map[string]any{},
			"timeout_seconds": 300,
			"executed_at":     at.Format(time.RFC3339Nano),
		},
		ActorType: "user",
		ActorID:   "test",
	}))
	return id
}

// TestListStaleExecutions_ExpiresStalePending pins the audit fix: a 'pending'
// execution older than the 24h max-age is now surfaced by ListStale (so the
// expiry sweep times it out), while a fresh pending one is left alone. Without
// this a months-offline device runs its whole stale backlog on reconnect.
func TestListStaleExecutions_ExpiresStalePending(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "stale-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Stale Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	stale := createPendingExecutionAt(t, st, deviceID, actionID, time.Now().Add(-25*time.Hour))
	fresh := createPendingExecutionAt(t, st, deviceID, actionID, time.Now())

	staleRows, err := st.Repos().Execution.ListStale(context.Background())
	require.NoError(t, err)
	ids := map[string]bool{}
	for _, r := range staleRows {
		ids[r.ID] = true
	}
	assert.True(t, ids[stale], "a pending execution older than 24h must be timed out")
	assert.False(t, ids[fresh], "a fresh pending execution must NOT be timed out")
}

// TestListPendingForDevice_SkipsStalePending pins that dispatchPendingActions
// (via ListPendingForDevice) does NOT re-dispatch a stale pending execution on
// reconnect — only fresh ones — so a long-offline device can't run stale,
// possibly destructive actions when it comes back.
func TestListPendingForDevice_SkipsStalePending(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "reconnect-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Backlog Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	stale := createPendingExecutionAt(t, st, deviceID, actionID, time.Now().Add(-25*time.Hour))
	fresh := createPendingExecutionAt(t, st, deviceID, actionID, time.Now())

	pending, err := st.Repos().Execution.ListPendingForDevice(context.Background(), deviceID)
	require.NoError(t, err)
	ids := map[string]bool{}
	for _, e := range pending {
		ids[e.ID] = true
	}
	assert.False(t, ids[stale], "a stale (>24h) pending execution must not be re-dispatched on reconnect")
	assert.True(t, ids[fresh], "a fresh pending execution must still be dispatched")
}
