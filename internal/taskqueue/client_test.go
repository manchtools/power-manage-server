package taskqueue

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_EnqueueToDeviceSignsPayloadAndUsesDeviceQueue(t *testing.T) {
	mr := miniredis.RunT(t)
	signer, err := NewSigner(testKeyHex)
	require.NoError(t, err)

	client := NewClientWithSigner(mr.Addr(), "", 0, signer)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	payload := OSQueryDispatchPayload{QueryID: "query-1", Table: "processes", Columns: []string{"pid"}, Limit: 10}
	require.NoError(t, client.EnqueueToDevice("device-1", TypeOSQueryDispatch, payload))

	inspector := asynq.NewInspector(asynq.RedisClientOpt{Addr: mr.Addr()})
	t.Cleanup(func() { require.NoError(t, inspector.Close()) })

	tasks, err := inspector.ListPendingTasks(DeviceQueue("device-1"))
	require.NoError(t, err)
	require.Len(t, tasks, 1)
	assert.Equal(t, TypeOSQueryDispatch, tasks[0].Type)
	assert.NotEqual(t, []byte(`{"QueryID":"query-1"}`), tasks[0].Payload, "payload must be HMAC wrapped before it is stored in Valkey")

	// The stored task verifies ONLY under its actual queue + type (spec 29).
	verified, err := signer.Verify(DeviceQueue("device-1"), tasks[0].Type, tasks[0].Payload)
	require.NoError(t, err)
	_, wrongQueueErr := signer.Verify(ControlInboxQueue, tasks[0].Type, tasks[0].Payload)
	require.Error(t, wrongQueueErr, "a device task must not verify under the control-inbox queue/direction")
	var got OSQueryDispatchPayload
	require.NoError(t, json.Unmarshal(verified, &got))
	assert.Equal(t, payload.QueryID, got.QueryID)
	assert.Equal(t, payload.Table, got.Table)
	assert.Equal(t, payload.Columns, got.Columns)
	assert.Equal(t, payload.Limit, got.Limit)
}

// A caller-supplied asynq.Queue option must NOT override the signed device
// queue — the task must land on exactly the queue its HMAC is bound to, or the
// consumer would (correctly) reject it as a queue mismatch.
func TestClient_EnqueueToDeviceIgnoresConflictingQueueOption(t *testing.T) {
	mr := miniredis.RunT(t)
	signer, err := NewSigner(testKeyHex)
	require.NoError(t, err)
	client := NewClientWithSigner(mr.Addr(), "", 0, signer)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	require.NoError(t, client.EnqueueToDevice("device-1", TypeOSQueryDispatch,
		OSQueryDispatchPayload{QueryID: "q"}, asynq.Queue("attacker-chosen")))

	inspector := asynq.NewInspector(asynq.RedisClientOpt{Addr: mr.Addr()})
	t.Cleanup(func() { require.NoError(t, inspector.Close()) })

	onSigned, err := inspector.ListPendingTasks(DeviceQueue("device-1"))
	require.NoError(t, err)
	require.Len(t, onSigned, 1, "the task must be enqueued to the signed device queue")

	onOverride, err := inspector.ListPendingTasks("attacker-chosen")
	if !errors.Is(err, asynq.ErrQueueNotFound) {
		require.NoError(t, err)
	}
	assert.Empty(t, onOverride, "a caller-supplied queue option must not override the signed queue")
}

func TestClient_EnqueueToControlRoutesTerminalAuditToSerialQueue(t *testing.T) {
	mr := miniredis.RunT(t)
	signer, err := NewSigner(testKeyHex)
	require.NoError(t, err)

	client := NewClientWithSigner(mr.Addr(), "", 0, signer)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	require.NoError(t, client.EnqueueToControl(TypeTerminalAuditChunk, TerminalAuditChunkPayload{
		SessionID: "sess-1",
		DeviceID:  "device-1",
		UserID:    "user-1",
		Sequence:  1,
		Data:      []byte("whoami\n"),
	}))

	inspector := asynq.NewInspector(asynq.RedisClientOpt{Addr: mr.Addr()})
	t.Cleanup(func() { require.NoError(t, inspector.Close()) })

	mainQueueTasks, err := inspector.ListPendingTasks(ControlInboxQueue)
	if errors.Is(err, asynq.ErrQueueNotFound) {
		mainQueueTasks = nil
	} else {
		require.NoError(t, err)
	}
	assert.Empty(t, mainQueueTasks)

	auditTasks, err := inspector.ListPendingTasks(ControlTerminalAuditQueue)
	require.NoError(t, err)
	require.Len(t, auditTasks, 1)
	assert.Equal(t, TypeTerminalAuditChunk, auditTasks[0].Type)
	verified, err := signer.Verify(ControlTerminalAuditQueue, auditTasks[0].Type, auditTasks[0].Payload)
	require.NoError(t, err)
	_, wrongQueueErr := signer.Verify(ControlInboxQueue, auditTasks[0].Type, auditTasks[0].Payload)
	require.Error(t, wrongQueueErr, "a terminal-audit task must not verify under the control-inbox queue")
	var got TerminalAuditChunkPayload
	require.NoError(t, json.Unmarshal(verified, &got))
	assert.Equal(t, "sess-1", got.SessionID)
	assert.Equal(t, "device-1", got.DeviceID)
	assert.Equal(t, "user-1", got.UserID)
	assert.Equal(t, int64(1), got.Sequence)
	assert.Equal(t, []byte("whoami\n"), got.Data)
}
