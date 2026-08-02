package store_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/manchtools/power-manage/server/internal/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/delivery"
	"github.com/manchtools/power-manage/server/internal/execution"
	"github.com/manchtools/power-manage/server/internal/store"
)

type executionResultFixture struct {
	t          *testing.T
	store      *store.Store
	raw        *testdb.DB
	service    *execution.Service
	now        time.Time
	deviceID   string
	deliveryID string
	manifestID string
	execution  string
	actionID   string
}

func newExecutionResultFixture(t *testing.T, deliveryState, executionState string) *executionResultFixture {
	t.Helper()
	st, raw := setupSQLite(t)
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	f := &executionResultFixture{
		t: t, store: st, raw: raw, now: now,
		deviceID: newID(), deliveryID: newID(), manifestID: newID(),
		execution: newID(), actionID: newID(),
	}
	_, err := raw.Exec(context.Background(), `
		INSERT INTO devices (id, hostname, agent_version, agent_sealing_public_key, registered_at)
		VALUES ($1, 'device', 'v1', $2, $3)`, f.deviceID, bytes.Repeat([]byte{1}, 32), now)
	require.NoError(t, err)
	var pushedAt, ackedAt *time.Time
	if deliveryState == delivery.StatePushed || deliveryState == delivery.StateAckedReceipt {
		pushedAt = &now
	}
	if deliveryState == delivery.StateAckedReceipt {
		ackedAt = &now
	}
	manifest, err := protojson.Marshal(&pmv1.Manifest{
		ManifestId: f.manifestID,
		Occurrences: []*pmv1.ManifestOccurrence{{
			OccurrenceId: f.execution,
			Action:       &pmv1.Action{Id: &pmv1.ActionId{Value: f.actionID}, Type: pmv1.ActionType_ACTION_TYPE_REBOOT},
		}},
	})
	require.NoError(t, err)
	_, err = raw.Exec(context.Background(), `
		INSERT INTO deliveries (
			delivery_id, device_id, manifest_id, manifest, state,
			pushed_at, acked_receipt_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		f.deliveryID, f.deviceID, f.manifestID, manifest, deliveryState, pushedAt, ackedAt)
	require.NoError(t, err)
	_, err = raw.Exec(context.Background(), `
		INSERT INTO executions (
			id, delivery_id, device_id, action_type, desired_state, params,
			timeout_seconds, status, created_at, created_by_type, created_by_id
		) VALUES ($1, $2, $3, 1, 0, '{}', 300, $4, $5, 'user', $6)`,
		f.execution, f.deliveryID, f.deviceID, executionState, now, newID())
	require.NoError(t, err)
	f.service = execution.New(execution.Config{Store: st, Now: func() time.Time { return now }})
	return f
}

func (f *executionResultFixture) result(status pmv1.ExecutionStatus) *pmv1.ActionResult {
	f.t.Helper()
	return &pmv1.ActionResult{
		ActionId: &pmv1.ActionId{Value: f.actionID}, Status: status,
		DeliveryId: f.deliveryID, OccurrenceId: f.execution,
	}
}

func TestExecutionResult_CommitsTerminalStateAndAbsorbsReplay(t *testing.T) {
	f := newExecutionResultFixture(t, delivery.StateAckedReceipt, "pending")
	completed := f.now.Add(-time.Minute)
	result := f.result(pmv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS)
	result.CompletedAt = timestamppb.New(completed)
	result.DurationMs = 1234
	result.Changed = true
	result.Compliant = true
	result.Output = &pmv1.CommandOutput{ExitCode: 0, Stdout: "done"}
	result.DetectionOutput = &pmv1.CommandOutput{ExitCode: 0, Stdout: "compliant"}

	require.NoError(t, f.service.ApplyActionResult(context.Background(), f.deviceID, result))
	row, err := f.store.GetExecution(context.Background(), f.execution)
	require.NoError(t, err)
	assert.Equal(t, "success", row.Status)
	assert.True(t, row.Changed)
	assert.True(t, row.Compliant)
	require.NotNil(t, row.CompletedAt)
	assert.True(t, row.CompletedAt.Equal(completed))
	require.NotNil(t, row.DurationMs)
	assert.Equal(t, int64(1234), *row.DurationMs)
	assert.JSONEq(t, `{"stdout":"done"}`, string(row.Output))
	assert.JSONEq(t, `{"stdout":"compliant"}`, string(row.DetectionOutput))

	var before int
	require.NoError(t, f.raw.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM audit_operations WHERE request_descriptor = 'execution.result'`).Scan(&before))
	require.NoError(t, f.service.ApplyActionResult(context.Background(), f.deviceID, result))
	var after int
	require.NoError(t, f.raw.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM audit_operations WHERE request_descriptor = 'execution.result'`).Scan(&after))
	assert.Equal(t, before, after, "an identical replay is not another mutation")

	conflict := f.result(pmv1.ExecutionStatus_EXECUTION_STATUS_FAILED)
	conflict.Error = "different outcome"
	err = f.service.ApplyActionResult(context.Background(), f.deviceID, conflict)
	assert.ErrorIs(t, err, execution.ErrConflictingReplay)
}

func TestExecutionResult_RunningThenIndeterminate(t *testing.T) {
	f := newExecutionResultFixture(t, delivery.StateAckedReceipt, "pending")
	require.NoError(t, f.service.ApplyActionResult(context.Background(), f.deviceID,
		f.result(pmv1.ExecutionStatus_EXECUTION_STATUS_RUNNING)))
	row, err := f.store.GetExecution(context.Background(), f.execution)
	require.NoError(t, err)
	assert.Equal(t, "running", row.Status)

	indeterminate := f.result(pmv1.ExecutionStatus_EXECUTION_STATUS_INDETERMINATE)
	indeterminate.Error = "agent restarted after STARTED"
	require.NoError(t, f.service.ApplyActionResult(context.Background(), f.deviceID, indeterminate))
	row, err = f.store.GetExecution(context.Background(), f.execution)
	require.NoError(t, err)
	assert.Equal(t, "indeterminate", row.Status)
}

func TestExecutionResult_EnforcesReceiptAndIdentityBindings(t *testing.T) {
	f := newExecutionResultFixture(t, delivery.StatePushed, "pending")
	result := f.result(pmv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS)
	assert.ErrorIs(t, f.service.ApplyActionResult(context.Background(), f.deviceID, result), execution.ErrInvalidTransition)

	wrongDevice := newID()
	assert.ErrorIs(t, f.service.ApplyActionResult(context.Background(), wrongDevice, result), execution.ErrWrongDevice)

	f2 := newExecutionResultFixture(t, delivery.StateAckedReceipt, "pending")
	wrongAction := f2.result(pmv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS)
	wrongAction.ActionId.Value = newID()
	assert.ErrorIs(t, f2.service.ApplyActionResult(context.Background(), f2.deviceID, wrongAction), execution.ErrWrongAction)

	wrongDelivery := f2.result(pmv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS)
	wrongDelivery.DeliveryId = newID()
	assert.ErrorIs(t, f2.service.ApplyActionResult(context.Background(), f2.deviceID, wrongDelivery), execution.ErrWrongDelivery)

	invalid := f2.result(pmv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS)
	invalid.Metadata = map[string]string{"lps.rotations": "must never ride result metadata"}
	assert.ErrorIs(t, f2.service.ApplyActionResult(context.Background(), f2.deviceID, invalid), execution.ErrInvalidInput)
}

func TestExecutionOutputChunk_IsBoundedOwnedAndIdempotent(t *testing.T) {
	f := newExecutionResultFixture(t, delivery.StateAckedReceipt, "running")
	chunk := &pmv1.OutputChunk{
		ExecutionId: f.execution, Stream: pmv1.OutputStreamType_OUTPUT_STREAM_TYPE_STDOUT,
		Data: []byte("hello"), Sequence: 4,
	}
	require.NoError(t, f.service.AppendOutputChunk(context.Background(), f.deviceID, chunk))
	require.NoError(t, f.service.AppendOutputChunk(context.Background(), f.deviceID, chunk))
	conflict := proto.Clone(chunk).(*pmv1.OutputChunk)
	conflict.Data = []byte("different")
	assert.ErrorIs(t, f.service.AppendOutputChunk(context.Background(), f.deviceID, conflict), execution.ErrConflictingReplay)
	var count int
	require.NoError(t, f.raw.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM execution_output_chunks WHERE execution_id = $1`, f.execution).Scan(&count))
	assert.Equal(t, 1, count)

	err := f.service.AppendOutputChunk(context.Background(), newID(), chunk)
	assert.ErrorIs(t, err, execution.ErrWrongDevice)
	oversized := proto.Clone(chunk).(*pmv1.OutputChunk)
	oversized.Data = bytes.Repeat([]byte{'x'}, 64*1024+1)
	assert.ErrorIs(t, f.service.AppendOutputChunk(context.Background(), f.deviceID, oversized), execution.ErrInvalidInput)
}

func TestExecutionResult_RejectsMalformedAndCancelledTransitions(t *testing.T) {
	f := newExecutionResultFixture(t, delivery.StateAckedReceipt, "cancelled")
	err := f.service.ApplyActionResult(context.Background(), f.deviceID,
		f.result(pmv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS))
	assert.True(t, errors.Is(err, execution.ErrInvalidTransition) || errors.Is(err, execution.ErrConflictingReplay))

	malformed := f.result(pmv1.ExecutionStatus_EXECUTION_STATUS_RUNNING)
	malformed.Error = "running is not terminal"
	assert.ErrorIs(t, f.service.ApplyActionResult(context.Background(), f.deviceID, malformed), execution.ErrInvalidInput)
}
