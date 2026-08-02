// Package execution owns direct ingestion of agent execution results and
// streamed output. It has no queue or projector path.
package execution

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/server/internal/delivery"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

const maxOutputChunkBytes = 64 * 1024

var (
	ErrInvalidInput      = errors.New("invalid execution result")
	ErrWrongDevice       = errors.New("execution belongs to another device")
	ErrWrongDelivery     = errors.New("execution belongs to another delivery")
	ErrWrongAction       = errors.New("execution belongs to another action")
	ErrInvalidTransition = errors.New("invalid execution transition")
	ErrConflictingReplay = errors.New("execution result conflicts with stored result")
	errNoChange          = errors.New("execution result made no change")
)

// Config supplies the authoritative store and deterministic clock.
type Config struct {
	Store *store.Store
	Now   func() time.Time
}

// Service commits device-reported execution state directly to SQLite.
type Service struct {
	store     *store.Store
	now       func() time.Time
	validator interface {
		Struct(any) error
	}
}

// New constructs the execution-result service.
func New(cfg Config) *Service {
	if cfg.Store == nil {
		panic("execution: store is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{store: cfg.Store, now: cfg.Now, validator: sdkvalidate.NewValidator()}
}

// ApplyActionResult advances one authored occurrence. Replaying the same
// terminal result is a successful no-op; a different result is rejected.
func (s *Service) ApplyActionResult(ctx context.Context, deviceID string, result *pmv1.ActionResult) error {
	if ctx == nil || !validID(deviceID) || result == nil || result.ActionId == nil ||
		!validID(result.ActionId.Value) || !validID(result.DeliveryId) || !validID(result.OccurrenceId) {
		return ErrInvalidInput
	}
	if err := s.validator.Struct(result); err != nil || len(result.Metadata) != 0 {
		return ErrInvalidInput
	}
	status, terminal := resultStatus(result.Status)
	if status == "" {
		return ErrInvalidInput
	}
	if !terminal && hasTerminalData(result) {
		return ErrInvalidInput
	}
	completedAt, err := resultTime(result.CompletedAt, s.now)
	if err != nil {
		return ErrInvalidInput
	}
	output, err := marshalOutput(result.Output)
	if err != nil {
		return fmt.Errorf("marshal execution output: %w", err)
	}
	detectionOutput, err := marshalOutput(result.DetectionOutput)
	if err != nil {
		return fmt.Errorf("marshal detection output: %w", err)
	}

	row, err := s.store.GetExecution(ctx, result.OccurrenceId)
	if err != nil {
		return err
	}
	if row.DeviceID != deviceID {
		return ErrWrongDevice
	}
	if row.DeliveryID != result.DeliveryId {
		return ErrWrongDelivery
	}
	deliveryRow, err := s.store.GetDelivery(ctx, result.DeliveryId)
	if err != nil {
		return err
	}
	if deliveryRow.DeviceID != deviceID {
		return ErrWrongDevice
	}
	manifestActionID, err := occurrenceActionID(deliveryRow.Manifest, result.OccurrenceId)
	if err != nil {
		return fmt.Errorf("read delivery manifest: %w", err)
	}
	if manifestActionID != result.ActionId.Value || (row.ActionID != nil && *row.ActionID != result.ActionId.Value) {
		return ErrWrongAction
	}
	if deliveryRow.State != delivery.StateAckedReceipt {
		if terminal && sameTerminalResult(row, result, status, completedAt, output, detectionOutput) {
			return nil
		}
		return ErrInvalidTransition
	}
	if terminal && isTerminal(row.Status) {
		if sameTerminalResult(row, result, status, completedAt, output, detectionOutput) {
			return nil
		}
		return ErrConflictingReplay
	}
	if !terminal && row.Status == "running" {
		return nil
	}

	op := agentOperation(deviceID, "execution.result")
	_, err = s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if !terminal {
			n, err := tx.MarkExecutionRunning(ctx, db.MarkExecutionRunningParams{
				StartedAt: &completedAt, ID: row.ID, DeliveryID: row.DeliveryID, DeviceID: deviceID,
			})
			if err != nil {
				return fmt.Errorf("mark execution running: %w", err)
			}
			if n != 1 {
				return errNoChange
			}
			rec.Effect(executionEffect(row.ID, "START", "status", "started_at"))
			return nil
		}
		errorText := result.Error
		var errorValue *string
		if errorText != "" {
			errorValue = &errorText
		}
		duration := result.DurationMs
		n, err := tx.CompleteExecutionFromAgent(ctx, db.CompleteExecutionFromAgentParams{
			Status: status, Error: errorValue, Output: output, DetectionOutput: detectionOutput,
			Changed: result.Changed, Compliant: result.Compliant,
			CompletedAt: &completedAt, DurationMs: &duration,
			ID: row.ID, DeliveryID: row.DeliveryID, DeviceID: deviceID,
		})
		if err != nil {
			return fmt.Errorf("complete execution: %w", err)
		}
		if n != 1 {
			return errNoChange
		}
		rec.Effect(executionEffect(row.ID, "RESULT",
			"status", "error", "output", "detection_output", "changed", "compliant", "completed_at", "duration_ms"))
		return nil
	})
	if err == nil {
		return nil
	}
	if !errors.Is(err, errNoChange) {
		return err
	}
	current, readErr := s.store.GetExecution(ctx, row.ID)
	if readErr != nil {
		return readErr
	}
	if !terminal && current.Status == "running" {
		return nil
	}
	if terminal && sameTerminalResult(current, result, status, completedAt, output, detectionOutput) {
		return nil
	}
	return ErrConflictingReplay
}

// AppendOutputChunk stores one bounded stream position. Duplicate frames are
// absorbed by the primary key and do not create duplicate audit evidence.
func (s *Service) AppendOutputChunk(ctx context.Context, deviceID string, chunk *pmv1.OutputChunk) error {
	if ctx == nil || !validID(deviceID) || chunk == nil || !validID(chunk.ExecutionId) ||
		chunk.Sequence < 0 || len(chunk.Data) == 0 || len(chunk.Data) > maxOutputChunkBytes {
		return ErrInvalidInput
	}
	stream := ""
	switch chunk.Stream {
	case pmv1.OutputStreamType_OUTPUT_STREAM_TYPE_STDOUT:
		stream = "stdout"
	case pmv1.OutputStreamType_OUTPUT_STREAM_TYPE_STDERR:
		stream = "stderr"
	default:
		return ErrInvalidInput
	}
	row, err := s.store.GetExecution(ctx, chunk.ExecutionId)
	if err != nil {
		return err
	}
	if row.DeviceID != deviceID {
		return ErrWrongDevice
	}
	deliveryRow, err := s.store.GetDelivery(ctx, row.DeliveryID)
	if err != nil {
		return err
	}
	if deliveryRow.State != delivery.StateAckedReceipt {
		return ErrInvalidTransition
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	_, err = s.store.WithAudit(ctx, agentOperation(deviceID, "execution.output"), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		params := db.InsertExecutionOutputChunkParams{
			ExecutionID: row.ID, Stream: stream, Sequence: int32(chunk.Sequence),
			Data: append([]byte(nil), chunk.Data...), ReceivedAt: now,
		}
		if _, err := tx.InsertExecutionOutputChunk(ctx, params); errors.Is(err, sql.ErrNoRows) {
			stored, readErr := tx.GetExecutionOutputChunk(ctx, db.GetExecutionOutputChunkParams{
				ExecutionID: row.ID, Stream: stream, Sequence: int32(chunk.Sequence),
			})
			if readErr != nil {
				return fmt.Errorf("read replayed execution output chunk: %w", readErr)
			}
			if !bytes.Equal(stored.Data, chunk.Data) {
				return ErrConflictingReplay
			}
			return errNoChange
		} else if err != nil {
			return fmt.Errorf("insert execution output chunk: %w", err)
		}
		rec.Effect(executionEffect(row.ID, "APPEND", "output"))
		return nil
	})
	if errors.Is(err, errNoChange) {
		return nil
	}
	return err
}

func validID(id string) bool {
	_, err := ulid.ParseStrict(id)
	return err == nil
}

func resultStatus(status pmv1.ExecutionStatus) (string, bool) {
	switch status {
	case pmv1.ExecutionStatus_EXECUTION_STATUS_RUNNING:
		return "running", false
	case pmv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS:
		return "success", true
	case pmv1.ExecutionStatus_EXECUTION_STATUS_FAILED:
		return "failed", true
	case pmv1.ExecutionStatus_EXECUTION_STATUS_SKIPPED:
		return "skipped", true
	case pmv1.ExecutionStatus_EXECUTION_STATUS_TIMEOUT:
		return "timeout", true
	case pmv1.ExecutionStatus_EXECUTION_STATUS_NOT_APPLICABLE:
		return "not_applicable", true
	case pmv1.ExecutionStatus_EXECUTION_STATUS_INDETERMINATE:
		return "indeterminate", true
	default:
		return "", false
	}
}

func hasTerminalData(result *pmv1.ActionResult) bool {
	return result.CompletedAt != nil || result.DurationMs != 0 || result.Error != "" ||
		result.Output != nil || result.DetectionOutput != nil || result.Changed || result.Compliant
}

func resultTime(value *timestamppb.Timestamp, now func() time.Time) (time.Time, error) {
	if value == nil {
		return now().UTC().Truncate(time.Microsecond), nil
	}
	if err := value.CheckValid(); err != nil {
		return time.Time{}, err
	}
	return value.AsTime().UTC().Truncate(time.Microsecond), nil
}

func marshalOutput(output *pmv1.CommandOutput) ([]byte, error) {
	if output == nil {
		return nil, nil
	}
	return protojson.Marshal(output)
}

func occurrenceActionID(raw []byte, occurrenceID string) (string, error) {
	manifest := &pmv1.Manifest{}
	if err := protojson.Unmarshal(raw, manifest); err != nil {
		return "", err
	}
	for _, occurrence := range manifest.Occurrences {
		if occurrence.GetOccurrenceId() == occurrenceID {
			id := occurrence.GetAction().GetId().GetValue()
			if !validID(id) {
				return "", ErrInvalidInput
			}
			return id, nil
		}
	}
	return "", ErrWrongAction
}

func isTerminal(status string) bool {
	switch status {
	case "success", "failed", "skipped", "timeout", "cancelled", "not_applicable", "indeterminate":
		return true
	default:
		return false
	}
}

func sameTerminalResult(row store.ExecutionView, result *pmv1.ActionResult, status string, completedAt time.Time, output, detectionOutput []byte) bool {
	if row.Status != status || row.Changed != result.Changed || row.Compliant != result.Compliant ||
		row.CompletedAt == nil || !row.CompletedAt.Equal(completedAt) || row.DurationMs == nil || *row.DurationMs != result.DurationMs {
		return false
	}
	storedError := ""
	if row.Error != nil {
		storedError = *row.Error
	}
	return storedError == result.Error && equalOutput(row.Output, output) && equalOutput(row.DetectionOutput, detectionOutput)
}

func equalOutput(stored, received []byte) bool {
	if len(stored) == 0 || len(received) == 0 {
		return len(stored) == len(received)
	}
	left, right := &pmv1.CommandOutput{}, &pmv1.CommandOutput{}
	if protojson.Unmarshal(stored, left) != nil || protojson.Unmarshal(received, right) != nil {
		return bytes.Equal(stored, received)
	}
	return proto.Equal(left, right)
}

func executionEffect(id, action string, fields ...string) store.AuditEffect {
	return store.AuditEffect{
		ResourceType: "execution", ResourceID: id, Action: action,
		Outcome: store.EffectApplied, ChangedFields: fields,
	}
}

func agentOperation(deviceID, descriptor string) store.AuditOperation {
	return store.AuditOperation{
		Class: store.ClassMutation, ActorType: "agent", ActorID: deviceID, Origin: "agent_stream",
		RequestDescriptor: descriptor, AuthorizationOutcome: store.AuthorizationAllowed,
		AuthorizationDetail: "device_mtls", Result: store.ResultSuccess, ResultCode: "OK",
	}
}
