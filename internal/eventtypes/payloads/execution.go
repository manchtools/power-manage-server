package payloads

import "encoding/json"

// CommandOutput is the wire shape for the nested output / detection_output
// JSONB blobs that ride along on terminal execution events.
// Mirrors the legacy commandOutputToMap helper.
type CommandOutput struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int32  `json:"exit_code"`
}

// ExecutionCreated is the wire shape for ExecutionCreated emitted by
// the gateway inbox worker when a derived execution from an offline
// agent result needs a parent row. The projector requires DeviceID
// and ActionType; the rest fall back to PL/pgSQL-equivalent defaults.
type ExecutionCreated struct {
	DeviceID       string          `json:"device_id"`
	ActionID       *string         `json:"action_id,omitempty"`
	DefinitionID   *string         `json:"definition_id,omitempty"`
	ActionType     *int32          `json:"action_type,omitempty"`
	DesiredState   *int32          `json:"desired_state,omitempty"`
	Params         json.RawMessage `json:"params,omitempty"`
	TimeoutSeconds *int32          `json:"timeout_seconds,omitempty"`
	ExecutedAt     *string         `json:"executed_at,omitempty"`
}

// ExecutionScheduled is the wire shape for ExecutionScheduled.
// scheduled_for is required (the only emitter populates it
// unconditionally — a missing key is an emitter bug).
type ExecutionScheduled struct {
	DeviceID       string          `json:"device_id"`
	ActionID       *string         `json:"action_id,omitempty"`
	DefinitionID   *string         `json:"definition_id,omitempty"`
	ActionType     *int32          `json:"action_type,omitempty"`
	DesiredState   *int32          `json:"desired_state,omitempty"`
	Params         json.RawMessage `json:"params,omitempty"`
	TimeoutSeconds *int32          `json:"timeout_seconds,omitempty"`
	ScheduledFor   string          `json:"scheduled_for"`
}

// ExecutionTerminal is the wire shape shared by ExecutionCompleted and
// ExecutionFailed. Output and DetectionOutput ride as JSONB blobs so
// the projector can pass the bytes straight to the JSONB column without
// a marshal round-trip; the emit-side helper RawCommandOutput converts
// a typed CommandOutput value into the json.RawMessage form. Error is
// populated only on the Failed variant.
type ExecutionTerminal struct {
	CompletedAt     *string         `json:"completed_at,omitempty"`
	Error           *string         `json:"error,omitempty"`
	Output          json.RawMessage `json:"output,omitempty"`
	DurationMs      *int64          `json:"duration_ms,omitempty"`
	Changed         *bool           `json:"changed,omitempty"`
	Compliant       *bool           `json:"compliant,omitempty"`
	DetectionOutput json.RawMessage `json:"detection_output,omitempty"`
}

// ExecutionTimedOut is the wire shape for ExecutionTimedOut. Subset of
// the terminal shape — no changed / compliant / detection_output.
type ExecutionTimedOut struct {
	CompletedAt *string         `json:"completed_at,omitempty"`
	Error       *string         `json:"error,omitempty"`
	Output      json.RawMessage `json:"output,omitempty"`
	DurationMs  *int64          `json:"duration_ms,omitempty"`
}

// RawCommandOutput marshals a CommandOutput into the json.RawMessage
// form used by the terminal-event payloads. Returns nil when the input
// is nil so the omitempty tag fires and the field is dropped from the
// wire payload (matches the legacy commandOutputToMap helper that
// returned nil for a nil proto).
func RawCommandOutput(o *CommandOutput) json.RawMessage {
	if o == nil {
		return nil
	}
	b, err := json.Marshal(o)
	if err != nil {
		// CommandOutput has only string and int32 fields; encoding
		// can't fail. The error path exists only to satisfy
		// json.Marshal's signature — surfacing it would force every
		// emit site to handle an impossible error.
		return nil
	}
	return b
}

// ExecutionReason is the wire shape shared by ExecutionSkipped and
// ExecutionCancelled. The reason rides on the wire as `reason` and is
// projected into the error column.
type ExecutionReason struct {
	Reason *string `json:"reason,omitempty"`
}

// ExecutionDispatched is the wire shape for ExecutionDispatched. The
// projector flips the execution row's status to "dispatched" using
// device_id to denormalise the originating device on the projection.
type ExecutionDispatched struct {
	DeviceID string `json:"device_id"`
}

// ExecutionFailedReason is the wire shape for the inbox-worker emit
// path that marks an execution failed because the action was deleted
// before the device came back online (orphaned execution case). Same
// JSON keys as the corresponding existing emit but in a typed shape.
type ExecutionFailedReason struct {
	Error       string `json:"error"`
	DurationMs  int64  `json:"duration_ms"`
	CompletedAt string `json:"completed_at"`
}

// ExecutionFailedCompensating is the wire shape for the
// dispatch-failure compensating ExecutionFailed event the action
// handler appends when the Asynq enqueue fails. completed_at is
// intentionally absent (pointer + omitempty) so the projector falls
// back to event.occurred_at.
type ExecutionFailedCompensating struct {
	Error       string  `json:"error"`
	CompletedAt *string `json:"completed_at,omitempty"`
}

// OutputChunk is the wire shape for the per-stream output chunks the
// agent pushes back through the gateway → control inbox. Fields mirror
// the historical map[string]any{} shape; the projector appends them
// to the per-execution output_chunks projection.
type OutputChunk struct {
	Stream   string `json:"stream"`
	Data     string `json:"data"`
	Sequence int64  `json:"sequence"`
}

// SecurityAlert is the wire shape for the SecurityAlert event the
// inbox worker emits when an agent reports a security_alert message.
// Details is a free-form string map per the protobuf definition.
type SecurityAlert struct {
	AlertType string            `json:"alert_type"`
	Message   string            `json:"message"`
	Details   map[string]string `json:"details,omitempty"`
}
