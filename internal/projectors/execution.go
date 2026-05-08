package projectors

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/manchtools/power-manage/server/internal/store"
)

// defaultExecutionParams mirrors the column default on
// executions_projection (`'{}'::JSONB`) and the PL/pgSQL projector's
// `COALESCE(event.data->'params', '{}')` fallback. Stored as a byte
// slice so the listener can pass it straight to the JSONB column
// without a marshal step.
var defaultExecutionParams = []byte(`{}`)

// defaultExecutionTimeoutSeconds mirrors the PL/pgSQL projector's
// `COALESCE((event.data->>'timeout_seconds')::INTEGER, 300)` fallback.
const defaultExecutionTimeoutSeconds int32 = 300

// ExecutionCreatedPayload mirrors the fields the deleted PL/pgSQL
// project_execution_event() read out of an ExecutionCreated event.
//
// Required: device_id and action_type (an emitter that omits either
// would have hit a NOT-NULL violation in PL/pgSQL too — surfaced here
// as a decoder error so the listener log line is actionable).
//
// Defaults match the PL/pgSQL COALESCE chain:
//
//   - action_id falls back to the payload's definition_id when the
//     primary key is absent (compliance-policy-bootstrap path).
//   - desired_state defaults to 0.
//   - params defaults to `{}` JSONB.
//   - timeout_seconds defaults to 300.
//   - created_at defaults to event.occurred_at when payload omits
//     executed_at.
type ExecutionCreatedPayload struct {
	ID             string
	DeviceID       string
	ActionID       *string
	ActionType     int32
	DesiredState   int32
	Params         []byte
	TimeoutSeconds int32
	CreatedAt      time.Time
	CreatedByType  string
	CreatedByID    string
}

type executionCreatedRaw struct {
	DeviceID       string          `json:"device_id"`
	ActionID       *string         `json:"action_id,omitempty"`
	DefinitionID   *string         `json:"definition_id,omitempty"`
	ActionType     *int32          `json:"action_type,omitempty"`
	DesiredState   *int32          `json:"desired_state,omitempty"`
	Params         json.RawMessage `json:"params,omitempty"`
	TimeoutSeconds *int32          `json:"timeout_seconds,omitempty"`
	ExecutedAt     *string         `json:"executed_at,omitempty"`
}

// ExecutionCreatedFromEvent decodes ExecutionCreated. Returns
// ErrIgnoredEvent for any other (stream, event_type) so the listener
// wrapper can silently no-op.
func ExecutionCreatedFromEvent(e store.PersistedEvent) (ExecutionCreatedPayload, error) {
	if e.StreamType != "execution" || e.EventType != "ExecutionCreated" {
		return ExecutionCreatedPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return ExecutionCreatedPayload{}, fmt.Errorf("projector: empty ExecutionCreated payload")
	}
	var raw executionCreatedRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return ExecutionCreatedPayload{}, fmt.Errorf("projector: invalid ExecutionCreated payload: %w", err)
	}
	if raw.DeviceID == "" {
		return ExecutionCreatedPayload{}, fmt.Errorf("projector: ExecutionCreated requires device_id")
	}
	if raw.ActionType == nil {
		return ExecutionCreatedPayload{}, fmt.Errorf("projector: ExecutionCreated requires action_type")
	}
	createdAt, err := resolveCreatedAt(raw.ExecutedAt, e.OccurredAt)
	if err != nil {
		return ExecutionCreatedPayload{}, fmt.Errorf("projector: invalid executed_at: %w", err)
	}
	out := ExecutionCreatedPayload{
		ID:             e.StreamID,
		DeviceID:       raw.DeviceID,
		ActionID:       coalesceActionID(raw.ActionID, raw.DefinitionID),
		ActionType:     *raw.ActionType,
		Params:         defaultExecutionParams,
		TimeoutSeconds: defaultExecutionTimeoutSeconds,
		CreatedAt:      createdAt,
		CreatedByType:  e.ActorType,
		CreatedByID:    e.ActorID,
	}
	if raw.DesiredState != nil {
		out.DesiredState = *raw.DesiredState
	}
	if len(raw.Params) > 0 {
		out.Params = []byte(raw.Params)
	}
	if raw.TimeoutSeconds != nil {
		out.TimeoutSeconds = *raw.TimeoutSeconds
	}
	return out, nil
}

// ExecutionScheduledPayload mirrors ExecutionCreated's column set plus
// scheduled_for. The PL/pgSQL projector did NOT honour an executed_at
// fallback on this branch (created_at = event.occurred_at outright);
// we match that exactly.
type ExecutionScheduledPayload struct {
	ID             string
	DeviceID       string
	ActionID       *string
	ActionType     int32
	DesiredState   int32
	Params         []byte
	TimeoutSeconds int32
	ScheduledFor   time.Time
	CreatedAt      time.Time
	CreatedByType  string
	CreatedByID    string
}

type executionScheduledRaw struct {
	DeviceID       string          `json:"device_id"`
	ActionID       *string         `json:"action_id,omitempty"`
	DefinitionID   *string         `json:"definition_id,omitempty"`
	ActionType     *int32          `json:"action_type,omitempty"`
	DesiredState   *int32          `json:"desired_state,omitempty"`
	Params         json.RawMessage `json:"params,omitempty"`
	TimeoutSeconds *int32          `json:"timeout_seconds,omitempty"`
	ScheduledFor   string          `json:"scheduled_for"`
}

// ExecutionScheduledFromEvent decodes ExecutionScheduled. scheduled_for
// is REQUIRED — the PL/pgSQL projector cast it directly without a
// COALESCE, so an absent key would have produced a NULL column write
// (and the column is nullable). We require it here because the only
// emitter that builds this event populates it unconditionally
// (action_handler.go RunAt branch); a missing key is an emitter bug.
func ExecutionScheduledFromEvent(e store.PersistedEvent) (ExecutionScheduledPayload, error) {
	if e.StreamType != "execution" || e.EventType != "ExecutionScheduled" {
		return ExecutionScheduledPayload{}, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return ExecutionScheduledPayload{}, fmt.Errorf("projector: empty ExecutionScheduled payload")
	}
	var raw executionScheduledRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return ExecutionScheduledPayload{}, fmt.Errorf("projector: invalid ExecutionScheduled payload: %w", err)
	}
	if raw.DeviceID == "" {
		return ExecutionScheduledPayload{}, fmt.Errorf("projector: ExecutionScheduled requires device_id")
	}
	if raw.ActionType == nil {
		return ExecutionScheduledPayload{}, fmt.Errorf("projector: ExecutionScheduled requires action_type")
	}
	if raw.ScheduledFor == "" {
		return ExecutionScheduledPayload{}, fmt.Errorf("projector: ExecutionScheduled requires scheduled_for")
	}
	scheduledFor, err := time.Parse(time.RFC3339Nano, raw.ScheduledFor)
	if err != nil {
		return ExecutionScheduledPayload{}, fmt.Errorf("projector: invalid scheduled_for: %w", err)
	}
	out := ExecutionScheduledPayload{
		ID:             e.StreamID,
		DeviceID:       raw.DeviceID,
		ActionID:       coalesceActionID(raw.ActionID, raw.DefinitionID),
		ActionType:     *raw.ActionType,
		Params:         defaultExecutionParams,
		TimeoutSeconds: defaultExecutionTimeoutSeconds,
		ScheduledFor:   scheduledFor,
		CreatedAt:      e.OccurredAt,
		CreatedByType:  e.ActorType,
		CreatedByID:    e.ActorID,
	}
	if raw.DesiredState != nil {
		out.DesiredState = *raw.DesiredState
	}
	if len(raw.Params) > 0 {
		out.Params = []byte(raw.Params)
	}
	if raw.TimeoutSeconds != nil {
		out.TimeoutSeconds = *raw.TimeoutSeconds
	}
	return out, nil
}

// ExecutionTerminalPayload covers the shared shape of ExecutionCompleted
// and ExecutionFailed. The PL/pgSQL projector wrote the same column set
// for both; the only difference is the status literal and the presence
// of the error field on Failed (NULL on Completed). Defaults match the
// PL/pgSQL COALESCE chain: changed defaults to TRUE, compliant defaults
// to FALSE; output / duration_ms / detection_output have no defaults
// and pass through as NULL when absent.
type ExecutionTerminalPayload struct {
	ID              string
	CompletedAt     time.Time
	Error           *string
	Output          []byte
	DurationMs      *int64
	Changed         bool
	Compliant       bool
	DetectionOutput []byte
}

type executionTerminalRaw struct {
	CompletedAt     *string         `json:"completed_at,omitempty"`
	Error           *string         `json:"error,omitempty"`
	Output          json.RawMessage `json:"output,omitempty"`
	DurationMs      *int64          `json:"duration_ms,omitempty"`
	Changed         *bool           `json:"changed,omitempty"`
	Compliant       *bool           `json:"compliant,omitempty"`
	DetectionOutput json.RawMessage `json:"detection_output,omitempty"`
}

// ExecutionCompletedFromEvent decodes ExecutionCompleted.
func ExecutionCompletedFromEvent(e store.PersistedEvent) (ExecutionTerminalPayload, error) {
	if e.StreamType != "execution" || e.EventType != "ExecutionCompleted" {
		return ExecutionTerminalPayload{}, ErrIgnoredEvent
	}
	return decodeTerminal(e, "ExecutionCompleted")
}

// ExecutionFailedFromEvent decodes ExecutionFailed.
func ExecutionFailedFromEvent(e store.PersistedEvent) (ExecutionTerminalPayload, error) {
	if e.StreamType != "execution" || e.EventType != "ExecutionFailed" {
		return ExecutionTerminalPayload{}, ErrIgnoredEvent
	}
	return decodeTerminal(e, "ExecutionFailed")
}

func decodeTerminal(e store.PersistedEvent, label string) (ExecutionTerminalPayload, error) {
	out := ExecutionTerminalPayload{
		ID:          e.StreamID,
		CompletedAt: e.OccurredAt,
		// Defaults match the PL/pgSQL COALESCEs: changed=TRUE,
		// compliant=FALSE.
		Changed:   true,
		Compliant: false,
	}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw executionTerminalRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return ExecutionTerminalPayload{}, fmt.Errorf("projector: invalid %s payload: %w", label, err)
	}
	completedAt, err := resolveCreatedAt(raw.CompletedAt, e.OccurredAt)
	if err != nil {
		return ExecutionTerminalPayload{}, fmt.Errorf("projector: invalid completed_at on %s: %w", label, err)
	}
	out.CompletedAt = completedAt
	out.Error = raw.Error
	if len(raw.Output) > 0 {
		out.Output = []byte(raw.Output)
	}
	out.DurationMs = raw.DurationMs
	if raw.Changed != nil {
		out.Changed = *raw.Changed
	}
	if raw.Compliant != nil {
		out.Compliant = *raw.Compliant
	}
	if len(raw.DetectionOutput) > 0 {
		out.DetectionOutput = []byte(raw.DetectionOutput)
	}
	return out, nil
}

// ExecutionTimedOutPayload is the subset of the terminal shape the
// PL/pgSQL projector wrote on timeout — no changed / compliant /
// detection_output.
type ExecutionTimedOutPayload struct {
	ID          string
	CompletedAt time.Time
	Error       *string
	Output      []byte
	DurationMs  *int64
}

type executionTimedOutRaw struct {
	CompletedAt *string         `json:"completed_at,omitempty"`
	Error       *string         `json:"error,omitempty"`
	Output      json.RawMessage `json:"output,omitempty"`
	DurationMs  *int64          `json:"duration_ms,omitempty"`
}

// ExecutionTimedOutFromEvent decodes ExecutionTimedOut.
func ExecutionTimedOutFromEvent(e store.PersistedEvent) (ExecutionTimedOutPayload, error) {
	if e.StreamType != "execution" || e.EventType != "ExecutionTimedOut" {
		return ExecutionTimedOutPayload{}, ErrIgnoredEvent
	}
	out := ExecutionTimedOutPayload{
		ID:          e.StreamID,
		CompletedAt: e.OccurredAt,
	}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw executionTimedOutRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return ExecutionTimedOutPayload{}, fmt.Errorf("projector: invalid ExecutionTimedOut payload: %w", err)
	}
	completedAt, err := resolveCreatedAt(raw.CompletedAt, e.OccurredAt)
	if err != nil {
		return ExecutionTimedOutPayload{}, fmt.Errorf("projector: invalid completed_at on ExecutionTimedOut: %w", err)
	}
	out.CompletedAt = completedAt
	out.Error = raw.Error
	if len(raw.Output) > 0 {
		out.Output = []byte(raw.Output)
	}
	out.DurationMs = raw.DurationMs
	return out, nil
}

// ExecutionReasonPayload covers ExecutionSkipped and ExecutionCancelled.
// Both events write completed_at = event.occurred_at unconditionally
// (no payload fallback in the PL/pgSQL source) and stash the reason in
// the error column. Decoder shapes them identically.
type ExecutionReasonPayload struct {
	ID          string
	CompletedAt time.Time
	Reason      *string
}

type executionReasonRaw struct {
	Reason *string `json:"reason,omitempty"`
}

// ExecutionSkippedFromEvent decodes ExecutionSkipped.
func ExecutionSkippedFromEvent(e store.PersistedEvent) (ExecutionReasonPayload, error) {
	if e.StreamType != "execution" || e.EventType != "ExecutionSkipped" {
		return ExecutionReasonPayload{}, ErrIgnoredEvent
	}
	return decodeReason(e, "ExecutionSkipped")
}

// ExecutionCancelledFromEvent decodes ExecutionCancelled.
func ExecutionCancelledFromEvent(e store.PersistedEvent) (ExecutionReasonPayload, error) {
	if e.StreamType != "execution" || e.EventType != "ExecutionCancelled" {
		return ExecutionReasonPayload{}, ErrIgnoredEvent
	}
	return decodeReason(e, "ExecutionCancelled")
}

func decodeReason(e store.PersistedEvent, label string) (ExecutionReasonPayload, error) {
	out := ExecutionReasonPayload{
		ID:          e.StreamID,
		CompletedAt: e.OccurredAt,
	}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw executionReasonRaw
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return ExecutionReasonPayload{}, fmt.Errorf("projector: invalid %s payload: %w", label, err)
	}
	out.Reason = raw.Reason
	return out, nil
}

// ExecutionStreamRefFromEvent validates Dispatched / Started events
// that carry no payload columns — both the PL/pgSQL projector and the
// Go listener only need stream_id + occurred_at + sequence_num for
// these. Returned string is the execution id; ErrIgnoredEvent for any
// stream/type mismatch.
func ExecutionStreamRefFromEvent(e store.PersistedEvent, eventType string) (string, error) {
	if e.StreamType != "execution" || e.EventType != eventType {
		return "", ErrIgnoredEvent
	}
	return e.StreamID, nil
}

// resolveCreatedAt returns the parsed RFC 3339 timestamp from the
// payload, or the event.occurred_at fallback when the payload field is
// absent or explicitly null. Mirrors PL/pgSQL
// `COALESCE((event.data->>'X')::TIMESTAMPTZ, event.occurred_at)`.
func resolveCreatedAt(payloadValue *string, fallback time.Time) (time.Time, error) {
	if payloadValue == nil || *payloadValue == "" {
		return fallback, nil
	}
	return time.Parse(time.RFC3339Nano, *payloadValue)
}

// coalesceActionID mirrors the PL/pgSQL
// `COALESCE(event.data->>'action_id', event.data->>'definition_id')`
// fallback. action_id is the canonical key; definition_id is the
// compliance-policy bootstrap path that synthesises an action row from
// a definition. Returns nil when neither key is set so the column is
// written as NULL (matches the PL/pgSQL behaviour where both COALESCE
// arms returning NULL yields NULL).
func coalesceActionID(actionID, definitionID *string) *string {
	if actionID != nil && *actionID != "" {
		return actionID
	}
	if definitionID != nil && *definitionID != "" {
		return definitionID
	}
	return nil
}
