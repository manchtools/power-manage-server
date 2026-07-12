// Package api file action_handler.go — declares the ActionHandler
// type and its constructor; per-RPC implementations live in sibling
// files (audit F005):
//
//   - action_crud.go        — Create / Get / List / Rename /
//     UpdateDescription / UpdateParams /
//     Delete + the signature lifecycle
//     (computeActionSignature,
//     persistActionSignature,
//     rollbackUnsignedCreate)
//   - action_dispatch.go    — DispatchAction / DispatchToMultiple /
//     DispatchAssignedActions /
//     DispatchActionSet /
//     DispatchDefinition /
//     DispatchToGroup /
//     DispatchInstantAction /
//     GetExecution / ListExecutions /
//     CancelExecution + isInstantActionType
//   - action_validators.go  — validateCreateActionParams /
//     validateUpdateActionParams /
//     validateInlineAction /
//     validateShellScriptChoice /
//     validateAgentUpdateParams /
//     actionParamsMatchType
//   - action_params.go      — serializeProtoParams /
//     extractCreateActionParamsMsg /
//     extractUpdateActionParamsMsg /
//     extractActionParamsMsg
//   - action_schedule.go    — scheduleToMap / scheduleFromJSON
//
// This file owns the type, the constructor, and the read-side proto
// translators (actionToProto / executionToProto / status helpers /
// loadLiveOutput) that don't fit either the CRUD or the dispatch
// section cleanly.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/store"
)

// ActionHandler handles action (single executable) and execution RPCs.
type ActionHandler struct {
	taskQueueHolder // aqClient is nil when CONTROL_VALKEY_ADDR is unset (in-process mode without Valkey)
	searchIndexHolder
	store  *store.Store
	logger *slog.Logger
	signer ca.ActionSigner
}

// NewActionHandler creates a new action handler.
func NewActionHandler(st *store.Store, logger *slog.Logger, signer ca.ActionSigner) *ActionHandler {
	return &ActionHandler{
		store:  st,
		logger: logger,
		signer: signer,
	}
}

func (h *ActionHandler) actionToProto(a store.Action) *pm.ManagedAction {
	action := &pm.ManagedAction{
		Id:             a.ID,
		Name:           a.Name,
		Type:           pm.ActionType(a.ActionType),
		DesiredState:   pm.DesiredState(a.DesiredState),
		TimeoutSeconds: a.TimeoutSeconds,
		CreatedBy:      a.CreatedBy,
	}

	if a.Description != nil {
		action.Description = *a.Description
	}

	if a.CreatedAt != nil {
		action.CreatedAt = timestamppb.New(*a.CreatedAt)
	}

	if a.UpdatedAt != nil {
		action.UpdatedAt = timestamppb.New(*a.UpdatedAt)
	}

	if len(a.Params) > 0 {
		if err := actionparams.PopulateManagedAction(action, pm.ActionType(a.ActionType), a.Params); err != nil {
			// Read path: log and return the action without params rather than
			// failing the whole list/get response (#368).
			h.logger.Warn("action params failed to parse for API response", "action_id", a.ID, "error", err)
		}
	}

	if len(a.Schedule) > 0 {
		action.Schedule = scheduleFromJSON(a.Schedule)
	}

	return action
}

func (h *ActionHandler) executionToProto(e store.Execution) *pm.ActionExecution {
	exec := &pm.ActionExecution{
		Id:           e.ID,
		DeviceId:     e.DeviceID,
		Type:         pm.ActionType(e.ActionType),
		Status:       stringToStatus(e.Status),
		DesiredState: pm.DesiredState(e.DesiredState),
		Changed:      e.Changed,
	}

	if e.ActionID != nil {
		exec.ActionId = *e.ActionID
	}

	if e.Error != nil {
		exec.Error = *e.Error
	}

	exec.Output = decodeCommandOutput(e.Output)

	if e.DurationMs != nil {
		exec.DurationMs = *e.DurationMs
	}

	exec.CreatedBy = e.CreatedByID

	if e.CreatedAt != nil {
		exec.CreatedAt = timestamppb.New(*e.CreatedAt)
	}

	if e.DispatchedAt != nil {
		exec.DispatchedAt = timestamppb.New(*e.DispatchedAt)
	}

	if e.CompletedAt != nil {
		exec.CompletedAt = timestamppb.New(*e.CompletedAt)
	}

	if e.ScheduledFor != nil {
		exec.ScheduledFor = timestamppb.New(*e.ScheduledFor)
	}

	exec.Compliant = e.Compliant
	exec.DetectionOutput = decodeCommandOutput(e.DetectionOutput)

	return exec
}

// commandOutputUnmarshal is the protojson codec for CommandOutput JSONB blobs.
// DiscardUnknown tolerates schema additions; protojson accepts BOTH the
// camelCase names a proto-native writer emits and the snake_case names the
// legacy stdlib-json writers produced, so existing rows still decode after the
// codec switch.
var commandOutputUnmarshal = protojson.UnmarshalOptions{DiscardUnknown: true}

// decodeCommandOutput decodes a CommandOutput JSONB blob with protojson — the
// correct codec for a proto message. stdlib encoding/json works only by
// snake-case-tag luck and silently breaks on any future enum/oneof/int64 field;
// it is forbidden on proto messages by TestNoStdlibJSONOfProtoMessage. Returns
// nil for empty or malformed input: a corrupt output blob must not fail the
// whole execution / compliance read. Single source for every CommandOutput
// decode in this package (replaces two stdlib-into-proto sites and two
// anonymous-struct re-declarations).
func decodeCommandOutput(data []byte) *pm.CommandOutput {
	if len(data) == 0 {
		return nil
	}
	var out pm.CommandOutput
	if err := commandOutputUnmarshal.Unmarshal(data, &out); err != nil {
		return nil
	}
	return &out
}

func statusToString(s pm.ExecutionStatus) string {
	switch s {
	case pm.ExecutionStatus_EXECUTION_STATUS_PENDING:
		return "pending"
	case pm.ExecutionStatus_EXECUTION_STATUS_RUNNING:
		return "running"
	case pm.ExecutionStatus_EXECUTION_STATUS_SUCCESS:
		return "success"
	case pm.ExecutionStatus_EXECUTION_STATUS_FAILED:
		return "failed"
	case pm.ExecutionStatus_EXECUTION_STATUS_TIMEOUT:
		return "timeout"
	case pm.ExecutionStatus_EXECUTION_STATUS_SCHEDULED:
		return "scheduled"
	case pm.ExecutionStatus_EXECUTION_STATUS_CANCELLED:
		return "cancelled"
	case pm.ExecutionStatus_EXECUTION_STATUS_SKIPPED:
		return "skipped"
	case pm.ExecutionStatus_EXECUTION_STATUS_NOT_APPLICABLE:
		return "not_applicable"
	default:
		return ""
	}
}

func stringToStatus(s string) pm.ExecutionStatus {
	switch s {
	case "pending":
		return pm.ExecutionStatus_EXECUTION_STATUS_PENDING
	case "dispatched":
		return pm.ExecutionStatus_EXECUTION_STATUS_PENDING
	case "running":
		return pm.ExecutionStatus_EXECUTION_STATUS_RUNNING
	case "success":
		return pm.ExecutionStatus_EXECUTION_STATUS_SUCCESS
	case "failed":
		return pm.ExecutionStatus_EXECUTION_STATUS_FAILED
	case "timeout":
		return pm.ExecutionStatus_EXECUTION_STATUS_TIMEOUT
	case "scheduled":
		return pm.ExecutionStatus_EXECUTION_STATUS_SCHEDULED
	case "cancelled":
		return pm.ExecutionStatus_EXECUTION_STATUS_CANCELLED
	case "skipped":
		return pm.ExecutionStatus_EXECUTION_STATUS_SKIPPED
	case "not_applicable":
		return pm.ExecutionStatus_EXECUTION_STATUS_NOT_APPLICABLE
	default:
		return pm.ExecutionStatus_EXECUTION_STATUS_UNSPECIFIED
	}
}

// loadLiveOutput loads streaming output chunks from the event store and
// aggregates them into a CommandOutput.
// maxOutputChunkRows bounds how many OutputChunk rows loadLiveOutput fetches for
// one execution (the SQL LIMIT), so a flood of chunks can't load an unbounded
// slice into control memory (spec 29 S6). Package var for the test seam.
var maxOutputChunkRows int32 = 4096

// maxLiveOutputBytes caps the total stdout+stderr bytes loadLiveOutput
// concatenates. Actions don't produce megabytes of output; past this the stream
// is truncated with a marker rather than blowing up control memory. Package var
// for the test seam.
var maxLiveOutputBytes = 4 << 20 // 4 MiB

func (h *ActionHandler) loadLiveOutput(ctx context.Context, executionID string) *pm.CommandOutput {
	// Fetch one more than the cap so we can tell "exactly at the cap" (nothing
	// dropped) from "over the cap" (output beyond the limit exists) — a plain
	// LIMIT can't distinguish the two, which would mark a full-but-at-limit
	// stream as truncated.
	chunks, err := h.store.Repos().Execution.LoadOutputChunks(ctx, executionID, maxOutputChunkRows+1)
	if err != nil {
		// A real DB failure must not look like "no output yet" — surface it.
		h.logger.ErrorContext(ctx, "failed to load execution output chunks", "execution_id", executionID, "error", err)
		return nil
	}
	if len(chunks) == 0 {
		return nil
	}

	truncated := false
	if int32(len(chunks)) > maxOutputChunkRows {
		// More chunks exist than we display; keep only the first cap-many.
		truncated = true
		chunks = chunks[:maxOutputChunkRows]
	}

	var stdout, stderr strings.Builder
	total := 0
	for _, chunk := range chunks {
		// Parse the chunk data
		var data struct {
			Stream string `json:"stream"`
			Data   string `json:"data"`
		}
		if err := json.Unmarshal(chunk.Data, &data); err != nil {
			continue
		}

		// Stop concatenating once the cumulative output would exceed the budget,
		// so a chunk flood can't grow the response without bound even within the
		// row limit.
		if total+len(data.Data) > maxLiveOutputBytes {
			truncated = true
			break
		}
		total += len(data.Data)

		if data.Stream == "stdout" {
			stdout.WriteString(data.Data)
		} else if data.Stream == "stderr" {
			stderr.WriteString(data.Data)
		}
	}

	// Only return if we have some output
	if stdout.Len() == 0 && stderr.Len() == 0 {
		return nil
	}

	if truncated {
		stderr.WriteString("\n[pm: output truncated — exceeded the per-execution display limit]")
	}

	return &pm.CommandOutput{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}
}
