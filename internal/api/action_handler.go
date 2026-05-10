// Package api file action_handler.go — declares the ActionHandler
// type and its constructor; per-RPC implementations live in sibling
// files (audit F005):
//
//   - action_crud.go        — Create / Get / List / Rename /
//                              UpdateDescription / UpdateParams /
//                              Delete + the signature lifecycle
//                              (computeActionSignature,
//                              persistActionSignature,
//                              rollbackUnsignedCreate)
//   - action_dispatch.go    — DispatchAction / DispatchToMultiple /
//                              DispatchAssignedActions /
//                              DispatchActionSet /
//                              DispatchDefinition /
//                              DispatchToGroup /
//                              DispatchInstantAction /
//                              GetExecution / ListExecutions /
//                              CancelExecution + isInstantActionType
//   - action_validators.go  — validateCreateActionParams /
//                              validateUpdateActionParams /
//                              validateInlineAction /
//                              validateShellScriptChoice /
//                              validateAgentUpdateParams /
//                              actionParamsMatchType
//   - action_params.go      — serializeProtoParams /
//                              extractCreateActionParamsMsg /
//                              extractUpdateActionParamsMsg /
//                              extractActionParamsMsg
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

	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
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

func (h *ActionHandler) actionToProto(a db.ActionsProjection) *pm.ManagedAction {
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
		actionparams.PopulateManagedAction(action, pm.ActionType(a.ActionType), a.Params)
	}

	if len(a.Schedule) > 0 {
		action.Schedule = scheduleFromJSON(a.Schedule)
	}

	return action
}

func (h *ActionHandler) executionToProto(e db.ExecutionsProjection) *pm.ActionExecution {
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

	if len(e.Output) > 0 {
		var output pm.CommandOutput
		if err := json.Unmarshal(e.Output, &output); err == nil {
			exec.Output = &output
		}
	}

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
	if len(e.DetectionOutput) > 0 {
		var detOutput pm.CommandOutput
		if err := json.Unmarshal(e.DetectionOutput, &detOutput); err == nil {
			exec.DetectionOutput = &detOutput
		}
	}

	return exec
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
	default:
		return pm.ExecutionStatus_EXECUTION_STATUS_UNSPECIFIED
	}
}

// loadLiveOutput loads streaming output chunks from the event store and
// aggregates them into a CommandOutput.
func (h *ActionHandler) loadLiveOutput(ctx context.Context, executionID string) *pm.CommandOutput {
	chunks, err := h.store.Queries().LoadOutputChunks(ctx, executionID)
	if err != nil || len(chunks) == 0 {
		return nil
	}

	var stdout, stderr strings.Builder
	for _, chunk := range chunks {
		// Parse the chunk data
		var data struct {
			Stream string `json:"stream"`
			Data   string `json:"data"`
		}
		if err := json.Unmarshal(chunk.Data, &data); err != nil {
			continue
		}

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

	return &pm.CommandOutput{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}
}

