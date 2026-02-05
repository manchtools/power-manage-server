package api

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// ActionSigner signs action payloads. Nil means signing is disabled.
type ActionSigner interface {
	Sign(actionID string, actionType int32, paramsJSON []byte) ([]byte, error)
}

// ActionHandler handles action (single executable) and execution RPCs.
type ActionHandler struct {
	store   *store.Store
	entropy *ulid.MonotonicEntropy
	logger  *slog.Logger
	signer  ActionSigner
}

// NewActionHandler creates a new action handler.
func NewActionHandler(st *store.Store, signer ActionSigner) *ActionHandler {
	return &ActionHandler{
		store:   st,
		entropy: ulid.Monotonic(rand.Reader, 0),
		logger:  slog.Default(),
		signer:  signer,
	}
}

// validateCreateActionParams validates params for CreateActionRequest using struct tags.
func validateCreateActionParams(req *pm.CreateActionRequest) error {
	switch p := req.Params.(type) {
	case *pm.CreateActionRequest_Package:
		if p.Package != nil {
			return Validate(p.Package)
		}
	case *pm.CreateActionRequest_Shell:
		if p.Shell != nil {
			return Validate(p.Shell)
		}
	case *pm.CreateActionRequest_Systemd:
		if p.Systemd != nil {
			return Validate(p.Systemd)
		}
	case *pm.CreateActionRequest_File:
		if p.File != nil {
			return Validate(p.File)
		}
	case *pm.CreateActionRequest_App:
		if p.App != nil {
			return Validate(p.App)
		}
	case *pm.CreateActionRequest_Flatpak:
		if p.Flatpak != nil {
			return Validate(p.Flatpak)
		}
	case *pm.CreateActionRequest_Update:
		if p.Update != nil {
			return Validate(p.Update)
		}
	case *pm.CreateActionRequest_Repository:
		if p.Repository != nil {
			return Validate(p.Repository)
		}
	case *pm.CreateActionRequest_Directory:
		if p.Directory != nil {
			return Validate(p.Directory)
		}
	}
	return nil
}

// validateUpdateActionParams validates params for UpdateActionParamsRequest using struct tags.
func validateUpdateActionParams(req *pm.UpdateActionParamsRequest) error {
	switch p := req.Params.(type) {
	case *pm.UpdateActionParamsRequest_Package:
		if p.Package != nil {
			return Validate(p.Package)
		}
	case *pm.UpdateActionParamsRequest_Shell:
		if p.Shell != nil {
			return Validate(p.Shell)
		}
	case *pm.UpdateActionParamsRequest_Systemd:
		if p.Systemd != nil {
			return Validate(p.Systemd)
		}
	case *pm.UpdateActionParamsRequest_File:
		if p.File != nil {
			return Validate(p.File)
		}
	case *pm.UpdateActionParamsRequest_App:
		if p.App != nil {
			return Validate(p.App)
		}
	case *pm.UpdateActionParamsRequest_Flatpak:
		if p.Flatpak != nil {
			return Validate(p.Flatpak)
		}
	case *pm.UpdateActionParamsRequest_Update:
		if p.Update != nil {
			return Validate(p.Update)
		}
	case *pm.UpdateActionParamsRequest_Repository:
		if p.Repository != nil {
			return Validate(p.Repository)
		}
	case *pm.UpdateActionParamsRequest_Directory:
		if p.Directory != nil {
			return Validate(p.Directory)
		}
	}
	return nil
}

// CreateAction creates a new action (single executable).
func (h *ActionHandler) CreateAction(ctx context.Context, req *connect.Request[pm.CreateActionRequest]) (*connect.Response[pm.CreateActionResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	if err := validateCreateActionParams(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	params, err := h.serializeCreateActionParams(req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	id := ulid.MustNew(ulid.Timestamp(time.Now()), h.entropy).String()

	timeoutSeconds := int32(req.Msg.TimeoutSeconds)
	if timeoutSeconds <= 0 {
		timeoutSeconds = 300
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   id,
		EventType:  "ActionCreated",
		Data: map[string]any{
			"name":            req.Msg.Name,
			"description":     req.Msg.Description,
			"action_type":     int32(req.Msg.Type),
			"params":          params,
			"timeout_seconds": timeoutSeconds,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		h.logger.Error("failed to append action event", "error", err, "id", id)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create action: %w", err))
	}

	action, err := h.store.QueriesFromContext(ctx).GetActionByID(ctx, id)
	if err != nil {
		h.logger.Error("failed to get action after create", "error", err, "id", id)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get action: %w", err))
	}

	// Sign the action so agents can verify authenticity
	h.signAction(ctx, &action)

	return connect.NewResponse(&pm.CreateActionResponse{
		Action: h.actionToProto(action),
	}), nil
}

// GetAction returns an action by ID.
func (h *ActionHandler) GetAction(ctx context.Context, req *connect.Request[pm.GetActionRequest]) (*connect.Response[pm.GetActionResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	action, err := h.store.QueriesFromContext(ctx).GetActionByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("action not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action"))
	}

	return connect.NewResponse(&pm.GetActionResponse{
		Action: h.actionToProto(action),
	}), nil
}

// ListActions returns a paginated list of actions.
func (h *ActionHandler) ListActions(ctx context.Context, req *connect.Request[pm.ListActionsRequest]) (*connect.Response[pm.ListActionsResponse], error) {
	pageSize := int32(req.Msg.PageSize)
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50
	}

	offset := int32(0)
	if req.Msg.PageToken != "" {
		offset64, err := parsePageToken(req.Msg.PageToken)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid page token"))
		}
		offset = int32(offset64)
	}

	typeFilter := int32(req.Msg.TypeFilter)

	actions, err := h.store.QueriesFromContext(ctx).ListActions(ctx, db.ListActionsParams{
		Column1: typeFilter,
		Limit:   pageSize,
		Offset:  offset,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list actions"))
	}

	count, err := h.store.QueriesFromContext(ctx).CountActions(ctx, typeFilter)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to count actions"))
	}

	var nextPageToken string
	if int32(len(actions)) == pageSize && int64(offset)+int64(pageSize) < count {
		nextPageToken = formatPageToken(int64(offset) + int64(pageSize))
	}

	protoActions := make([]*pm.ManagedAction, len(actions))
	for i, a := range actions {
		protoActions[i] = h.actionToProto(a)
	}

	return connect.NewResponse(&pm.ListActionsResponse{
		Actions:       protoActions,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// RenameAction renames an action.
func (h *ActionHandler) RenameAction(ctx context.Context, req *connect.Request[pm.RenameActionRequest]) (*connect.Response[pm.UpdateActionResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   req.Msg.Id,
		EventType:  "ActionRenamed",
		Data: map[string]any{
			"name": req.Msg.Name,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to rename action"))
	}

	action, err := h.store.QueriesFromContext(ctx).GetActionByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("action not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action"))
	}

	return connect.NewResponse(&pm.UpdateActionResponse{
		Action: h.actionToProto(action),
	}), nil
}

// UpdateActionDescription updates an action's description.
func (h *ActionHandler) UpdateActionDescription(ctx context.Context, req *connect.Request[pm.UpdateActionDescriptionRequest]) (*connect.Response[pm.UpdateActionResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   req.Msg.Id,
		EventType:  "ActionDescriptionUpdated",
		Data: map[string]any{
			"description": req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update description"))
	}

	action, err := h.store.QueriesFromContext(ctx).GetActionByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("action not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action"))
	}

	return connect.NewResponse(&pm.UpdateActionResponse{
		Action: h.actionToProto(action),
	}), nil
}

// UpdateActionParams updates an action's parameters, desired state, and timeout.
func (h *ActionHandler) UpdateActionParams(ctx context.Context, req *connect.Request[pm.UpdateActionParamsRequest]) (*connect.Response[pm.UpdateActionResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	if err := validateUpdateActionParams(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	_, err := h.store.QueriesFromContext(ctx).GetActionByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("action not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action"))
	}

	params, err := h.serializeUpdateActionParams(req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	eventData := map[string]any{
		"params": params,
	}

	if req.Msg.TimeoutSeconds > 0 {
		eventData["timeout_seconds"] = req.Msg.TimeoutSeconds
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   req.Msg.Id,
		EventType:  "ActionParamsUpdated",
		Data:       eventData,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update action params"))
	}

	action, err := h.store.QueriesFromContext(ctx).GetActionByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("action not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action"))
	}

	// Re-sign the action after params update
	h.signAction(ctx, &action)

	return connect.NewResponse(&pm.UpdateActionResponse{
		Action: h.actionToProto(action),
	}), nil
}

// signAction computes a signature over the action's canonical payload and
// persists it in the projection. This is a best-effort operation; signing
// failures are logged but do not fail the parent request.
func (h *ActionHandler) signAction(ctx context.Context, action *db.ActionsProjection) {
	if h.signer == nil {
		return
	}

	paramsJSON := action.Params
	if paramsJSON == nil {
		paramsJSON = []byte("{}")
	}

	sig, err := h.signer.Sign(action.ID, action.ActionType, paramsJSON)
	if err != nil {
		h.logger.Error("failed to sign action", "action_id", action.ID, "error", err)
		return
	}

	if err := h.store.QueriesFromContext(ctx).UpdateActionSignature(ctx, db.UpdateActionSignatureParams{
		ID:              action.ID,
		Signature:       sig,
		ParamsCanonical: paramsJSON,
	}); err != nil {
		h.logger.Error("failed to store action signature", "action_id", action.ID, "error", err)
		return
	}

	// Update the in-memory struct so the response includes the signature
	action.Signature = sig
	action.ParamsCanonical = paramsJSON
}

// DeleteAction deletes an action.
func (h *ActionHandler) DeleteAction(ctx context.Context, req *connect.Request[pm.DeleteActionRequest]) (*connect.Response[pm.DeleteActionResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   req.Msg.Id,
		EventType:  "ActionDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete action"))
	}

	return connect.NewResponse(&pm.DeleteActionResponse{}), nil
}

// DispatchAction dispatches an action to a device.
func (h *ActionHandler) DispatchAction(ctx context.Context, req *connect.Request[pm.DispatchActionRequest]) (*connect.Response[pm.DispatchActionResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	_, err := h.store.QueriesFromContext(ctx).GetDeviceByID(ctx, req.Msg.DeviceId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device"))
	}

	var actionType pm.ActionType
	var desiredState pm.DesiredState
	var params any // Use any to store either parsed JSON object or raw JSON
	var timeoutSeconds int32
	var actionID *string

	switch source := req.Msg.ActionSource.(type) {
	case *pm.DispatchActionRequest_ActionId:
		action, err := h.store.QueriesFromContext(ctx).GetActionByID(ctx, source.ActionId)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, connect.NewError(connect.CodeNotFound, errors.New("action not found"))
			}
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action"))
		}
		actionType = pm.ActionType(action.ActionType)
		desiredState = pm.DesiredState_DESIRED_STATE_PRESENT // Default for ad-hoc dispatch
		// Parse params JSON to avoid double-encoding when storing the event
		var parsedParams map[string]any
		if err := json.Unmarshal(action.Params, &parsedParams); err == nil {
			params = parsedParams
		} else {
			params = string(action.Params) // Fallback to string if parsing fails
		}
		timeoutSeconds = action.TimeoutSeconds
		actionID = &source.ActionId

	case *pm.DispatchActionRequest_InlineAction:
		action := source.InlineAction
		actionType = action.Type
		desiredState = action.DesiredState
		params = serializeActionParamsToMap(action)
		timeoutSeconds = action.TimeoutSeconds
		if timeoutSeconds <= 0 {
			timeoutSeconds = 300
		}

	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("either action_id or inline_action is required"))
	}

	id := ulid.MustNew(ulid.Timestamp(time.Now()), h.entropy).String()

	eventData := map[string]any{
		"device_id":       req.Msg.DeviceId,
		"action_type":     int32(actionType),
		"desired_state":   int32(desiredState),
		"params":          params,
		"timeout_seconds": timeoutSeconds,
	}
	if actionID != nil {
		eventData["action_id"] = *actionID
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "execution",
		StreamID:   id,
		EventType:  "ExecutionCreated",
		Data:       eventData,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create execution"))
	}

	exec, err := h.store.QueriesFromContext(ctx).GetExecutionByID(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get execution"))
	}

	return connect.NewResponse(&pm.DispatchActionResponse{
		Execution: h.executionToProto(exec),
	}), nil
}

// DispatchToMultiple dispatches an action to multiple devices.
func (h *ActionHandler) DispatchToMultiple(ctx context.Context, req *connect.Request[pm.DispatchToMultipleRequest]) (*connect.Response[pm.DispatchToMultipleResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	executions := make([]*pm.ActionExecution, 0, len(req.Msg.DeviceIds))

	for _, deviceID := range req.Msg.DeviceIds {
		var dispatchReq *pm.DispatchActionRequest
		switch source := req.Msg.ActionSource.(type) {
		case *pm.DispatchToMultipleRequest_ActionId:
			dispatchReq = &pm.DispatchActionRequest{
				DeviceId:     deviceID,
				ActionSource: &pm.DispatchActionRequest_ActionId{ActionId: source.ActionId},
			}
		case *pm.DispatchToMultipleRequest_InlineAction:
			dispatchReq = &pm.DispatchActionRequest{
				DeviceId:     deviceID,
				ActionSource: &pm.DispatchActionRequest_InlineAction{InlineAction: source.InlineAction},
			}
		default:
			continue
		}

		resp, err := h.DispatchAction(ctx, connect.NewRequest(dispatchReq))
		if err != nil {
			continue
		}
		executions = append(executions, resp.Msg.Execution)
	}

	return connect.NewResponse(&pm.DispatchToMultipleResponse{
		Executions: executions,
	}), nil
}

// DispatchAssignedActions dispatches all actions assigned to a device.
func (h *ActionHandler) DispatchAssignedActions(ctx context.Context, req *connect.Request[pm.DispatchAssignedActionsRequest]) (*connect.Response[pm.DispatchAssignedActionsResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	actions, err := h.store.QueriesFromContext(ctx).ListAssignedActionsForDevice(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get assigned actions"))
	}

	executions := make([]*pm.ActionExecution, 0, len(actions))
	for _, action := range actions {
		dispatchReq := &pm.DispatchActionRequest{
			DeviceId:     req.Msg.DeviceId,
			ActionSource: &pm.DispatchActionRequest_ActionId{ActionId: action.ID},
		}
		resp, err := h.DispatchAction(ctx, connect.NewRequest(dispatchReq))
		if err != nil {
			continue
		}
		executions = append(executions, resp.Msg.Execution)
	}

	return connect.NewResponse(&pm.DispatchAssignedActionsResponse{
		Executions: executions,
	}), nil
}

// DispatchActionSet dispatches all actions from an action set to a device.
func (h *ActionHandler) DispatchActionSet(ctx context.Context, req *connect.Request[pm.DispatchActionSetRequest]) (*connect.Response[pm.DispatchActionSetResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	actions, err := h.store.QueriesFromContext(ctx).ListActionsInSet(ctx, req.Msg.ActionSetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get actions in set"))
	}

	executions := make([]*pm.ActionExecution, 0, len(actions))
	for _, action := range actions {
		dispatchReq := &pm.DispatchActionRequest{
			DeviceId:     req.Msg.DeviceId,
			ActionSource: &pm.DispatchActionRequest_ActionId{ActionId: action.ID},
		}
		resp, err := h.DispatchAction(ctx, connect.NewRequest(dispatchReq))
		if err != nil {
			continue
		}
		executions = append(executions, resp.Msg.Execution)
	}

	return connect.NewResponse(&pm.DispatchActionSetResponse{
		Executions: executions,
	}), nil
}

// DispatchDefinition dispatches all actions from a definition to a device.
func (h *ActionHandler) DispatchDefinition(ctx context.Context, req *connect.Request[pm.DispatchDefinitionRequest]) (*connect.Response[pm.DispatchDefinitionResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	actionSets, err := h.store.QueriesFromContext(ctx).ListActionSetsInDefinition(ctx, req.Msg.DefinitionId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action sets in definition"))
	}

	executions := make([]*pm.ActionExecution, 0)
	for _, set := range actionSets {
		actions, err := h.store.QueriesFromContext(ctx).ListActionsInSet(ctx, set.ID)
		if err != nil {
			continue
		}
		for _, action := range actions {
			dispatchReq := &pm.DispatchActionRequest{
				DeviceId:     req.Msg.DeviceId,
				ActionSource: &pm.DispatchActionRequest_ActionId{ActionId: action.ID},
			}
			resp, err := h.DispatchAction(ctx, connect.NewRequest(dispatchReq))
			if err != nil {
				continue
			}
			executions = append(executions, resp.Msg.Execution)
		}
	}

	return connect.NewResponse(&pm.DispatchDefinitionResponse{
		Executions: executions,
	}), nil
}

// DispatchToGroup dispatches an action/set/definition to all devices in a group.
func (h *ActionHandler) DispatchToGroup(ctx context.Context, req *connect.Request[pm.DispatchToGroupRequest]) (*connect.Response[pm.DispatchToGroupResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	devices, err := h.store.QueriesFromContext(ctx).ListDevicesInGroup(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get devices in group"))
	}

	executions := make([]*pm.ActionExecution, 0)

	for _, device := range devices {
		switch source := req.Msg.ActionSource.(type) {
		case *pm.DispatchToGroupRequest_ActionId:
			dispatchReq := &pm.DispatchActionRequest{
				DeviceId:     device.ID,
				ActionSource: &pm.DispatchActionRequest_ActionId{ActionId: source.ActionId},
			}
			resp, err := h.DispatchAction(ctx, connect.NewRequest(dispatchReq))
			if err == nil {
				executions = append(executions, resp.Msg.Execution)
			}

		case *pm.DispatchToGroupRequest_ActionSetId:
			setReq := &pm.DispatchActionSetRequest{
				DeviceId:    device.ID,
				ActionSetId: source.ActionSetId,
			}
			resp, err := h.DispatchActionSet(ctx, connect.NewRequest(setReq))
			if err == nil {
				executions = append(executions, resp.Msg.Executions...)
			}

		case *pm.DispatchToGroupRequest_DefinitionId:
			defReq := &pm.DispatchDefinitionRequest{
				DeviceId:     device.ID,
				DefinitionId: source.DefinitionId,
			}
			resp, err := h.DispatchDefinition(ctx, connect.NewRequest(defReq))
			if err == nil {
				executions = append(executions, resp.Msg.Executions...)
			}

		case *pm.DispatchToGroupRequest_InlineAction:
			dispatchReq := &pm.DispatchActionRequest{
				DeviceId:     device.ID,
				ActionSource: &pm.DispatchActionRequest_InlineAction{InlineAction: source.InlineAction},
			}
			resp, err := h.DispatchAction(ctx, connect.NewRequest(dispatchReq))
			if err == nil {
				executions = append(executions, resp.Msg.Execution)
			}
		}
	}

	return connect.NewResponse(&pm.DispatchToGroupResponse{
		Executions: executions,
	}), nil
}

// GetExecution returns an execution by ID.
func (h *ActionHandler) GetExecution(ctx context.Context, req *connect.Request[pm.GetExecutionRequest]) (*connect.Response[pm.GetExecutionResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	exec, err := h.store.QueriesFromContext(ctx).GetExecutionByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("execution not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get execution"))
	}

	protoExec := h.executionToProto(exec)

	// Load live output from output chunks
	liveOutput := h.loadLiveOutput(ctx, req.Msg.Id)
	if liveOutput != nil {
		protoExec.LiveOutput = liveOutput
	}

	return connect.NewResponse(&pm.GetExecutionResponse{
		Execution: protoExec,
	}), nil
}

// ListExecutions returns a paginated list of executions.
func (h *ActionHandler) ListExecutions(ctx context.Context, req *connect.Request[pm.ListExecutionsRequest]) (*connect.Response[pm.ListExecutionsResponse], error) {
	pageSize := int32(req.Msg.PageSize)
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50
	}

	offset := int32(0)
	if req.Msg.PageToken != "" {
		offset64, err := parsePageToken(req.Msg.PageToken)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid page token"))
		}
		offset = int32(offset64)
	}

	statusFilter := ""
	if req.Msg.StatusFilter != pm.ExecutionStatus_EXECUTION_STATUS_UNSPECIFIED {
		statusFilter = statusToString(req.Msg.StatusFilter)
	}

	execs, err := h.store.QueriesFromContext(ctx).ListExecutions(ctx, db.ListExecutionsParams{
		Column1: req.Msg.DeviceId,
		Column2: statusFilter,
		Limit:   pageSize,
		Offset:  offset,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list executions"))
	}

	count, err := h.store.QueriesFromContext(ctx).CountExecutions(ctx, db.CountExecutionsParams{
		Column1: req.Msg.DeviceId,
		Column2: statusFilter,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to count executions"))
	}

	var nextPageToken string
	if int32(len(execs)) == pageSize && int64(offset)+int64(pageSize) < count {
		nextPageToken = formatPageToken(int64(offset) + int64(pageSize))
	}

	protoExecs := make([]*pm.ActionExecution, len(execs))
	for i, e := range execs {
		protoExecs[i] = h.executionToProto(e)
	}

	return connect.NewResponse(&pm.ListExecutionsResponse{
		Executions:    protoExecs,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

func (h *ActionHandler) serializeCreateActionParams(req *pm.CreateActionRequest) (map[string]any, error) {
	params := map[string]any{}

	switch p := req.Params.(type) {
	case *pm.CreateActionRequest_Package:
		data, _ := protojson.Marshal(p.Package)
		json.Unmarshal(data, &params)
	case *pm.CreateActionRequest_App:
		data, _ := protojson.Marshal(p.App)
		json.Unmarshal(data, &params)
	case *pm.CreateActionRequest_Flatpak:
		data, _ := protojson.Marshal(p.Flatpak)
		json.Unmarshal(data, &params)
	case *pm.CreateActionRequest_Shell:
		data, _ := protojson.Marshal(p.Shell)
		json.Unmarshal(data, &params)
	case *pm.CreateActionRequest_Systemd:
		data, _ := protojson.Marshal(p.Systemd)
		json.Unmarshal(data, &params)
	case *pm.CreateActionRequest_File:
		data, _ := protojson.Marshal(p.File)
		json.Unmarshal(data, &params)
	case *pm.CreateActionRequest_Update:
		data, _ := protojson.Marshal(p.Update)
		json.Unmarshal(data, &params)
	case *pm.CreateActionRequest_Repository:
		data, _ := protojson.Marshal(p.Repository)
		json.Unmarshal(data, &params)
	case *pm.CreateActionRequest_Directory:
		data, _ := protojson.Marshal(p.Directory)
		json.Unmarshal(data, &params)
	}

	return params, nil
}

func (h *ActionHandler) serializeUpdateActionParams(req *pm.UpdateActionParamsRequest) (map[string]any, error) {
	params := map[string]any{}

	switch p := req.Params.(type) {
	case *pm.UpdateActionParamsRequest_Package:
		data, _ := protojson.Marshal(p.Package)
		json.Unmarshal(data, &params)
	case *pm.UpdateActionParamsRequest_App:
		data, _ := protojson.Marshal(p.App)
		json.Unmarshal(data, &params)
	case *pm.UpdateActionParamsRequest_Flatpak:
		data, _ := protojson.Marshal(p.Flatpak)
		json.Unmarshal(data, &params)
	case *pm.UpdateActionParamsRequest_Shell:
		data, _ := protojson.Marshal(p.Shell)
		json.Unmarshal(data, &params)
	case *pm.UpdateActionParamsRequest_Systemd:
		data, _ := protojson.Marshal(p.Systemd)
		json.Unmarshal(data, &params)
	case *pm.UpdateActionParamsRequest_File:
		data, _ := protojson.Marshal(p.File)
		json.Unmarshal(data, &params)
	case *pm.UpdateActionParamsRequest_Update:
		data, _ := protojson.Marshal(p.Update)
		json.Unmarshal(data, &params)
	case *pm.UpdateActionParamsRequest_Repository:
		data, _ := protojson.Marshal(p.Repository)
		json.Unmarshal(data, &params)
	case *pm.UpdateActionParamsRequest_Directory:
		data, _ := protojson.Marshal(p.Directory)
		json.Unmarshal(data, &params)
	}

	return params, nil
}

func serializeActionParams(action *pm.Action) (string, error) {
	params := serializeActionParamsToMap(action)
	data, err := json.Marshal(params)
	return string(data), err
}

func serializeActionParamsToMap(action *pm.Action) map[string]any {
	params := map[string]any{}

	switch p := action.Params.(type) {
	case *pm.Action_Package:
		data, _ := protojson.Marshal(p.Package)
		json.Unmarshal(data, &params)
	case *pm.Action_App:
		data, _ := protojson.Marshal(p.App)
		json.Unmarshal(data, &params)
	case *pm.Action_Flatpak:
		data, _ := protojson.Marshal(p.Flatpak)
		json.Unmarshal(data, &params)
	case *pm.Action_Shell:
		data, _ := protojson.Marshal(p.Shell)
		json.Unmarshal(data, &params)
	case *pm.Action_Systemd:
		data, _ := protojson.Marshal(p.Systemd)
		json.Unmarshal(data, &params)
	case *pm.Action_File:
		data, _ := protojson.Marshal(p.File)
		json.Unmarshal(data, &params)
	case *pm.Action_Update:
		data, _ := protojson.Marshal(p.Update)
		json.Unmarshal(data, &params)
	case *pm.Action_Repository:
		data, _ := protojson.Marshal(p.Repository)
		json.Unmarshal(data, &params)
	case *pm.Action_Directory:
		data, _ := protojson.Marshal(p.Directory)
		json.Unmarshal(data, &params)
	}

	return params
}

func (h *ActionHandler) actionToProto(a db.ActionsProjection) *pm.ManagedAction {
	action := &pm.ManagedAction{
		Id:             a.ID,
		Name:           a.Name,
		Type:           pm.ActionType(a.ActionType),
		TimeoutSeconds: a.TimeoutSeconds,
		CreatedBy:      a.CreatedBy,
	}

	if a.Description != nil {
		action.Description = *a.Description
	}

	if a.CreatedAt.Valid {
		action.CreatedAt = timestamppb.New(a.CreatedAt.Time)
	}

	if len(a.Params) > 0 {
		h.deserializeActionParams(action, pm.ActionType(a.ActionType), a.Params)
	}

	return action
}

func (h *ActionHandler) deserializeActionParams(action *pm.ManagedAction, actionType pm.ActionType, paramsJSON []byte) {
	switch actionType {
	case pm.ActionType_ACTION_TYPE_PACKAGE:
		var p pm.PackageParams
		if err := protojson.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Package{Package: &p}
		}
	case pm.ActionType_ACTION_TYPE_APP_IMAGE:
		var p pm.AppInstallParams
		if err := protojson.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_App{App: &p}
		}
	case pm.ActionType_ACTION_TYPE_SHELL:
		var p pm.ShellParams
		if err := protojson.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Shell{Shell: &p}
		}
	case pm.ActionType_ACTION_TYPE_SYSTEMD:
		var p pm.SystemdParams
		if err := protojson.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Systemd{Systemd: &p}
		}
	case pm.ActionType_ACTION_TYPE_FILE:
		var p pm.FileParams
		if err := protojson.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_File{File: &p}
		}
	case pm.ActionType_ACTION_TYPE_UPDATE:
		var p pm.UpdateParams
		if err := protojson.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Update{Update: &p}
		}
	case pm.ActionType_ACTION_TYPE_REPOSITORY:
		var p pm.RepositoryParams
		if err := protojson.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Repository{Repository: &p}
		}
	case pm.ActionType_ACTION_TYPE_DIRECTORY:
		var p pm.DirectoryParams
		if err := protojson.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Directory{Directory: &p}
		}
	}
}

func (h *ActionHandler) executionToProto(e db.ExecutionsProjection) *pm.ActionExecution {
	exec := &pm.ActionExecution{
		Id:       e.ID,
		DeviceId: e.DeviceID,
		Type:     pm.ActionType(e.ActionType),
		Status:   stringToStatus(e.Status),
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

	if e.CreatedAt.Valid {
		exec.CreatedAt = timestamppb.New(e.CreatedAt.Time)
	}

	if e.DispatchedAt.Valid {
		exec.DispatchedAt = timestamppb.New(e.DispatchedAt.Time)
	}

	if e.CompletedAt.Valid {
		exec.CompletedAt = timestamppb.New(e.CompletedAt.Time)
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
	default:
		return pm.ExecutionStatus_EXECUTION_STATUS_UNSPECIFIED
	}
}

// loadLiveOutput loads streaming output chunks from the event store and
// aggregates them into a CommandOutput.
func (h *ActionHandler) loadLiveOutput(ctx context.Context, executionID string) *pm.CommandOutput {
	chunks, err := h.store.QueriesFromContext(ctx).LoadOutputChunks(ctx, executionID)
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
