package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"connectrpc.com/connect"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// ActionSigner signs action payloads. Nil means signing is disabled.
type ActionSigner interface {
	Sign(actionID string, actionType int32, paramsJSON []byte) ([]byte, error)
}

// ActionHandler handles action (single executable) and execution RPCs.
type ActionHandler struct {
	taskQueueHolder // aqClient is nil during Phase 2 dual-write if Valkey is not configured
	searchIndexHolder
	store  *store.Store
	logger *slog.Logger
	signer ActionSigner
}

// NewActionHandler creates a new action handler.
func NewActionHandler(st *store.Store, logger *slog.Logger, signer ActionSigner) *ActionHandler {
	return &ActionHandler{
		store:  st,
		logger: logger,
		signer: signer,
	}
}

// validateCreateActionParams validates params for CreateActionRequest using struct tags.
func validateCreateActionParams(ctx context.Context, req *pm.CreateActionRequest) error {
	switch p := req.Params.(type) {
	case *pm.CreateActionRequest_Package:
		if p.Package != nil {
			return Validate(ctx, p.Package)
		}
	case *pm.CreateActionRequest_Shell:
		if p.Shell != nil {
			if err := Validate(ctx, p.Shell); err != nil {
				return err
			}
			if p.Shell.Script == "" && p.Shell.DetectionScript == "" {
				return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "at least one of script or detection_script is required")
			}
			return nil
		}
	case *pm.CreateActionRequest_Service:
		if p.Service != nil {
			return Validate(ctx, p.Service)
		}
	case *pm.CreateActionRequest_File:
		if p.File != nil {
			return Validate(ctx, p.File)
		}
	case *pm.CreateActionRequest_App:
		if p.App != nil {
			return Validate(ctx, p.App)
		}
	case *pm.CreateActionRequest_Flatpak:
		if p.Flatpak != nil {
			return Validate(ctx, p.Flatpak)
		}
	case *pm.CreateActionRequest_Update:
		if p.Update != nil {
			return Validate(ctx, p.Update)
		}
	case *pm.CreateActionRequest_Repository:
		if p.Repository != nil {
			return Validate(ctx, p.Repository)
		}
	case *pm.CreateActionRequest_Directory:
		if p.Directory != nil {
			return Validate(ctx, p.Directory)
		}
	case *pm.CreateActionRequest_User:
		if p.User != nil {
			return Validate(ctx, p.User)
		}
	case *pm.CreateActionRequest_Ssh:
		if p.Ssh != nil {
			return Validate(ctx, p.Ssh)
		}
	case *pm.CreateActionRequest_Sshd:
		if p.Sshd != nil {
			return Validate(ctx, p.Sshd)
		}
	case *pm.CreateActionRequest_AdminPolicy:
		if p.AdminPolicy != nil {
			return Validate(ctx, p.AdminPolicy)
		}
	case *pm.CreateActionRequest_Lps:
		if p.Lps != nil {
			return Validate(ctx, p.Lps)
		}
	case *pm.CreateActionRequest_Encryption:
		if p.Encryption != nil {
			return Validate(ctx, p.Encryption)
		}
	case *pm.CreateActionRequest_Group:
		if p.Group != nil {
			return Validate(ctx, p.Group)
		}
	case *pm.CreateActionRequest_Wifi:
		if p.Wifi != nil {
			return Validate(ctx, p.Wifi)
		}
	case *pm.CreateActionRequest_AgentUpdate:
		if p.AgentUpdate != nil {
			return validateAgentUpdateParams(ctx, p.AgentUpdate)
		}
	}
	return nil
}

// validateUpdateActionParams validates params for UpdateActionParamsRequest using struct tags.
func validateUpdateActionParams(ctx context.Context, req *pm.UpdateActionParamsRequest) error {
	switch p := req.Params.(type) {
	case *pm.UpdateActionParamsRequest_Package:
		if p.Package != nil {
			return Validate(ctx, p.Package)
		}
	case *pm.UpdateActionParamsRequest_Shell:
		if p.Shell != nil {
			return Validate(ctx, p.Shell)
		}
	case *pm.UpdateActionParamsRequest_Service:
		if p.Service != nil {
			return Validate(ctx, p.Service)
		}
	case *pm.UpdateActionParamsRequest_File:
		if p.File != nil {
			return Validate(ctx, p.File)
		}
	case *pm.UpdateActionParamsRequest_App:
		if p.App != nil {
			return Validate(ctx, p.App)
		}
	case *pm.UpdateActionParamsRequest_Flatpak:
		if p.Flatpak != nil {
			return Validate(ctx, p.Flatpak)
		}
	case *pm.UpdateActionParamsRequest_Update:
		if p.Update != nil {
			return Validate(ctx, p.Update)
		}
	case *pm.UpdateActionParamsRequest_Repository:
		if p.Repository != nil {
			return Validate(ctx, p.Repository)
		}
	case *pm.UpdateActionParamsRequest_Directory:
		if p.Directory != nil {
			return Validate(ctx, p.Directory)
		}
	case *pm.UpdateActionParamsRequest_User:
		if p.User != nil {
			return Validate(ctx, p.User)
		}
	case *pm.UpdateActionParamsRequest_Ssh:
		if p.Ssh != nil {
			return Validate(ctx, p.Ssh)
		}
	case *pm.UpdateActionParamsRequest_Sshd:
		if p.Sshd != nil {
			return Validate(ctx, p.Sshd)
		}
	case *pm.UpdateActionParamsRequest_AdminPolicy:
		if p.AdminPolicy != nil {
			return Validate(ctx, p.AdminPolicy)
		}
	case *pm.UpdateActionParamsRequest_Lps:
		if p.Lps != nil {
			return Validate(ctx, p.Lps)
		}
	case *pm.UpdateActionParamsRequest_Encryption:
		if p.Encryption != nil {
			return Validate(ctx, p.Encryption)
		}
	case *pm.UpdateActionParamsRequest_Group:
		if p.Group != nil {
			return Validate(ctx, p.Group)
		}
	case *pm.UpdateActionParamsRequest_Wifi:
		if p.Wifi != nil {
			return Validate(ctx, p.Wifi)
		}
	case *pm.UpdateActionParamsRequest_AgentUpdate:
		if p.AgentUpdate != nil {
			return validateAgentUpdateParams(ctx, p.AgentUpdate)
		}
	}
	return nil
}

// validateInlineAction validates a DispatchAction inline Action before the
// server signs and enqueues it. Inline actions intentionally do not require
// Action.id because DispatchAction replaces it with the execution ID.
func validateInlineAction(ctx context.Context, action *pm.Action) error {
	if action == nil {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "inline_action is required")
	}
	if action.Type == pm.ActionType_ACTION_TYPE_UNSPECIFIED {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "action type is required")
	}
	if action.TimeoutSeconds < 0 || action.TimeoutSeconds > 3600 {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "timeout_seconds must be between 0 and 3600")
	}
	if action.Schedule != nil {
		if err := Validate(ctx, action.Schedule); err != nil {
			return err
		}
	}

	params := extractActionParamsMsg(action)
	if params == nil {
		if action.Type == pm.ActionType_ACTION_TYPE_UPDATE {
			return nil
		}
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "inline_action params are required")
	}
	if !actionParamsMatchType(action.Type, action.Params) {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "inline_action params do not match action.Type")
	}
	if err := Validate(ctx, params); err != nil {
		return err
	}
	if shell, ok := params.(*pm.ShellParams); ok {
		if shell.Script == "" && shell.DetectionScript == "" {
			return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "at least one of script or detection_script is required")
		}
	}
	if agentUpdate, ok := params.(*pm.AgentUpdateParams); ok {
		return validateAgentUpdateParams(ctx, agentUpdate)
	}
	return nil
}

func actionParamsMatchType(actionType pm.ActionType, params any) bool {
	switch actionType {
	case pm.ActionType_ACTION_TYPE_PACKAGE:
		_, ok := params.(*pm.Action_Package)
		return ok
	case pm.ActionType_ACTION_TYPE_APP_IMAGE, pm.ActionType_ACTION_TYPE_DEB, pm.ActionType_ACTION_TYPE_RPM:
		_, ok := params.(*pm.Action_App)
		return ok
	case pm.ActionType_ACTION_TYPE_FLATPAK:
		_, ok := params.(*pm.Action_Flatpak)
		return ok
	case pm.ActionType_ACTION_TYPE_SHELL, pm.ActionType_ACTION_TYPE_SCRIPT_RUN:
		_, ok := params.(*pm.Action_Shell)
		return ok
	case pm.ActionType_ACTION_TYPE_SERVICE:
		_, ok := params.(*pm.Action_Service)
		return ok
	case pm.ActionType_ACTION_TYPE_FILE:
		_, ok := params.(*pm.Action_File)
		return ok
	case pm.ActionType_ACTION_TYPE_UPDATE:
		_, ok := params.(*pm.Action_Update)
		return ok
	case pm.ActionType_ACTION_TYPE_REPOSITORY:
		_, ok := params.(*pm.Action_Repository)
		return ok
	case pm.ActionType_ACTION_TYPE_DIRECTORY:
		_, ok := params.(*pm.Action_Directory)
		return ok
	case pm.ActionType_ACTION_TYPE_USER:
		_, ok := params.(*pm.Action_User)
		return ok
	case pm.ActionType_ACTION_TYPE_SSH:
		_, ok := params.(*pm.Action_Ssh)
		return ok
	case pm.ActionType_ACTION_TYPE_SSHD:
		_, ok := params.(*pm.Action_Sshd)
		return ok
	case pm.ActionType_ACTION_TYPE_ADMIN_POLICY:
		_, ok := params.(*pm.Action_AdminPolicy)
		return ok
	case pm.ActionType_ACTION_TYPE_LPS:
		_, ok := params.(*pm.Action_Lps)
		return ok
	case pm.ActionType_ACTION_TYPE_ENCRYPTION:
		_, ok := params.(*pm.Action_Encryption)
		return ok
	case pm.ActionType_ACTION_TYPE_GROUP:
		_, ok := params.(*pm.Action_Group)
		return ok
	case pm.ActionType_ACTION_TYPE_WIFI:
		_, ok := params.(*pm.Action_Wifi)
		return ok
	case pm.ActionType_ACTION_TYPE_AGENT_UPDATE:
		_, ok := params.(*pm.Action_AgentUpdate)
		return ok
	default:
		return false
	}
}

// validateAgentUpdateParams checks that at least one arch is set and all URLs are HTTPS.
func validateAgentUpdateParams(ctx context.Context, p *pm.AgentUpdateParams) error {
	if err := Validate(ctx, p); err != nil {
		return err
	}
	if p.Amd64 == nil && p.Arm64 == nil {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "at least one architecture (amd64 or arm64) must be specified")
	}
	for _, arch := range []*pm.AgentUpdateArch{p.Amd64, p.Arm64} {
		if arch == nil {
			continue
		}
		if !strings.HasPrefix(arch.BinaryUrl, "https://") {
			return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "binary_url must use HTTPS")
		}
		if !strings.HasPrefix(arch.ChecksumUrl, "https://") {
			return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "checksum_url must use HTTPS")
		}
	}
	return nil
}

// CreateAction creates a new action (single executable).
func (h *ActionHandler) CreateAction(ctx context.Context, req *connect.Request[pm.CreateActionRequest]) (*connect.Response[pm.CreateActionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if err := validateCreateActionParams(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	params, err := serializeProtoParams(extractCreateActionParamsMsg(req.Msg))
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, err.Error())
	}

	// Auto-assign priority for SSHD actions based on creation order
	if req.Msg.Type == pm.ActionType_ACTION_TYPE_SSHD {
		count, countErr := h.store.Queries().CountActions(ctx, db.CountActionsParams{
			Column1: int32(pm.ActionType_ACTION_TYPE_SSHD),
		})
		if countErr != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count SSHD actions")
		}
		params["priority"] = count
	}

	id := ulid.Make().String()

	timeoutSeconds := int32(req.Msg.TimeoutSeconds)
	if timeoutSeconds <= 0 {
		timeoutSeconds = 300
	}

	eventData := map[string]any{
		"name":            req.Msg.Name,
		"description":     req.Msg.Description,
		"action_type":     int32(req.Msg.Type),
		"desired_state":   int32(req.Msg.DesiredState),
		"params":          params,
		"timeout_seconds": timeoutSeconds,
	}
	if req.Msg.Schedule != nil {
		eventData["schedule"] = scheduleToMap(req.Msg.Schedule)
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "action",
		StreamID:   id,
		EventType:  "ActionCreated",
		Data:       eventData,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to create action"); err != nil {
		return nil, err
	}

	action, err := h.store.Queries().GetActionByID(ctx, id)
	if err != nil {
		h.logger.Error("failed to get action after create", "error", err, "id", id)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action")
	}

	// Sign the action so agents can verify authenticity
	h.signAction(ctx, &action)

	h.enqueueActionReindex(ctx, action)

	return connect.NewResponse(&pm.CreateActionResponse{
		Action: h.actionToProto(action),
	}), nil
}

// GetAction returns an action by ID.
func (h *ActionHandler) GetAction(ctx context.Context, req *connect.Request[pm.GetActionRequest]) (*connect.Response[pm.GetActionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	action, err := h.store.Queries().GetActionByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrActionNotFound, "action not found")
	}

	return connect.NewResponse(&pm.GetActionResponse{
		Action: h.actionToProto(action),
	}), nil
}

// ListActions returns a paginated list of actions.
func (h *ActionHandler) ListActions(ctx context.Context, req *connect.Request[pm.ListActionsRequest]) (*connect.Response[pm.ListActionsResponse], error) {
	pageSize, offset, err := parsePagination(int32(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, err
	}

	typeFilter := int32(req.Msg.TypeFilter)

	actions, err := h.store.Queries().ListActions(ctx, db.ListActionsParams{
		Column1:        typeFilter,
		Limit:          pageSize,
		Offset:         offset,
		UnassignedOnly: req.Msg.UnassignedOnly,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list actions")
	}

	count, err := h.store.Queries().CountActions(ctx, db.CountActionsParams{
		Column1:        typeFilter,
		UnassignedOnly: req.Msg.UnassignedOnly,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count actions")
	}

	nextPageToken := buildNextPageToken(int32(len(actions)), offset, pageSize, count)

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
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Verify action exists before appending event
	if _, err := h.store.Queries().GetActionByID(ctx, req.Msg.Id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrActionNotFound, connect.CodeNotFound, "action not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "action",
		StreamID:   req.Msg.Id,
		EventType:  "ActionRenamed",
		Data: map[string]any{
			"name": req.Msg.Name,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to rename action"); err != nil {
		return nil, err
	}

	action, err := h.store.Queries().GetActionByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action")
	}

	h.enqueueActionReindex(ctx, action)

	return connect.NewResponse(&pm.UpdateActionResponse{
		Action: h.actionToProto(action),
	}), nil
}

// UpdateActionDescription updates an action's description.
func (h *ActionHandler) UpdateActionDescription(ctx context.Context, req *connect.Request[pm.UpdateActionDescriptionRequest]) (*connect.Response[pm.UpdateActionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Verify action exists before appending event
	if _, err := h.store.Queries().GetActionByID(ctx, req.Msg.Id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrActionNotFound, connect.CodeNotFound, "action not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "action",
		StreamID:   req.Msg.Id,
		EventType:  "ActionDescriptionUpdated",
		Data: map[string]any{
			"description": req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to update description"); err != nil {
		return nil, err
	}

	action, err := h.store.Queries().GetActionByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action")
	}

	h.enqueueActionReindex(ctx, action)

	return connect.NewResponse(&pm.UpdateActionResponse{
		Action: h.actionToProto(action),
	}), nil
}

// UpdateActionParams updates an action's parameters, desired state, and timeout.
func (h *ActionHandler) UpdateActionParams(ctx context.Context, req *connect.Request[pm.UpdateActionParamsRequest]) (*connect.Response[pm.UpdateActionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if err := validateUpdateActionParams(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	existing, err := h.store.Queries().GetActionByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrActionNotFound, "action not found")
	}

	params, err := serializeProtoParams(extractUpdateActionParamsMsg(req.Msg))
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, err.Error())
	}

	// Preserve server-assigned priority for SSHD actions
	if existing.ActionType == int32(pm.ActionType_ACTION_TYPE_SSHD) && existing.Params != nil {
		var existingParams map[string]any
		if json.Unmarshal(existing.Params, &existingParams) == nil {
			if p, ok := existingParams["priority"]; ok {
				params["priority"] = p
			}
		}
	}

	eventData := map[string]any{
		"params":        params,
		"desired_state": int32(req.Msg.DesiredState),
	}

	if req.Msg.TimeoutSeconds > 0 {
		eventData["timeout_seconds"] = req.Msg.TimeoutSeconds
	}
	if req.Msg.Schedule != nil {
		eventData["schedule"] = scheduleToMap(req.Msg.Schedule)
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "action",
		StreamID:   req.Msg.Id,
		EventType:  "ActionParamsUpdated",
		Data:       eventData,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to update action params"); err != nil {
		return nil, err
	}

	action, err := h.store.Queries().GetActionByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrActionNotFound, "action not found")
	}

	// Re-sign the action after params update
	h.signAction(ctx, &action)

	h.enqueueActionReindex(ctx, action)

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

	if err := h.store.Queries().UpdateActionSignature(ctx, db.UpdateActionSignatureParams{
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
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Capture cascade IDs from Valkey before deleting.
	var cascadeIDs []string
	if h.searchIdx != nil {
		cascadeIDs = h.searchIdx.GetReverseMembers(ctx, "action", req.Msg.Id)
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "action",
		StreamID:   req.Msg.Id,
		EventType:  "ActionDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to delete action"); err != nil {
		return nil, err
	}

	if h.searchIdx != nil {
		if err := h.searchIdx.EnqueueRemove(ctx, "action", req.Msg.Id, cascadeIDs); err != nil {
			h.logger.Warn("failed to enqueue search index remove", "scope", "action", "error", err)
		}
	}

	return connect.NewResponse(&pm.DeleteActionResponse{}), nil
}

// DispatchAction dispatches an action to a device.
func (h *ActionHandler) DispatchAction(ctx context.Context, req *connect.Request[pm.DispatchActionRequest]) (*connect.Response[pm.DispatchActionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.DeviceId})
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceNotFound, "device not found")
	}

	var actionType pm.ActionType
	var desiredState pm.DesiredState
	var params any // Use any to store either parsed JSON object or raw JSON
	var timeoutSeconds int32
	var actionID *string
	var actionName string
	var signature []byte
	var paramsCanonical []byte

	switch source := req.Msg.ActionSource.(type) {
	case *pm.DispatchActionRequest_ActionId:
		action, err := h.store.Queries().GetActionByID(ctx, source.ActionId)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, apiErrorCtx(ctx, ErrActionNotFound, connect.CodeNotFound, "action not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action")
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
		actionName = action.Name
		signature = action.Signature
		paramsCanonical = action.ParamsCanonical

	case *pm.DispatchActionRequest_InlineAction:
		action := source.InlineAction
		if err := validateInlineAction(ctx, action); err != nil {
			return nil, err
		}
		actionType = action.Type
		desiredState = action.DesiredState
		params, err = serializeProtoParams(extractActionParamsMsg(action))
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, fmt.Sprintf("failed to serialize inline action params: %v", err))
		}
		timeoutSeconds = action.TimeoutSeconds
		if timeoutSeconds <= 0 {
			timeoutSeconds = 300
		}

	default:
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "either action_id or inline_action is required")
	}

	id := ulid.Make().String()

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

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "execution",
		StreamID:   id,
		EventType:  "ExecutionCreated",
		Data:       eventData,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to create execution"); err != nil {
		return nil, err
	}

	// Dispatch action to device via Asynq task queue
	if h.aqClient != nil {
		paramsJSON, _ := json.Marshal(params)

		// Always re-sign with the execution ID — the agent verifies against
		// the received action ID, which is the execution ID for dispatched actions.
		if h.signer != nil {
			if sig, err := h.signer.Sign(id, int32(actionType), paramsJSON); err == nil {
				signature = sig
				paramsCanonical = paramsJSON
			}
		}

		if err := h.aqClient.EnqueueToDevice(req.Msg.DeviceId, taskqueue.TypeActionDispatch, taskqueue.ActionDispatchPayload{
			ExecutionID:     id,
			ActionType:      int32(actionType),
			DesiredState:    int32(desiredState),
			Params:          paramsJSON,
			TimeoutSeconds:  timeoutSeconds,
			Signature:       signature,
			ParamsCanonical: paramsCanonical,
		}, asynq.MaxRetry(5)); err != nil {
			h.logger.Warn("failed to enqueue action dispatch", "error", err, "execution_id", id)
		}
	}

	exec, err := h.store.Queries().GetExecutionByID(ctx, id)
	if err != nil {
		h.logger.Error("failed to get execution after creation", "error", err, "execution_id", id)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get execution")
	}

	// Enqueue execution for search indexing using already-fetched data.
	if h.searchIdx != nil {
		var execCreatedAt int64
		if exec.CreatedAt != nil {
			execCreatedAt = exec.CreatedAt.Unix()
		}
		var execDurationMs int64
		if exec.DurationMs != nil {
			execDurationMs = *exec.DurationMs
		}
		execActionID := ""
		if exec.ActionID != nil {
			execActionID = *exec.ActionID
		}
		if err := h.searchIdx.EnqueueReindex(ctx, search.ScopeExecution, exec.ID, &taskqueue.SearchEntityData{
			ActionName:     actionName,
			DeviceHostname: device.Hostname,
			Status:         exec.Status,
			Type:           exec.ActionType,
			DeviceID:       exec.DeviceID,
			CreatedAt:      execCreatedAt,
			DurationMs:     execDurationMs,
			Changed:        exec.Changed,
			DesiredState:   exec.DesiredState,
			ActionID:       execActionID,
		}); err != nil {
			h.logger.Warn("failed to enqueue execution search reindex", "error", err)
		}
	}

	h.logger.Info("action dispatched",
		"execution_id", id,
		"device_id", req.Msg.DeviceId,
		"action_type", actionType.String(),
	)

	return connect.NewResponse(&pm.DispatchActionResponse{
		Execution: h.executionToProto(exec),
	}), nil
}

// DispatchToMultiple dispatches an action to multiple devices.
func (h *ActionHandler) DispatchToMultiple(ctx context.Context, req *connect.Request[pm.DispatchToMultipleRequest]) (*connect.Response[pm.DispatchToMultipleResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
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
			h.logger.Warn("dispatch to device failed", "device_id", deviceID, "error", err)
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
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	actions, err := h.store.Queries().ListAssignedActionsForDevice(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get assigned actions")
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
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	actions, err := h.store.Queries().ListActionsInSet(ctx, req.Msg.ActionSetId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get actions in set")
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
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	actionSets, err := h.store.Queries().ListActionSetsInDefinition(ctx, req.Msg.DefinitionId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action sets in definition")
	}

	executions := make([]*pm.ActionExecution, 0)
	for _, set := range actionSets {
		actions, err := h.store.Queries().ListActionsInSet(ctx, set.ID)
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
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	devices, err := h.store.Queries().ListDevicesInGroup(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get devices in group")
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
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	exec, err := h.store.Queries().GetExecutionByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrExecutionNotFound, "execution not found")
	}

	protoExec := h.executionToProto(exec)

	// Fetch action name
	if exec.ActionID != nil {
		rows, err := h.store.Queries().GetActionNamesByIDs(ctx, []string{*exec.ActionID})
		if err == nil && len(rows) > 0 {
			protoExec.ActionName = rows[0].Name
		}
	}

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
	pageSize, offset, err := parsePagination(int32(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, err
	}

	statusFilter := ""
	if req.Msg.StatusFilter != pm.ExecutionStatus_EXECUTION_STATUS_UNSPECIFIED {
		statusFilter = statusToString(req.Msg.StatusFilter)
	}

	typeFilter := int32(req.Msg.TypeFilter)
	searchQuery := strings.TrimSpace(req.Msg.Search)

	execs, err := h.store.Queries().ListExecutions(ctx, db.ListExecutionsParams{
		Column1: req.Msg.DeviceId,
		Column2: statusFilter,
		Column3: typeFilter,
		Column4: searchQuery,
		Limit:   pageSize,
		Offset:  offset,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list executions")
	}

	count, err := h.store.Queries().CountExecutions(ctx, db.CountExecutionsParams{
		Column1: req.Msg.DeviceId,
		Column2: statusFilter,
		Column3: typeFilter,
		Column4: searchQuery,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count executions")
	}

	nextPageToken := buildNextPageToken(int32(len(execs)), offset, pageSize, count)

	protoExecs := make([]*pm.ActionExecution, len(execs))
	for i, e := range execs {
		protoExecs[i] = h.executionToProto(e)
	}

	// Batch-fetch action names to avoid N+1 queries on the client
	actionIDs := make([]string, 0, len(execs))
	for _, e := range execs {
		if e.ActionID != nil {
			actionIDs = append(actionIDs, *e.ActionID)
		}
	}
	if len(actionIDs) > 0 {
		rows, err := h.store.Queries().GetActionNamesByIDs(ctx, actionIDs)
		if err == nil {
			nameMap := make(map[string]string, len(rows))
			for _, row := range rows {
				nameMap[row.ID] = row.Name
			}
			for i, e := range execs {
				if e.ActionID != nil {
					protoExecs[i].ActionName = nameMap[*e.ActionID]
				}
			}
		}
	}

	return connect.NewResponse(&pm.ListExecutionsResponse{
		Executions:    protoExecs,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// isInstantActionType returns true if the action type is an instant action (agent-builtin, no parameters).
func isInstantActionType(t pm.ActionType) bool {
	return t == pm.ActionType_ACTION_TYPE_REBOOT || t == pm.ActionType_ACTION_TYPE_SYNC
}

// DispatchInstantAction dispatches an instant action (reboot, sync) to a device.
// Instant actions are agent-builtin and require no parameters.
func (h *ActionHandler) DispatchInstantAction(ctx context.Context, req *connect.Request[pm.DispatchInstantActionRequest]) (*connect.Response[pm.DispatchInstantActionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if !isInstantActionType(req.Msg.InstantAction) {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "invalid instant action type: "+req.Msg.InstantAction.String())
	}

	_, err = h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.DeviceId})
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceNotFound, "device not found")
	}

	var timeoutSeconds int32
	switch req.Msg.InstantAction {
	case pm.ActionType_ACTION_TYPE_REBOOT:
		timeoutSeconds = 600
	case pm.ActionType_ACTION_TYPE_SYNC:
		timeoutSeconds = 60
	}

	id := ulid.Make().String()

	eventData := map[string]any{
		"device_id":       req.Msg.DeviceId,
		"action_type":     int32(req.Msg.InstantAction),
		"desired_state":   int32(pm.DesiredState_DESIRED_STATE_PRESENT),
		"params":          map[string]any{},
		"timeout_seconds": timeoutSeconds,
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "execution",
		StreamID:   id,
		EventType:  "ExecutionCreated",
		Data:       eventData,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to create execution"); err != nil {
		return nil, err
	}

	// Dispatch instant action to device via Asynq task queue
	if h.aqClient != nil {
		if err := h.aqClient.EnqueueToDevice(req.Msg.DeviceId, taskqueue.TypeActionDispatch, taskqueue.ActionDispatchPayload{
			ExecutionID:    id,
			ActionType:     int32(req.Msg.InstantAction),
			DesiredState:   int32(pm.DesiredState_DESIRED_STATE_PRESENT),
			Params:         json.RawMessage("{}"),
			TimeoutSeconds: timeoutSeconds,
		}, asynq.MaxRetry(3)); err != nil {
			h.logger.Warn("failed to enqueue instant action dispatch", "error", err, "execution_id", id)
		}
	}

	exec, err := h.store.Queries().GetExecutionByID(ctx, id)
	if err != nil {
		h.logger.Error("failed to get execution after creation", "error", err, "execution_id", id)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get execution")
	}

	h.logger.Info("instant action dispatched",
		"execution_id", id,
		"device_id", req.Msg.DeviceId,
		"action_type", req.Msg.InstantAction.String(),
	)

	return connect.NewResponse(&pm.DispatchInstantActionResponse{
		Execution: h.executionToProto(exec),
	}), nil
}

// serializeProtoParams marshals an action params proto to the
// map[string]any shape that's stored in the event's Data field.
// Delegates to actionparams.MarshalActionParams so the wire format
// is identical for user-created and system-managed actions — both
// use EmitUnpopulated so proto3 scalar zero values cross the wire
// rather than being silently dropped. See that helper for the full
// rationale.
func serializeProtoParams(msg proto.Message) (map[string]any, error) {
	if msg == nil {
		return map[string]any{}, nil
	}
	data, err := actionparams.MarshalActionParams(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal params: %w", err)
	}
	var params map[string]any
	if err := json.Unmarshal(data, &params); err != nil {
		return nil, fmt.Errorf("unmarshal params to map: %w", err)
	}
	return params, nil
}

// extractCreateActionParamsMsg returns the concrete proto.Message from a CreateActionRequest oneof.
func extractCreateActionParamsMsg(req *pm.CreateActionRequest) proto.Message {
	switch p := req.Params.(type) {
	case *pm.CreateActionRequest_Package:
		return p.Package
	case *pm.CreateActionRequest_App:
		return p.App
	case *pm.CreateActionRequest_Flatpak:
		return p.Flatpak
	case *pm.CreateActionRequest_Shell:
		return p.Shell
	case *pm.CreateActionRequest_Service:
		return p.Service
	case *pm.CreateActionRequest_File:
		return p.File
	case *pm.CreateActionRequest_Update:
		return p.Update
	case *pm.CreateActionRequest_Repository:
		return p.Repository
	case *pm.CreateActionRequest_Directory:
		return p.Directory
	case *pm.CreateActionRequest_User:
		return p.User
	case *pm.CreateActionRequest_Ssh:
		return p.Ssh
	case *pm.CreateActionRequest_Sshd:
		return p.Sshd
	case *pm.CreateActionRequest_AdminPolicy:
		return p.AdminPolicy
	case *pm.CreateActionRequest_Lps:
		return p.Lps
	case *pm.CreateActionRequest_Encryption:
		return p.Encryption
	case *pm.CreateActionRequest_Group:
		return p.Group
	case *pm.CreateActionRequest_Wifi:
		return p.Wifi
	case *pm.CreateActionRequest_AgentUpdate:
		return p.AgentUpdate
	default:
		return nil
	}
}

// extractUpdateActionParamsMsg returns the concrete proto.Message from an UpdateActionParamsRequest oneof.
func extractUpdateActionParamsMsg(req *pm.UpdateActionParamsRequest) proto.Message {
	switch p := req.Params.(type) {
	case *pm.UpdateActionParamsRequest_Package:
		return p.Package
	case *pm.UpdateActionParamsRequest_App:
		return p.App
	case *pm.UpdateActionParamsRequest_Flatpak:
		return p.Flatpak
	case *pm.UpdateActionParamsRequest_Shell:
		return p.Shell
	case *pm.UpdateActionParamsRequest_Service:
		return p.Service
	case *pm.UpdateActionParamsRequest_File:
		return p.File
	case *pm.UpdateActionParamsRequest_Update:
		return p.Update
	case *pm.UpdateActionParamsRequest_Repository:
		return p.Repository
	case *pm.UpdateActionParamsRequest_Directory:
		return p.Directory
	case *pm.UpdateActionParamsRequest_User:
		return p.User
	case *pm.UpdateActionParamsRequest_Ssh:
		return p.Ssh
	case *pm.UpdateActionParamsRequest_Sshd:
		return p.Sshd
	case *pm.UpdateActionParamsRequest_AdminPolicy:
		return p.AdminPolicy
	case *pm.UpdateActionParamsRequest_Lps:
		return p.Lps
	case *pm.UpdateActionParamsRequest_Encryption:
		return p.Encryption
	case *pm.UpdateActionParamsRequest_Group:
		return p.Group
	case *pm.UpdateActionParamsRequest_Wifi:
		return p.Wifi
	case *pm.UpdateActionParamsRequest_AgentUpdate:
		return p.AgentUpdate
	default:
		return nil
	}
}

// extractActionParamsMsg returns the concrete proto.Message from an Action oneof.
func extractActionParamsMsg(action *pm.Action) proto.Message {
	switch p := action.Params.(type) {
	case *pm.Action_Package:
		return p.Package
	case *pm.Action_App:
		return p.App
	case *pm.Action_Flatpak:
		return p.Flatpak
	case *pm.Action_Shell:
		return p.Shell
	case *pm.Action_Service:
		return p.Service
	case *pm.Action_File:
		return p.File
	case *pm.Action_Update:
		return p.Update
	case *pm.Action_Repository:
		return p.Repository
	case *pm.Action_Directory:
		return p.Directory
	case *pm.Action_User:
		return p.User
	case *pm.Action_Ssh:
		return p.Ssh
	case *pm.Action_Sshd:
		return p.Sshd
	case *pm.Action_AdminPolicy:
		return p.AdminPolicy
	case *pm.Action_Lps:
		return p.Lps
	case *pm.Action_Encryption:
		return p.Encryption
	case *pm.Action_Group:
		return p.Group
	case *pm.Action_Wifi:
		return p.Wifi
	case *pm.Action_AgentUpdate:
		return p.AgentUpdate
	default:
		return nil
	}
}

// enqueueActionReindex enqueues a search index update for an action.
func (h *ActionHandler) enqueueActionReindex(ctx context.Context, a db.ActionsProjection) {
	desc := ""
	if a.Description != nil {
		desc = *a.Description
	}
	isCompliance := false
	var params map[string]any
	if json.Unmarshal(a.Params, &params) == nil {
		if v, ok := params["isCompliance"].(bool); ok {
			isCompliance = v
		}
	}
	var createdAt, updatedAt int64
	if a.CreatedAt != nil {
		createdAt = a.CreatedAt.Unix()
	}
	if a.UpdatedAt != nil {
		updatedAt = a.UpdatedAt.Unix()
	}
	enqueueSearchReindex(ctx, h.searchIdx, h.logger, search.ScopeAction, a.ID, &taskqueue.SearchEntityData{
		Name:         a.Name,
		Description:  desc,
		Type:         a.ActionType,
		IsCompliance: isCompliance,
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
	})
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

// scheduleToMap converts an ActionSchedule proto to a map for event storage.
func scheduleToMap(s *pm.ActionSchedule) map[string]any {
	m := map[string]any{}
	if s.Cron != "" {
		m["cron"] = s.Cron
	}
	if s.IntervalHours > 0 {
		m["interval_hours"] = s.IntervalHours
	}
	if s.RunOnAssign {
		m["run_on_assign"] = true
	}
	if s.SkipIfUnchanged {
		m["skip_if_unchanged"] = true
	}
	return m
}

// scheduleFromJSON deserializes a schedule JSONB column into an ActionSchedule proto.
func scheduleFromJSON(data []byte) *pm.ActionSchedule {
	var raw struct {
		Cron            string `json:"cron"`
		IntervalHours   int32  `json:"interval_hours"`
		RunOnAssign     bool   `json:"run_on_assign"`
		SkipIfUnchanged bool   `json:"skip_if_unchanged"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	// Empty object means no schedule configured
	if raw.Cron == "" && raw.IntervalHours == 0 && !raw.RunOnAssign && !raw.SkipIfUnchanged {
		return nil
	}
	return &pm.ActionSchedule{
		Cron:            raw.Cron,
		IntervalHours:   raw.IntervalHours,
		RunOnAssign:     raw.RunOnAssign,
		SkipIfUnchanged: raw.SkipIfUnchanged,
	}
}
