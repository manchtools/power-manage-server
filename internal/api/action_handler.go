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
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/middleware"
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
	store     *store.Store
	logger    *slog.Logger
	signer    ActionSigner
	aqClient  *taskqueue.Client // nil during Phase 2 dual-write if Valkey is not configured
	searchIdx *search.Index
}

// NewActionHandler creates a new action handler.
func NewActionHandler(st *store.Store, logger *slog.Logger, signer ActionSigner) *ActionHandler {
	return &ActionHandler{
		store:  st,
		logger: logger,
		signer: signer,
	}
}

// SetTaskQueueClient sets the Asynq client for dual-write dispatch.
func (h *ActionHandler) SetTaskQueueClient(c *taskqueue.Client) {
	h.aqClient = c
}

// SetSearchIndex sets the search index for enqueuing index updates.
func (h *ActionHandler) SetSearchIndex(idx *search.Index) {
	h.searchIdx = idx
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
	case *pm.CreateActionRequest_Systemd:
		if p.Systemd != nil {
			return Validate(ctx, p.Systemd)
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
	case *pm.CreateActionRequest_Sudo:
		if p.Sudo != nil {
			return Validate(ctx, p.Sudo)
		}
	case *pm.CreateActionRequest_Lps:
		if p.Lps != nil {
			return Validate(ctx, p.Lps)
		}
	case *pm.CreateActionRequest_Luks:
		if p.Luks != nil {
			return Validate(ctx, p.Luks)
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
	case *pm.UpdateActionParamsRequest_Systemd:
		if p.Systemd != nil {
			return Validate(ctx, p.Systemd)
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
	case *pm.UpdateActionParamsRequest_Sudo:
		if p.Sudo != nil {
			return Validate(ctx, p.Sudo)
		}
	case *pm.UpdateActionParamsRequest_Lps:
		if p.Lps != nil {
			return Validate(ctx, p.Lps)
		}
	case *pm.UpdateActionParamsRequest_Luks:
		if p.Luks != nil {
			return Validate(ctx, p.Luks)
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

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	params, err := h.serializeCreateActionParams(req.Msg)
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

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   id,
		EventType:  "ActionCreated",
		Data: map[string]any{
			"name":            req.Msg.Name,
			"description":     req.Msg.Description,
			"action_type":     int32(req.Msg.Type),
			"desired_state":   int32(req.Msg.DesiredState),
			"params":          params,
			"timeout_seconds": timeoutSeconds,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		h.logger.Error("failed to append action event", "error", err, "id", id)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to create action")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "action",
		"stream_id", id,
		"event_type", "ActionCreated",
	)

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
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrActionNotFound, connect.CodeNotFound, "action not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action")
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
			return nil, apiErrorCtx(ctx, ErrInvalidPageToken, connect.CodeInvalidArgument, "invalid page token")
		}
		offset = int32(offset64)
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
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// Verify action exists before appending event
	if _, err := h.store.Queries().GetActionByID(ctx, req.Msg.Id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrActionNotFound, connect.CodeNotFound, "action not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action")
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
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to rename action")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "action",
		"stream_id", req.Msg.Id,
		"event_type", "ActionRenamed",
	)

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

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// Verify action exists before appending event
	if _, err := h.store.Queries().GetActionByID(ctx, req.Msg.Id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrActionNotFound, connect.CodeNotFound, "action not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action")
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
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update description")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "action",
		"stream_id", req.Msg.Id,
		"event_type", "ActionDescriptionUpdated",
	)

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

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	existing, err := h.store.Queries().GetActionByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrActionNotFound, connect.CodeNotFound, "action not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action")
	}

	params, err := h.serializeUpdateActionParams(req.Msg)
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

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   req.Msg.Id,
		EventType:  "ActionParamsUpdated",
		Data:       eventData,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update action params")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "action",
		"stream_id", req.Msg.Id,
		"event_type", "ActionParamsUpdated",
	)

	action, err := h.store.Queries().GetActionByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrActionNotFound, connect.CodeNotFound, "action not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action")
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

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// Capture cascade IDs from Valkey before deleting.
	var cascadeIDs []string
	if h.searchIdx != nil {
		cascadeIDs = h.searchIdx.GetReverseMembers(ctx, "action", req.Msg.Id)
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
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to delete action")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "action",
		"stream_id", req.Msg.Id,
		"event_type", "ActionDeleted",
	)

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

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.DeviceId})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device")
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
		actionType = action.Type
		desiredState = action.DesiredState
		params = serializeActionParamsToMap(action)
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

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "execution",
		StreamID:   id,
		EventType:  "ExecutionCreated",
		Data:       eventData,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to create execution")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "execution",
		"stream_id", id,
		"event_type", "ExecutionCreated",
	)

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
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrExecutionNotFound, connect.CodeNotFound, "execution not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get execution")
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
	pageSize := int32(req.Msg.PageSize)
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50
	}

	offset := int32(0)
	if req.Msg.PageToken != "" {
		offset64, err := parsePageToken(req.Msg.PageToken)
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInvalidPageToken, connect.CodeInvalidArgument, "invalid page token")
		}
		offset = int32(offset64)
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

	var nextPageToken string
	if int32(len(execs)) == pageSize && int64(offset)+int64(pageSize) < count {
		nextPageToken = formatPageToken(int64(offset) + int64(pageSize))
	}

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

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	if !isInstantActionType(req.Msg.InstantAction) {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "invalid instant action type: "+req.Msg.InstantAction.String())
	}

	_, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.DeviceId})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device")
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

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "execution",
		StreamID:   id,
		EventType:  "ExecutionCreated",
		Data:       eventData,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to create execution")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "execution",
		"stream_id", id,
		"event_type", "ExecutionCreated",
	)

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

func (h *ActionHandler) serializeCreateActionParams(req *pm.CreateActionRequest) (map[string]any, error) {
	params := map[string]any{}

	var data []byte
	var err error

	switch p := req.Params.(type) {
	case *pm.CreateActionRequest_Package:
		data, err = protojson.Marshal(p.Package)
	case *pm.CreateActionRequest_App:
		data, err = protojson.Marshal(p.App)
	case *pm.CreateActionRequest_Flatpak:
		data, err = protojson.Marshal(p.Flatpak)
	case *pm.CreateActionRequest_Shell:
		data, err = protojson.Marshal(p.Shell)
	case *pm.CreateActionRequest_Systemd:
		data, err = protojson.Marshal(p.Systemd)
	case *pm.CreateActionRequest_File:
		data, err = protojson.Marshal(p.File)
	case *pm.CreateActionRequest_Update:
		data, err = protojson.Marshal(p.Update)
	case *pm.CreateActionRequest_Repository:
		data, err = protojson.Marshal(p.Repository)
	case *pm.CreateActionRequest_Directory:
		data, err = protojson.Marshal(p.Directory)
	case *pm.CreateActionRequest_User:
		data, err = protojson.Marshal(p.User)
	case *pm.CreateActionRequest_Ssh:
		data, err = protojson.Marshal(p.Ssh)
	case *pm.CreateActionRequest_Sshd:
		data, err = protojson.Marshal(p.Sshd)
	case *pm.CreateActionRequest_Sudo:
		data, err = protojson.Marshal(p.Sudo)
	case *pm.CreateActionRequest_Lps:
		data, err = protojson.Marshal(p.Lps)
	case *pm.CreateActionRequest_Luks:
		data, err = protojson.Marshal(p.Luks)
	case *pm.CreateActionRequest_Group:
		data, err = protojson.Marshal(p.Group)
	case *pm.CreateActionRequest_Wifi:
		data, err = protojson.Marshal(p.Wifi)
	case *pm.CreateActionRequest_AgentUpdate:
		data, err = protojson.Marshal(p.AgentUpdate)
	default:
		return params, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to marshal params: %w", err)
	}
	if err := json.Unmarshal(data, &params); err != nil {
		return nil, fmt.Errorf("failed to unmarshal params to map: %w", err)
	}

	return params, nil
}

func (h *ActionHandler) serializeUpdateActionParams(req *pm.UpdateActionParamsRequest) (map[string]any, error) {
	params := map[string]any{}

	var data []byte
	var err error

	switch p := req.Params.(type) {
	case *pm.UpdateActionParamsRequest_Package:
		data, err = protojson.Marshal(p.Package)
	case *pm.UpdateActionParamsRequest_App:
		data, err = protojson.Marshal(p.App)
	case *pm.UpdateActionParamsRequest_Flatpak:
		data, err = protojson.Marshal(p.Flatpak)
	case *pm.UpdateActionParamsRequest_Shell:
		data, err = protojson.Marshal(p.Shell)
	case *pm.UpdateActionParamsRequest_Systemd:
		data, err = protojson.Marshal(p.Systemd)
	case *pm.UpdateActionParamsRequest_File:
		data, err = protojson.Marshal(p.File)
	case *pm.UpdateActionParamsRequest_Update:
		data, err = protojson.Marshal(p.Update)
	case *pm.UpdateActionParamsRequest_Repository:
		data, err = protojson.Marshal(p.Repository)
	case *pm.UpdateActionParamsRequest_Directory:
		data, err = protojson.Marshal(p.Directory)
	case *pm.UpdateActionParamsRequest_User:
		data, err = protojson.Marshal(p.User)
	case *pm.UpdateActionParamsRequest_Ssh:
		data, err = protojson.Marshal(p.Ssh)
	case *pm.UpdateActionParamsRequest_Sshd:
		data, err = protojson.Marshal(p.Sshd)
	case *pm.UpdateActionParamsRequest_Sudo:
		data, err = protojson.Marshal(p.Sudo)
	case *pm.UpdateActionParamsRequest_Lps:
		data, err = protojson.Marshal(p.Lps)
	case *pm.UpdateActionParamsRequest_Luks:
		data, err = protojson.Marshal(p.Luks)
	case *pm.UpdateActionParamsRequest_Group:
		data, err = protojson.Marshal(p.Group)
	case *pm.UpdateActionParamsRequest_Wifi:
		data, err = protojson.Marshal(p.Wifi)
	case *pm.UpdateActionParamsRequest_AgentUpdate:
		data, err = protojson.Marshal(p.AgentUpdate)
	default:
		return params, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to marshal params: %w", err)
	}
	if err := json.Unmarshal(data, &params); err != nil {
		return nil, fmt.Errorf("failed to unmarshal params to map: %w", err)
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
	case *pm.Action_User:
		data, _ := protojson.Marshal(p.User)
		json.Unmarshal(data, &params)
	case *pm.Action_Ssh:
		data, _ := protojson.Marshal(p.Ssh)
		json.Unmarshal(data, &params)
	case *pm.Action_Sshd:
		data, _ := protojson.Marshal(p.Sshd)
		json.Unmarshal(data, &params)
	case *pm.Action_Sudo:
		data, _ := protojson.Marshal(p.Sudo)
		json.Unmarshal(data, &params)
	case *pm.Action_Lps:
		data, _ := protojson.Marshal(p.Lps)
		json.Unmarshal(data, &params)
	case *pm.Action_Luks:
		data, _ := protojson.Marshal(p.Luks)
		json.Unmarshal(data, &params)
	case *pm.Action_Wifi:
		data, _ := protojson.Marshal(p.Wifi)
		json.Unmarshal(data, &params)
	}

	return params
}

// enqueueActionReindex enqueues a search index update for an action.
func (h *ActionHandler) enqueueActionReindex(ctx context.Context, a db.ActionsProjection) {
	if h.searchIdx == nil {
		return
	}
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
	if err := h.searchIdx.EnqueueReindex(ctx, "action", a.ID, &taskqueue.SearchEntityData{
		Name:         a.Name,
		Description:  desc,
		Type:         a.ActionType,
		IsCompliance: isCompliance,
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
	}); err != nil {
		h.logger.Warn("failed to enqueue search reindex", "scope", "action", "error", err)
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
	case pm.ActionType_ACTION_TYPE_USER:
		var p pm.UserParams
		if err := protojson.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_User{User: &p}
		}
	case pm.ActionType_ACTION_TYPE_SSH:
		var p pm.SshParams
		if err := protojson.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Ssh{Ssh: &p}
		}
	case pm.ActionType_ACTION_TYPE_SSHD:
		var p pm.SshdParams
		if err := protojson.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Sshd{Sshd: &p}
		}
	case pm.ActionType_ACTION_TYPE_SUDO:
		var p pm.SudoParams
		if err := protojson.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Sudo{Sudo: &p}
		}
	case pm.ActionType_ACTION_TYPE_LPS:
		var p pm.LpsParams
		if err := protojson.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Lps{Lps: &p}
		}
	case pm.ActionType_ACTION_TYPE_LUKS:
		var p pm.LuksParams
		if err := protojson.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Luks{Luks: &p}
		}
	case pm.ActionType_ACTION_TYPE_WIFI:
		var p pm.WifiParams
		if err := protojson.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Wifi{Wifi: &p}
		}
	case pm.ActionType_ACTION_TYPE_AGENT_UPDATE:
		var p pm.AgentUpdateParams
		if err := protojson.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_AgentUpdate{AgentUpdate: &p}
		}
	}
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
