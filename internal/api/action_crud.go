// Package api file action_crud.go — single-action CRUD RPC handlers
// extracted from action_handler.go (audit F005): Create / Get /
// List / Rename / UpdateDescription / UpdateParams / Delete plus
// the per-action signature lifecycle helpers (compute / persist /
// rollback). Dispatch / executions live in action_dispatch.go.
package api

import (
	"context"
	"encoding/json"
	"errors"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

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

	// Compute the signature BEFORE writing the ActionCreated event.
	// If signing fails, no projection row ever appears, and the
	// caller sees a clean error. Previously the order was
	// appendEvent → sign, which left an unsigned row in the DB on
	// any signer failure — lower severity than the dispatch fake-
	// send issue but still an operator-confusing state.
	paramsJSON, marshalErr := json.Marshal(params)
	if marshalErr != nil {
		h.logger.Error("create: failed to marshal params for signing", "action_id", id, "error", marshalErr)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to marshal action params")
	}
	sig, paramsCanonical, err := h.computeActionSignature(ctx, id, int32(req.Msg.Type), paramsJSON)
	if err != nil {
		return nil, err
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
		EventType:  string(eventtypes.ActionCreated),
		Data:       eventData,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to create action"); err != nil {
		return nil, err
	}

	action, err := h.store.Queries().GetActionByID(ctx, id)
	if err != nil {
		h.logger.Error("failed to get action after create", "error", err, "id", id)
		// Projection row may already exist without signature; roll
		// it back so the operator doesn't see an unsigned row.
		h.rollbackUnsignedCreate(ctx, userCtx.ID, id)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action")
	}

	// Persist the precomputed signature. Narrow failure window: if
	// this UPDATE fails after the event+projection succeeded, emit
	// a compensating ActionDeleted so the unsigned row does not
	// linger. See rollbackUnsignedCreate for the best-effort notes.
	if err := h.persistActionSignature(ctx, &action, sig, paramsCanonical); err != nil {
		h.rollbackUnsignedCreate(ctx, userCtx.ID, id)
		return nil, err
	}

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
		EventType:  string(eventtypes.ActionRenamed),
		Data: payloads.ActionRenamed{
			Name: req.Msg.Name,
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
		EventType:  string(eventtypes.ActionDescriptionUpdated),
		Data: payloads.ActionDescriptionUpdated{
			Description: &req.Msg.Description,
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

	// Compute the re-signature BEFORE writing ActionParamsUpdated.
	// If signing fails the old event is never written, so the
	// projection still carries the old (valid) signature matching
	// the old params — a consistent state. Computing after the
	// event used to leave the row with NEW params but OLD
	// signature, which the agent rejects on dispatch.
	paramsJSON, marshalErr := json.Marshal(params)
	if marshalErr != nil {
		h.logger.Error("update: failed to marshal params for signing",
			"action_id", req.Msg.Id, "error", marshalErr)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to marshal updated action params")
	}
	sig, paramsCanonical, err := h.computeActionSignature(ctx, req.Msg.Id, existing.ActionType, paramsJSON)
	if err != nil {
		return nil, err
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
		EventType:  string(eventtypes.ActionParamsUpdated),
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

	// Persist the precomputed signature. Unlike Create, there is no
	// clean compensating event for Update — emitting "revert to
	// previous params" would need an ActionParamsReverted event type
	// the projector doesn't model. On persist failure we log loudly;
	// the row now has NEW params with the OLD signature, which the
	// agent will reject on dispatch. The operator recovers by
	// re-running Update with the same payload once the DB is
	// healthy.
	if err := h.persistActionSignature(ctx, &action, sig, paramsCanonical); err != nil {
		h.logger.Error("update: signature persist failed; row carries NEW params with OLD signature — re-run UpdateActionParams to recover",
			"action_id", req.Msg.Id)
		return nil, err
	}

	return connect.NewResponse(&pm.UpdateActionResponse{
		Action: h.actionToProto(action),
	}), nil
}

// computeActionSignature produces a signature over (id, actionType,
// paramsJSON). Pure compute — no DB access. Fail-closed on nil
// signer. Split out of the legacy signAction() so Create/Update
// can compute the signature BEFORE writing the ActionCreated /
// ActionParamsUpdated event, so a sign failure never produces an
// unsigned row in the projection.
func (h *ActionHandler) computeActionSignature(ctx context.Context, id string, actionType int32, paramsJSON []byte) ([]byte, []byte, error) {
	if h.signer == nil {
		h.logger.Error("computeActionSignature called with nil signer — wiring bug", "action_id", id)
		return nil, nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "action signer not configured")
	}
	if paramsJSON == nil {
		paramsJSON = []byte("{}")
	}
	sig, err := h.signer.Sign(id, actionType, paramsJSON)
	if err != nil {
		h.logger.Error("failed to sign action", "action_id", id, "error", err)
		return nil, nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to sign action")
	}
	return sig, paramsJSON, nil
}

// persistActionSignature writes a precomputed signature to the
// existing projection row. Intended for Create/Update after the
// event has been written: the row exists, we just backfill the
// sig + canonical params columns the projector doesn't set.
//
// On failure the row stays unsigned — callers SHOULD emit a
// compensating ActionDeleted so the operator doesn't see a broken
// unsigned row. See rollbackUnsignedCreate.
func (h *ActionHandler) persistActionSignature(ctx context.Context, action *db.ActionsProjection, sig, paramsCanonical []byte) error {
	if err := h.store.Queries().UpdateActionSignature(ctx, db.UpdateActionSignatureParams{
		ID:              action.ID,
		Signature:       sig,
		ParamsCanonical: paramsCanonical,
	}); err != nil {
		h.logger.Error("failed to store action signature", "action_id", action.ID, "error", err)
		return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to store action signature")
	}
	action.Signature = sig
	action.ParamsCanonical = paramsCanonical
	return nil
}

// rollbackUnsignedCreate emits a compensating ActionDeleted event
// when persistActionSignature fails after appendEvent(ActionCreated)
// has already landed. Best-effort: if the compensating append also
// fails, the row lingers as unsigned — logged loudly so the
// operator can clean it up manually. Either way the caller's RPC
// returns the original persist error.
func (h *ActionHandler) rollbackUnsignedCreate(ctx context.Context, userID, actionID string) {
	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "action",
		StreamID:   actionID,
		EventType:  string(eventtypes.ActionDeleted),
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userID,
	}, "failed to append compensating ActionDeleted after signature persist failure"); err != nil {
		h.logger.Error("compensating ActionDeleted failed; action row is stuck unsigned and visible in projection",
			"action_id", actionID, "error", err)
	}
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

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "action",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.ActionDeleted),
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to delete action"); err != nil {
		return nil, err
	}

	// Search index removal + cascade-rebuild of parent action_sets
	// is handled by api.SearchListener: the listener calls
	// GetReverseMembers + EnqueueRemove on ActionDeleted.

	return connect.NewResponse(&pm.DeleteActionResponse{}), nil
}
