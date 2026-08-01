package authoring

import (
	"context"

	"connectrpc.com/connect"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
)

// docref: begin explicit-action-rpcs

// CreateAction validates and writes one ordinary Action with its audit effect.
func (h *Handlers) CreateAction(ctx context.Context, req *connect.Request[pmv1.CreateActionRequest]) (*connect.Response[pmv1.CreateActionResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "CreateAction", ""); err != nil {
		return nil, err
	}
	params, err := requestParams(req.Msg, req.Msg.Type)
	if err != nil {
		return nil, h.actionError(ctx, "validate create action params", err)
	}
	row, err := h.state.CreateAction(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceCreateActionProcedure, "CreateAction"), CreateActionParams{
		Name: req.Msg.Name, Description: req.Msg.Description, CreatedBy: actor.ID,
		Type: req.Msg.Type, DesiredState: req.Msg.DesiredState, Params: params,
		TimeoutSeconds: req.Msg.TimeoutSeconds, Schedule: req.Msg.Schedule,
	})
	if err != nil {
		return nil, h.actionError(ctx, "create action", err)
	}
	action, err := actionToProto(row)
	if err != nil {
		return nil, h.internal(ctx, "encode created action", err)
	}
	return connect.NewResponse(&pmv1.CreateActionResponse{Action: action}), nil
}

// GetAction returns one operator-visible Action without revealing system or
// out-of-scope rows.
func (h *Handlers) GetAction(ctx context.Context, req *connect.Request[pmv1.GetActionRequest]) (*connect.Response[pmv1.GetActionResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "GetAction", req.Msg.Id); err != nil {
		return nil, err
	}
	row, err := h.operatorAction(ctx, req.Msg.Id)
	if err != nil {
		return nil, err
	}
	if err := h.enforceActionReadScope(ctx, req.Msg.Id); err != nil {
		return nil, err
	}
	action, err := actionToProto(row)
	if err != nil {
		return nil, h.internal(ctx, "encode action", err)
	}
	return connect.NewResponse(&pmv1.GetActionResponse{Action: action}), nil
}

// ListActions returns a deterministic PostgreSQL keyset page. Scope,
// assignment and type filters are all applied before pagination.
func (h *Handlers) ListActions(ctx context.Context, req *connect.Request[pmv1.ListActionsRequest]) (*connect.Response[pmv1.ListActionsResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "ListActions", ""); err != nil {
		return nil, err
	}
	if !validPageToken(req.Msg.PageToken) {
		return nil, authoringRPCError(ctx, errInvalidPageToken, connect.CodeInvalidArgument, "invalid page token")
	}
	if _, ok := pmv1.ActionType_name[int32(req.Msg.TypeFilter)]; !ok {
		return nil, authoringRPCError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid action type filter")
	}
	limit := req.Msg.PageSize
	if limit == 0 {
		limit = defaultAuthoringPageSize
	}
	groupIDs, restricted := auth.ObjectScopeListFilter(ctx)
	filter := store.ActionListFilter{
		AfterID: req.Msg.PageToken, Limit: limit + 1, Type: int32(req.Msg.TypeFilter),
		UnassignedOnly: req.Msg.UnassignedOnly, ScopeRestricted: restricted,
		ScopeGroupIDs: groupIDs,
	}
	rows, err := h.store.ListAuthoringActions(ctx, filter)
	if err != nil {
		return nil, h.internal(ctx, "list actions", err)
	}
	hasMore := len(rows) > int(limit)
	if hasMore {
		rows = rows[:limit]
	}
	countFilter := filter
	countFilter.AfterID = ""
	countFilter.Limit = 0
	total, err := h.store.CountAuthoringActions(ctx, countFilter)
	if err != nil {
		return nil, h.internal(ctx, "count actions", err)
	}
	actions := make([]*pmv1.ManagedAction, len(rows))
	for i := range rows {
		actions[i], err = actionToProto(rows[i])
		if err != nil {
			return nil, h.internal(ctx, "encode listed action", err)
		}
	}
	next := ""
	if hasMore {
		next = rows[len(rows)-1].ID
	}
	return connect.NewResponse(&pmv1.ListActionsResponse{
		Actions: actions, NextPageToken: next, TotalCount: boundedCount(total),
	}), nil
}

// RenameAction replaces an Action name with audited last-write-wins CRUD.
func (h *Handlers) RenameAction(ctx context.Context, req *connect.Request[pmv1.RenameActionRequest]) (*connect.Response[pmv1.UpdateActionResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActor(ctx, req.Msg.Id, "RenameAction")
	if err != nil {
		return nil, err
	}
	row, err := h.state.RenameAction(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceRenameActionProcedure, "RenameAction"), req.Msg.Id, req.Msg.Name, false)
	return h.updatedAction(ctx, "rename action", row, err)
}

// UpdateActionDescription replaces an Action description.
func (h *Handlers) UpdateActionDescription(ctx context.Context, req *connect.Request[pmv1.UpdateActionDescriptionRequest]) (*connect.Response[pmv1.UpdateActionResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActor(ctx, req.Msg.Id, "UpdateActionDescription")
	if err != nil {
		return nil, err
	}
	row, err := h.state.UpdateActionDescription(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceUpdateActionDescriptionProcedure, "UpdateActionDescription"),
		req.Msg.Id, req.Msg.Description, false)
	return h.updatedAction(ctx, "update action description", row, err)
}

// UpdateActionParams replaces the mutable execution fields while keeping the
// Action type immutable.
func (h *Handlers) UpdateActionParams(ctx context.Context, req *connect.Request[pmv1.UpdateActionParamsRequest]) (*connect.Response[pmv1.UpdateActionResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, row, err := h.mutationAction(ctx, req.Msg.Id, "UpdateActionParams")
	if err != nil {
		return nil, err
	}
	params, err := requestParams(req.Msg, pmv1.ActionType(row.ActionType))
	if err != nil {
		return nil, h.actionError(ctx, "validate updated action params", err)
	}
	updated, err := h.state.UpdateActionParams(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceUpdateActionParamsProcedure, "UpdateActionParams"), UpdateActionParams{
		ID: req.Msg.Id, DesiredState: req.Msg.DesiredState, Params: params,
		TimeoutSeconds: req.Msg.TimeoutSeconds, Schedule: req.Msg.Schedule,
	})
	return h.updatedAction(ctx, "update action params", updated, err)
}

// DeleteAction soft-deletes an Action and its composition edges atomically.
func (h *Handlers) DeleteAction(ctx context.Context, req *connect.Request[pmv1.DeleteActionRequest]) (*connect.Response[pmv1.DeleteActionResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActor(ctx, req.Msg.Id, "DeleteAction")
	if err != nil {
		return nil, err
	}
	if err := h.state.DeleteAction(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceDeleteActionProcedure, "DeleteAction"), req.Msg.Id, false); err != nil {
		return nil, h.actionError(ctx, "delete action", err)
	}
	return connect.NewResponse(&pmv1.DeleteActionResponse{}), nil
}

// docref: end explicit-action-rpcs

func (h *Handlers) operatorAction(ctx context.Context, id string) (store.ActionRow, error) {
	row, err := h.store.GetManifestAction(ctx, id)
	if err != nil {
		if store.IsNotFound(err) {
			return store.ActionRow{}, authoringNotFound(ctx, errActionNotFound, "action not found")
		}
		return store.ActionRow{}, h.internal(ctx, "read action", err)
	}
	if row.IsSystem {
		return store.ActionRow{}, authoringNotFound(ctx, errActionNotFound, "action not found")
	}
	return row, nil
}

func (h *Handlers) enforceActionReadScope(ctx context.Context, id string) error {
	callerGroups, restricted := auth.ObjectScopeListFilter(ctx)
	if !restricted {
		return nil
	}
	objectGroups, err := h.effectiveActionScopeGroups(ctx, id)
	if err != nil {
		return h.internal(ctx, "resolve action read scope", err)
	}
	if !groupsOverlap(callerGroups, objectGroups) {
		h.logger.Warn("out-of-scope action read denied", "action_id", id)
		return authoringNotFound(ctx, errActionNotFound, "action not found")
	}
	return nil
}

func (h *Handlers) enforceActionWriteScope(ctx context.Context, id string) error {
	callerGroups, restricted := auth.ObjectScopeListFilter(ctx)
	if !restricted {
		return nil
	}
	objectGroups, err := h.directScopeGroups(ctx, "action", id)
	if err != nil {
		return h.internal(ctx, "resolve action write scope", err)
	}
	if !groupsOverlap(callerGroups, objectGroups) {
		h.logger.Warn("out-of-scope action mutation denied", "action_id", id)
		return authoringRPCError(ctx, errPermissionDenied, connect.CodePermissionDenied, "permission denied")
	}
	return nil
}

func (h *Handlers) mutationAction(ctx context.Context, id, permission string) (*auth.UserContext, store.ActionRow, error) {
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, store.ActionRow{}, err
	}
	if err := h.authorize(ctx, permission, id); err != nil {
		return nil, store.ActionRow{}, err
	}
	if err := h.enforceActionWriteScope(ctx, id); err != nil {
		return nil, store.ActionRow{}, err
	}
	row, err := h.store.GetManifestAction(ctx, id)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, store.ActionRow{}, authoringNotFound(ctx, errActionNotFound, "action not found")
		}
		return nil, store.ActionRow{}, h.internal(ctx, "read action mutation target", err)
	}
	if row.IsSystem {
		return nil, store.ActionRow{}, h.actionError(ctx, "reject system action mutation", ErrSystemAction)
	}
	return actor, row, nil
}

func (h *Handlers) mutationActor(ctx context.Context, id, permission string) (*auth.UserContext, error) {
	actor, _, err := h.mutationAction(ctx, id, permission)
	return actor, err
}

func (h *Handlers) updatedAction(ctx context.Context, operation string, row store.ActionRow, err error) (*connect.Response[pmv1.UpdateActionResponse], error) {
	if err != nil {
		return nil, h.actionError(ctx, operation, err)
	}
	action, err := actionToProto(row)
	if err != nil {
		return nil, h.internal(ctx, "encode updated action", err)
	}
	return connect.NewResponse(&pmv1.UpdateActionResponse{Action: action}), nil
}
