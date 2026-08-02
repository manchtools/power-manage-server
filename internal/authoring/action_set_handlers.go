package authoring

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
)

// CreateActionSet writes one independently scheduled and failure-governed set.
func (h *Handlers) CreateActionSet(ctx context.Context, req *connect.Request[pmv1.CreateActionSetRequest]) (*connect.Response[pmv1.CreateActionSetResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "CreateActionSet", ""); err != nil {
		return nil, err
	}
	row, err := h.state.CreateActionSet(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceCreateActionSetProcedure, "CreateActionSet"), CreateActionSetParams{
		Name: req.Msg.Name, Description: req.Msg.Description, CreatedBy: actor.ID,
		Schedule: req.Msg.Schedule, OnFailure: req.Msg.OnFailure,
	})
	if err != nil {
		return nil, h.actionSetError(ctx, "create action set", err)
	}
	set, err := ActionSetToProto(row, 0)
	if err != nil {
		return nil, h.internal(ctx, "encode created action set", err)
	}
	return connect.NewResponse(&pmv1.CreateActionSetResponse{Set: set}), nil
}

// GetActionSet returns one visible set and its live ordered members.
func (h *Handlers) GetActionSet(ctx context.Context, req *connect.Request[pmv1.GetActionSetRequest]) (*connect.Response[pmv1.GetActionSetResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "GetActionSet", req.Msg.Id); err != nil {
		return nil, err
	}
	row, err := h.operatorActionSet(ctx, req.Msg.Id)
	if err != nil {
		return nil, err
	}
	if err := h.enforceActionSetReadScope(ctx, req.Msg.Id); err != nil {
		return nil, err
	}
	members, err := h.store.ListActionSetMembers(ctx, req.Msg.Id)
	if err != nil {
		return nil, h.internal(ctx, "list action set members", err)
	}
	set, err := ActionSetToProto(row, int64(len(members)))
	if err != nil {
		return nil, h.internal(ctx, "encode action set", err)
	}
	return connect.NewResponse(&pmv1.GetActionSetResponse{
		Set: set, Members: ActionSetMembersToProto(members),
	}), nil
}

// ListActionSets returns a deterministic PostgreSQL keyset page.
func (h *Handlers) ListActionSets(ctx context.Context, req *connect.Request[pmv1.ListActionSetsRequest]) (*connect.Response[pmv1.ListActionSetsResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "ListActionSets", ""); err != nil {
		return nil, err
	}
	if !validPageToken(req.Msg.PageToken) {
		return nil, authoringRPCError(ctx, errInvalidPageToken, connect.CodeInvalidArgument, "invalid page token")
	}
	limit := req.Msg.PageSize
	if limit == 0 {
		limit = defaultAuthoringPageSize
	}
	groupIDs, restricted := auth.ObjectScopeListFilter(ctx)
	filter := store.ActionSetListFilter{
		AfterID: req.Msg.PageToken, Limit: limit + 1,
		UnassignedOnly: req.Msg.UnassignedOnly, ScopeRestricted: restricted,
		ScopeGroupIDs: groupIDs,
	}
	views, err := h.store.ListAuthoringActionSets(ctx, filter)
	if err != nil {
		return nil, h.internal(ctx, "list action sets", err)
	}
	hasMore := len(views) > int(limit)
	if hasMore {
		views = views[:limit]
	}
	total, err := h.store.CountAuthoringActionSets(ctx, filter)
	if err != nil {
		return nil, h.internal(ctx, "count action sets", err)
	}
	sets := make([]*pmv1.ActionSet, len(views))
	for i, view := range views {
		sets[i], err = ActionSetToProto(view.ActionSetRow, view.MemberCount)
		if err != nil {
			return nil, h.internal(ctx, "encode listed action set", err)
		}
	}
	next := ""
	if hasMore {
		next = views[len(views)-1].ID
	}
	return connect.NewResponse(&pmv1.ListActionSetsResponse{
		Sets: sets, NextPageToken: next, TotalCount: boundedCount(total),
	}), nil
}

// RenameActionSet replaces a set name.
func (h *Handlers) RenameActionSet(ctx context.Context, req *connect.Request[pmv1.RenameActionSetRequest]) (*connect.Response[pmv1.UpdateActionSetResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActionSetActor(ctx, req.Msg.Id, "RenameActionSet")
	if err != nil {
		return nil, err
	}
	row, err := h.state.RenameActionSet(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceRenameActionSetProcedure, "RenameActionSet"), req.Msg.Id, req.Msg.Name)
	return h.updatedActionSet(ctx, "rename action set", row, err)
}

// UpdateActionSetDescription replaces a set description.
func (h *Handlers) UpdateActionSetDescription(ctx context.Context, req *connect.Request[pmv1.UpdateActionSetDescriptionRequest]) (*connect.Response[pmv1.UpdateActionSetResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActionSetActor(ctx, req.Msg.Id, "UpdateActionSetDescription")
	if err != nil {
		return nil, err
	}
	row, err := h.state.UpdateActionSetDescription(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceUpdateActionSetDescriptionProcedure, "UpdateActionSetDescription"),
		req.Msg.Id, req.Msg.Description)
	return h.updatedActionSet(ctx, "update action set description", row, err)
}

// UpdateActionSetSchedule replaces the set schedule and failure policy.
func (h *Handlers) UpdateActionSetSchedule(ctx context.Context, req *connect.Request[pmv1.UpdateActionSetScheduleRequest]) (*connect.Response[pmv1.UpdateActionSetResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActionSetActor(ctx, req.Msg.Id, "UpdateActionSetSchedule")
	if err != nil {
		return nil, err
	}
	row, err := h.state.UpdateActionSetPolicy(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceUpdateActionSetScheduleProcedure, "UpdateActionSetSchedule"),
		req.Msg.Id, req.Msg.Schedule, req.Msg.OnFailure)
	return h.updatedActionSet(ctx, "update action set policy", row, err)
}

// DeleteActionSet soft-deletes a set and removes its composition edges.
func (h *Handlers) DeleteActionSet(ctx context.Context, req *connect.Request[pmv1.DeleteActionSetRequest]) (*connect.Response[pmv1.DeleteActionSetResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActionSetActor(ctx, req.Msg.Id, "DeleteActionSet")
	if err != nil {
		return nil, err
	}
	if err := h.state.DeleteActionSet(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceDeleteActionSetProcedure, "DeleteActionSet"), req.Msg.Id); err != nil {
		return nil, h.actionSetError(ctx, "delete action set", err)
	}
	return connect.NewResponse(&pmv1.DeleteActionSetResponse{}), nil
}

// AddActionToSet adds one visible, ordinary Action occurrence to a set.
func (h *Handlers) AddActionToSet(ctx context.Context, req *connect.Request[pmv1.AddActionToSetRequest]) (*connect.Response[pmv1.AddActionToSetResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActionSetActor(ctx, req.Msg.SetId, "AddActionToSet")
	if err != nil {
		return nil, err
	}
	if err := h.enforceActionReadScope(ctx, req.Msg.ActionId); err != nil {
		return nil, err
	}
	action, err := h.store.GetManifestAction(ctx, req.Msg.ActionId)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, authoringNotFound(ctx, errActionNotFound, "action not found")
		}
		return nil, h.internal(ctx, "read action set member", err)
	}
	if action.IsSystem {
		return nil, h.actionError(ctx, "reject system action membership", ErrSystemAction)
	}
	if err := h.state.AddActionToSet(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceAddActionToSetProcedure, "AddActionToSet"),
		req.Msg.SetId, req.Msg.ActionId, req.Msg.SortOrder); err != nil {
		return nil, h.addActionToSetError(ctx, req.Msg.SetId, req.Msg.ActionId, err)
	}
	set, err := h.actionSetResponse(ctx, req.Msg.SetId)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.AddActionToSetResponse{Set: set}), nil
}

// RemoveActionFromSet removes one occurrence edge.
func (h *Handlers) RemoveActionFromSet(ctx context.Context, req *connect.Request[pmv1.RemoveActionFromSetRequest]) (*connect.Response[pmv1.RemoveActionFromSetResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActionSetActor(ctx, req.Msg.SetId, "RemoveActionFromSet")
	if err != nil {
		return nil, err
	}
	if err := h.state.RemoveActionFromSet(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceRemoveActionFromSetProcedure, "RemoveActionFromSet"),
		req.Msg.SetId, req.Msg.ActionId); err != nil {
		return nil, h.actionSetError(ctx, "remove action from set", err)
	}
	set, err := h.actionSetResponse(ctx, req.Msg.SetId)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.RemoveActionFromSetResponse{Set: set}), nil
}

// ReorderActionInSet replaces one occurrence's authored position.
func (h *Handlers) ReorderActionInSet(ctx context.Context, req *connect.Request[pmv1.ReorderActionInSetRequest]) (*connect.Response[pmv1.ReorderActionInSetResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActionSetActor(ctx, req.Msg.SetId, "ReorderActionInSet")
	if err != nil {
		return nil, err
	}
	if err := h.state.ReorderActionInSet(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceReorderActionInSetProcedure, "ReorderActionInSet"),
		req.Msg.SetId, req.Msg.ActionId, req.Msg.NewOrder); err != nil {
		return nil, h.actionSetError(ctx, "reorder action in set", err)
	}
	set, err := h.actionSetResponse(ctx, req.Msg.SetId)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.ReorderActionInSetResponse{Set: set}), nil
}

func (h *Handlers) actionSetError(ctx context.Context, operation string, err error) error {
	switch {
	case errors.Is(err, ErrInvalidInput):
		return authoringRPCError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid action set")
	case errors.Is(err, ErrAlreadyMember):
		return authoringRPCError(ctx, errActionAlreadyInSet, connect.CodeAlreadyExists, "action is already in the set")
	case errors.Is(err, ErrMemberNotFound):
		return authoringNotFound(ctx, errActionSetMemberNotFound, "action set member not found")
	case errors.Is(err, ErrSystemAction):
		return h.actionError(ctx, operation, err)
	case store.IsNotFound(err):
		return authoringNotFound(ctx, errActionSetNotFound, "action set not found")
	default:
		return h.internal(ctx, operation, err)
	}
}

func (h *Handlers) addActionToSetError(ctx context.Context, setID, actionID string, err error) error {
	if !store.IsNotFound(err) {
		return h.actionSetError(ctx, "add action to set", err)
	}
	if _, setErr := h.store.GetManifestActionSet(ctx, setID); setErr != nil {
		if store.IsNotFound(setErr) {
			return authoringNotFound(ctx, errActionSetNotFound, "action set not found")
		}
		return h.internal(ctx, "classify missing action set member target", setErr)
	}
	if _, actionErr := h.store.GetManifestAction(ctx, actionID); actionErr != nil {
		if store.IsNotFound(actionErr) {
			return authoringNotFound(ctx, errActionNotFound, "action not found")
		}
		return h.internal(ctx, "classify missing action set member", actionErr)
	}
	return h.internal(ctx, "add action to set", err)
}

func (h *Handlers) operatorActionSet(ctx context.Context, id string) (store.ActionSetRow, error) {
	row, err := h.store.GetManifestActionSet(ctx, id)
	if err != nil {
		if store.IsNotFound(err) {
			return store.ActionSetRow{}, authoringNotFound(ctx, errActionSetNotFound, "action set not found")
		}
		return store.ActionSetRow{}, h.internal(ctx, "read action set", err)
	}
	return row, nil
}

func (h *Handlers) enforceActionSetReadScope(ctx context.Context, id string) error {
	callerGroups, restricted := auth.ObjectScopeListFilter(ctx)
	if !restricted {
		return nil
	}
	objectGroups, err := h.effectiveActionSetScopeGroups(ctx, id)
	if err != nil {
		return h.internal(ctx, "resolve action set read scope", err)
	}
	if !groupsOverlap(callerGroups, objectGroups) {
		h.logger.Warn("out-of-scope action set read denied", "action_set_id", id)
		return authoringNotFound(ctx, errActionSetNotFound, "action set not found")
	}
	return nil
}

func (h *Handlers) enforceActionSetWriteScope(ctx context.Context, id string) error {
	callerGroups, restricted := auth.ObjectScopeListFilter(ctx)
	if !restricted {
		return nil
	}
	objectGroups, err := h.directScopeGroups(ctx, "action_set", id)
	if err != nil {
		return h.internal(ctx, "resolve action set write scope", err)
	}
	if !groupsOverlap(callerGroups, objectGroups) {
		h.logger.Warn("out-of-scope action set mutation denied", "action_set_id", id)
		return authoringRPCError(ctx, errPermissionDenied, connect.CodePermissionDenied, "permission denied")
	}
	return nil
}

func (h *Handlers) mutationActionSetActor(ctx context.Context, id, permission string) (*auth.UserContext, error) {
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, permission, id); err != nil {
		return nil, err
	}
	if err := h.enforceActionSetWriteScope(ctx, id); err != nil {
		return nil, err
	}
	if _, err := h.operatorActionSet(ctx, id); err != nil {
		return nil, err
	}
	return actor, nil
}

func (h *Handlers) updatedActionSet(ctx context.Context, operation string, row store.ActionSetRow, err error) (*connect.Response[pmv1.UpdateActionSetResponse], error) {
	if err != nil {
		return nil, h.actionSetError(ctx, operation, err)
	}
	members, err := h.store.ListActionSetMembers(ctx, row.ID)
	if err != nil {
		return nil, h.internal(ctx, "count updated action set members", err)
	}
	set, err := ActionSetToProto(row, int64(len(members)))
	if err != nil {
		return nil, h.internal(ctx, "encode updated action set", err)
	}
	return connect.NewResponse(&pmv1.UpdateActionSetResponse{Set: set}), nil
}

func (h *Handlers) actionSetResponse(ctx context.Context, id string) (*pmv1.ActionSet, error) {
	row, err := h.store.GetManifestActionSet(ctx, id)
	if err != nil {
		return nil, h.actionSetError(ctx, "read changed action set", err)
	}
	members, err := h.store.ListActionSetMembers(ctx, id)
	if err != nil {
		return nil, h.internal(ctx, "count changed action set members", err)
	}
	set, err := ActionSetToProto(row, int64(len(members)))
	if err != nil {
		return nil, h.internal(ctx, "encode changed action set", err)
	}
	return set, nil
}
