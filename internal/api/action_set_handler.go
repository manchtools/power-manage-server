package api

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// ActionSetHandler handles action set RPCs.
type ActionSetHandler struct {
	store     *store.Store
	logger    *slog.Logger
	searchIdx *search.Index
}

// NewActionSetHandler creates a new action set handler.
func NewActionSetHandler(st *store.Store, logger *slog.Logger) *ActionSetHandler {
	return &ActionSetHandler{
		store:  st,
		logger: logger,
	}
}

// SetSearchIndex sets the search index for enqueuing index updates.
func (h *ActionSetHandler) SetSearchIndex(idx *search.Index) {
	h.searchIdx = idx
}

// CreateActionSet creates a new action set.
func (h *ActionSetHandler) CreateActionSet(ctx context.Context, req *connect.Request[pm.CreateActionSetRequest]) (*connect.Response[pm.CreateActionSetResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	id := ulid.Make().String()

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "action_set",
		StreamID:   id,
		EventType:  "ActionSetCreated",
		Data: map[string]any{
			"name":        req.Msg.Name,
			"description": req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to create action set"); err != nil {
		return nil, err
	}

	set, err := h.store.Queries().GetActionSetByID(ctx, id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action set")
	}

	h.enqueueSetReindex(ctx, set)

	return connect.NewResponse(&pm.CreateActionSetResponse{
		Set: h.actionSetToProto(set),
	}), nil
}

// GetActionSet returns an action set by ID.
func (h *ActionSetHandler) GetActionSet(ctx context.Context, req *connect.Request[pm.GetActionSetRequest]) (*connect.Response[pm.GetActionSetResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	set, err := h.store.Queries().GetActionSetByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrActionSetNotFound, "action set not found")
	}

	members, err := h.store.Queries().ListActionSetMembers(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action set members")
	}

	protoMembers := make([]*pm.ActionSetMember, len(members))
	for i, m := range members {
		protoMembers[i] = &pm.ActionSetMember{
			ActionId:   m.ActionID,
			SortOrder:  m.SortOrder,
			ActionName: m.ActionName,
			ActionType: pm.ActionType(m.ActionType),
		}
	}

	return connect.NewResponse(&pm.GetActionSetResponse{
		Set:     h.actionSetToProto(set),
		Members: protoMembers,
	}), nil
}

// ListActionSets returns a paginated list of action sets.
func (h *ActionSetHandler) ListActionSets(ctx context.Context, req *connect.Request[pm.ListActionSetsRequest]) (*connect.Response[pm.ListActionSetsResponse], error) {
	pageSize, offset, err := parsePagination(int32(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, err
	}

	sets, err := h.store.Queries().ListActionSets(ctx, db.ListActionSetsParams{
		Limit:          pageSize,
		Offset:         offset,
		UnassignedOnly: req.Msg.UnassignedOnly,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list action sets")
	}

	count, err := h.store.Queries().CountActionSets(ctx, req.Msg.UnassignedOnly)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count action sets")
	}

	nextPageToken := buildNextPageToken(int32(len(sets)), offset, pageSize, count)

	protoSets := make([]*pm.ActionSet, len(sets))
	for i, s := range sets {
		protoSets[i] = h.actionSetToProto(s)
	}

	return connect.NewResponse(&pm.ListActionSetsResponse{
		Sets:          protoSets,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// RenameActionSet renames an action set.
func (h *ActionSetHandler) RenameActionSet(ctx context.Context, req *connect.Request[pm.RenameActionSetRequest]) (*connect.Response[pm.UpdateActionSetResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "action_set",
		StreamID:   req.Msg.Id,
		EventType:  "ActionSetRenamed",
		Data: map[string]any{
			"name": req.Msg.Name,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to rename action set"); err != nil {
		return nil, err
	}

	set, err := h.store.Queries().GetActionSetByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrActionSetNotFound, "action set not found")
	}

	h.enqueueSetReindex(ctx, set)

	return connect.NewResponse(&pm.UpdateActionSetResponse{
		Set: h.actionSetToProto(set),
	}), nil
}

// UpdateActionSetDescription updates an action set's description.
func (h *ActionSetHandler) UpdateActionSetDescription(ctx context.Context, req *connect.Request[pm.UpdateActionSetDescriptionRequest]) (*connect.Response[pm.UpdateActionSetResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "action_set",
		StreamID:   req.Msg.Id,
		EventType:  "ActionSetDescriptionUpdated",
		Data: map[string]any{
			"description": req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to update description"); err != nil {
		return nil, err
	}

	set, err := h.store.Queries().GetActionSetByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrActionSetNotFound, "action set not found")
	}

	h.enqueueSetReindex(ctx, set)

	return connect.NewResponse(&pm.UpdateActionSetResponse{
		Set: h.actionSetToProto(set),
	}), nil
}

// DeleteActionSet deletes an action set.
func (h *ActionSetHandler) DeleteActionSet(ctx context.Context, req *connect.Request[pm.DeleteActionSetRequest]) (*connect.Response[pm.DeleteActionSetResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	var cascadeIDs []string
	if h.searchIdx != nil {
		cascadeIDs = h.searchIdx.GetReverseMembers(ctx, "action_set", req.Msg.Id)
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "action_set",
		StreamID:   req.Msg.Id,
		EventType:  "ActionSetDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to delete action set"); err != nil {
		return nil, err
	}

	if h.searchIdx != nil {
		if err := h.searchIdx.EnqueueRemove(ctx, "action_set", req.Msg.Id, cascadeIDs); err != nil {
			h.logger.Warn("failed to enqueue search index remove", "scope", "action_set", "error", err)
		}
	}

	return connect.NewResponse(&pm.DeleteActionSetResponse{}), nil
}

// AddActionToSet adds an action to a set.
func (h *ActionSetHandler) AddActionToSet(ctx context.Context, req *connect.Request[pm.AddActionToSetRequest]) (*connect.Response[pm.AddActionToSetResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Verify set exists
	_, err = h.store.Queries().GetActionSetByID(ctx, req.Msg.SetId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrActionSetNotFound, "action set not found")
	}

	// Verify action exists
	action, err := h.store.Queries().GetActionByID(ctx, req.Msg.ActionId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrActionNotFound, "action not found")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "action_set",
		StreamID:   req.Msg.SetId,
		EventType:  "ActionSetMemberAdded",
		Data: map[string]any{
			"action_id":  req.Msg.ActionId,
			"sort_order": req.Msg.SortOrder,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to add action to set"); err != nil {
		return nil, err
	}

	set, err := h.store.Queries().GetActionSetByID(ctx, req.Msg.SetId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action set")
	}

	if h.searchIdx != nil {
		if err := h.searchIdx.EnqueueMemberAdded(ctx, "action_set", req.Msg.SetId, "action", req.Msg.ActionId, action.Name); err != nil {
			h.logger.Warn("failed to enqueue search member added", "scope", "action_set", "error", err)
		}
	}

	return connect.NewResponse(&pm.AddActionToSetResponse{
		Set: h.actionSetToProto(set),
	}), nil
}

// RemoveActionFromSet removes an action from a set.
func (h *ActionSetHandler) RemoveActionFromSet(ctx context.Context, req *connect.Request[pm.RemoveActionFromSetRequest]) (*connect.Response[pm.RemoveActionFromSetResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "action_set",
		StreamID:   req.Msg.SetId,
		EventType:  "ActionSetMemberRemoved",
		Data: map[string]any{
			"action_id": req.Msg.ActionId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to remove action from set"); err != nil {
		return nil, err
	}

	set, err := h.store.Queries().GetActionSetByID(ctx, req.Msg.SetId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrActionSetNotFound, "action set not found")
	}

	if h.searchIdx != nil {
		if err := h.searchIdx.EnqueueMemberRemoved(ctx, "action_set", req.Msg.SetId, "action", req.Msg.ActionId, ""); err != nil {
			h.logger.Warn("failed to enqueue search member removed", "scope", "action_set", "error", err)
		}
	}

	return connect.NewResponse(&pm.RemoveActionFromSetResponse{
		Set: h.actionSetToProto(set),
	}), nil
}

// ReorderActionInSet changes the order of an action in a set.
func (h *ActionSetHandler) ReorderActionInSet(ctx context.Context, req *connect.Request[pm.ReorderActionInSetRequest]) (*connect.Response[pm.ReorderActionInSetResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "action_set",
		StreamID:   req.Msg.SetId,
		EventType:  "ActionSetMemberReordered",
		Data: map[string]any{
			"action_id":  req.Msg.ActionId,
			"sort_order": req.Msg.NewOrder,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to reorder action in set"); err != nil {
		return nil, err
	}

	set, err := h.store.Queries().GetActionSetByID(ctx, req.Msg.SetId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrActionSetNotFound, "action set not found")
	}

	return connect.NewResponse(&pm.ReorderActionInSetResponse{
		Set: h.actionSetToProto(set),
	}), nil
}

// enqueueSetReindex enqueues a search index update for an action set.
func (h *ActionSetHandler) enqueueSetReindex(ctx context.Context, s db.ActionSetsProjection) {
	if h.searchIdx == nil {
		return
	}
	var createdAt, updatedAt int64
	if s.CreatedAt != nil {
		createdAt = s.CreatedAt.Unix()
	}
	if s.UpdatedAt != nil {
		updatedAt = s.UpdatedAt.Unix()
	}
	if err := h.searchIdx.EnqueueReindex(ctx, "action_set", s.ID, &taskqueue.SearchEntityData{
		Name:        s.Name,
		Description: s.Description,
		MemberCount: s.MemberCount,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}); err != nil {
		h.logger.Warn("failed to enqueue search reindex", "scope", "action_set", "error", err)
	}
}

func (h *ActionSetHandler) actionSetToProto(s db.ActionSetsProjection) *pm.ActionSet {
	set := &pm.ActionSet{
		Id:          s.ID,
		Name:        s.Name,
		Description: s.Description,
		MemberCount: s.MemberCount,
		CreatedBy:   s.CreatedBy,
	}

	if s.CreatedAt != nil {
		set.CreatedAt = timestamppb.New(*s.CreatedAt)
	}

	if s.UpdatedAt != nil {
		set.UpdatedAt = timestamppb.New(*s.UpdatedAt)
	}

	return set
}
