package api

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/middleware"
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

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	id := ulid.Make().String()

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "action_set",
		StreamID:   id,
		EventType:  "ActionSetCreated",
		Data: map[string]any{
			"name":        req.Msg.Name,
			"description": req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to create action set")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "action_set",
		"stream_id", id,
		"event_type", "ActionSetCreated",
	)

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
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrActionSetNotFound, connect.CodeNotFound, "action set not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action set")
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

	var nextPageToken string
	if int32(len(sets)) == pageSize && int64(offset)+int64(pageSize) < count {
		nextPageToken = formatPageToken(int64(offset) + int64(pageSize))
	}

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

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "action_set",
		StreamID:   req.Msg.Id,
		EventType:  "ActionSetRenamed",
		Data: map[string]any{
			"name": req.Msg.Name,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to rename action set")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "action_set",
		"stream_id", req.Msg.Id,
		"event_type", "ActionSetRenamed",
	)

	set, err := h.store.Queries().GetActionSetByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrActionSetNotFound, connect.CodeNotFound, "action set not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action set")
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

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "action_set",
		StreamID:   req.Msg.Id,
		EventType:  "ActionSetDescriptionUpdated",
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
		"stream_type", "action_set",
		"stream_id", req.Msg.Id,
		"event_type", "ActionSetDescriptionUpdated",
	)

	set, err := h.store.Queries().GetActionSetByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrActionSetNotFound, connect.CodeNotFound, "action set not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action set")
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

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	var cascadeIDs []string
	if h.searchIdx != nil {
		cascadeIDs = h.searchIdx.GetReverseMembers(ctx, "action_set", req.Msg.Id)
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "action_set",
		StreamID:   req.Msg.Id,
		EventType:  "ActionSetDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to delete action set")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "action_set",
		"stream_id", req.Msg.Id,
		"event_type", "ActionSetDeleted",
	)

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

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// Verify set exists
	_, err := h.store.Queries().GetActionSetByID(ctx, req.Msg.SetId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrActionSetNotFound, connect.CodeNotFound, "action set not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action set")
	}

	// Verify action exists
	action, err := h.store.Queries().GetActionByID(ctx, req.Msg.ActionId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrActionNotFound, connect.CodeNotFound, "action not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action")
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "action_set",
		StreamID:   req.Msg.SetId,
		EventType:  "ActionSetMemberAdded",
		Data: map[string]any{
			"action_id":  req.Msg.ActionId,
			"sort_order": req.Msg.SortOrder,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to add action to set")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "action_set",
		"stream_id", req.Msg.SetId,
		"event_type", "ActionSetMemberAdded",
	)

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

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "action_set",
		StreamID:   req.Msg.SetId,
		EventType:  "ActionSetMemberRemoved",
		Data: map[string]any{
			"action_id": req.Msg.ActionId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to remove action from set")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "action_set",
		"stream_id", req.Msg.SetId,
		"event_type", "ActionSetMemberRemoved",
	)

	set, err := h.store.Queries().GetActionSetByID(ctx, req.Msg.SetId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrActionSetNotFound, connect.CodeNotFound, "action set not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action set")
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

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "action_set",
		StreamID:   req.Msg.SetId,
		EventType:  "ActionSetMemberReordered",
		Data: map[string]any{
			"action_id":  req.Msg.ActionId,
			"sort_order": req.Msg.NewOrder,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to reorder action in set")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "action_set",
		"stream_id", req.Msg.SetId,
		"event_type", "ActionSetMemberReordered",
	)

	set, err := h.store.Queries().GetActionSetByID(ctx, req.Msg.SetId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrActionSetNotFound, connect.CodeNotFound, "action set not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action set")
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
	if s.CreatedAt.Valid {
		createdAt = s.CreatedAt.Time.Unix()
	}
	if s.UpdatedAt.Valid {
		updatedAt = s.UpdatedAt.Time.Unix()
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

	if s.CreatedAt.Valid {
		set.CreatedAt = timestamppb.New(s.CreatedAt.Time)
	}

	if s.UpdatedAt.Valid {
		set.UpdatedAt = timestamppb.New(s.UpdatedAt.Time)
	}

	return set
}
