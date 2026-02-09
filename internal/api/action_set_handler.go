package api

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// ActionSetHandler handles action set RPCs.
type ActionSetHandler struct {
	store   *store.Store
	entropy *ulid.MonotonicEntropy
}

// NewActionSetHandler creates a new action set handler.
func NewActionSetHandler(st *store.Store) *ActionSetHandler {
	return &ActionSetHandler{
		store:   st,
		entropy: ulid.Monotonic(rand.Reader, 0),
	}
}

// CreateActionSet creates a new action set.
func (h *ActionSetHandler) CreateActionSet(ctx context.Context, req *connect.Request[pm.CreateActionSetRequest]) (*connect.Response[pm.CreateActionSetResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	id := ulid.MustNew(ulid.Timestamp(time.Now()), h.entropy).String()

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
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create action set"))
	}

	set, err := h.store.QueriesFromContext(ctx).GetActionSetByID(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action set"))
	}

	return connect.NewResponse(&pm.CreateActionSetResponse{
		Set: h.actionSetToProto(set),
	}), nil
}

// GetActionSet returns an action set by ID.
func (h *ActionSetHandler) GetActionSet(ctx context.Context, req *connect.Request[pm.GetActionSetRequest]) (*connect.Response[pm.GetActionSetResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	set, err := h.store.QueriesFromContext(ctx).GetActionSetByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("action set not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action set"))
	}

	members, err := h.store.QueriesFromContext(ctx).ListActionSetMembers(ctx, req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action set members"))
	}

	protoMembers := make([]*pm.ActionSetMember, len(members))
	for i, m := range members {
		protoMembers[i] = &pm.ActionSetMember{
			ActionId:  m.ActionID,
			SortOrder: m.SortOrder,
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
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid page token"))
		}
		offset = int32(offset64)
	}

	sets, err := h.store.QueriesFromContext(ctx).ListActionSets(ctx, db.ListActionSetsParams{
		Limit:  pageSize,
		Offset: offset,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list action sets"))
	}

	count, err := h.store.QueriesFromContext(ctx).CountActionSets(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to count action sets"))
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
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
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
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to rename action set"))
	}

	set, err := h.store.QueriesFromContext(ctx).GetActionSetByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("action set not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action set"))
	}

	return connect.NewResponse(&pm.UpdateActionSetResponse{
		Set: h.actionSetToProto(set),
	}), nil
}

// UpdateActionSetDescription updates an action set's description.
func (h *ActionSetHandler) UpdateActionSetDescription(ctx context.Context, req *connect.Request[pm.UpdateActionSetDescriptionRequest]) (*connect.Response[pm.UpdateActionSetResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
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
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update description"))
	}

	set, err := h.store.QueriesFromContext(ctx).GetActionSetByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("action set not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action set"))
	}

	return connect.NewResponse(&pm.UpdateActionSetResponse{
		Set: h.actionSetToProto(set),
	}), nil
}

// DeleteActionSet deletes an action set.
func (h *ActionSetHandler) DeleteActionSet(ctx context.Context, req *connect.Request[pm.DeleteActionSetRequest]) (*connect.Response[pm.DeleteActionSetResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
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
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete action set"))
	}

	return connect.NewResponse(&pm.DeleteActionSetResponse{}), nil
}

// AddActionToSet adds an action to a set.
func (h *ActionSetHandler) AddActionToSet(ctx context.Context, req *connect.Request[pm.AddActionToSetRequest]) (*connect.Response[pm.AddActionToSetResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Verify set exists
	_, err := h.store.QueriesFromContext(ctx).GetActionSetByID(ctx, req.Msg.SetId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("action set not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action set"))
	}

	// Verify action exists
	_, err = h.store.QueriesFromContext(ctx).GetActionByID(ctx, req.Msg.ActionId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("action not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action"))
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
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to add action to set"))
	}

	set, err := h.store.QueriesFromContext(ctx).GetActionSetByID(ctx, req.Msg.SetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action set"))
	}

	return connect.NewResponse(&pm.AddActionToSetResponse{
		Set: h.actionSetToProto(set),
	}), nil
}

// RemoveActionFromSet removes an action from a set.
func (h *ActionSetHandler) RemoveActionFromSet(ctx context.Context, req *connect.Request[pm.RemoveActionFromSetRequest]) (*connect.Response[pm.RemoveActionFromSetResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
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
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to remove action from set"))
	}

	set, err := h.store.QueriesFromContext(ctx).GetActionSetByID(ctx, req.Msg.SetId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("action set not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action set"))
	}

	return connect.NewResponse(&pm.RemoveActionFromSetResponse{
		Set: h.actionSetToProto(set),
	}), nil
}

// ReorderActionInSet changes the order of an action in a set.
func (h *ActionSetHandler) ReorderActionInSet(ctx context.Context, req *connect.Request[pm.ReorderActionInSetRequest]) (*connect.Response[pm.ReorderActionInSetResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
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
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to reorder action in set"))
	}

	set, err := h.store.QueriesFromContext(ctx).GetActionSetByID(ctx, req.Msg.SetId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("action set not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action set"))
	}

	return connect.NewResponse(&pm.ReorderActionInSetResponse{
		Set: h.actionSetToProto(set),
	}), nil
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

	return set
}
