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

// DefinitionHandler handles definition (collection of action sets) RPCs.
type DefinitionHandler struct {
	store   *store.Store
	entropy *ulid.MonotonicEntropy
}

// NewDefinitionHandler creates a new definition handler.
func NewDefinitionHandler(st *store.Store) *DefinitionHandler {
	return &DefinitionHandler{
		store:   st,
		entropy: ulid.Monotonic(rand.Reader, 0),
	}
}

// CreateDefinition creates a new definition.
func (h *DefinitionHandler) CreateDefinition(ctx context.Context, req *connect.Request[pm.CreateDefinitionRequest]) (*connect.Response[pm.CreateDefinitionResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	id := ulid.MustNew(ulid.Timestamp(time.Now()), h.entropy).String()

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "definition",
		StreamID:   id,
		EventType:  "DefinitionCreated",
		Data: map[string]any{
			"name":        req.Msg.Name,
			"description": req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create definition"))
	}

	def, err := h.store.Queries().GetDefinitionByID(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get definition"))
	}

	return connect.NewResponse(&pm.CreateDefinitionResponse{
		Definition: h.definitionToProto(def),
	}), nil
}

// GetDefinition returns a definition by ID.
func (h *DefinitionHandler) GetDefinition(ctx context.Context, req *connect.Request[pm.GetDefinitionRequest]) (*connect.Response[pm.GetDefinitionResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	def, err := h.store.Queries().GetDefinitionByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("definition not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get definition"))
	}

	members, err := h.store.Queries().ListDefinitionMembers(ctx, req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get definition members"))
	}

	protoMembers := make([]*pm.DefinitionMember, len(members))
	for i, m := range members {
		protoMembers[i] = &pm.DefinitionMember{
			ActionSetId: m.ActionSetID,
			SortOrder:   m.SortOrder,
		}
	}

	return connect.NewResponse(&pm.GetDefinitionResponse{
		Definition: h.definitionToProto(def),
		Members:    protoMembers,
	}), nil
}

// ListDefinitions returns a paginated list of definitions.
func (h *DefinitionHandler) ListDefinitions(ctx context.Context, req *connect.Request[pm.ListDefinitionsRequest]) (*connect.Response[pm.ListDefinitionsResponse], error) {
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

	defs, err := h.store.Queries().ListDefinitions(ctx, db.ListDefinitionsParams{
		Limit:  pageSize,
		Offset: offset,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list definitions"))
	}

	count, err := h.store.Queries().CountDefinitions(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to count definitions"))
	}

	var nextPageToken string
	if int32(len(defs)) == pageSize && int64(offset)+int64(pageSize) < count {
		nextPageToken = formatPageToken(int64(offset) + int64(pageSize))
	}

	protoDefs := make([]*pm.Definition, len(defs))
	for i, d := range defs {
		protoDefs[i] = h.definitionToProto(d)
	}

	return connect.NewResponse(&pm.ListDefinitionsResponse{
		Definitions:   protoDefs,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// RenameDefinition renames a definition.
func (h *DefinitionHandler) RenameDefinition(ctx context.Context, req *connect.Request[pm.RenameDefinitionRequest]) (*connect.Response[pm.UpdateDefinitionResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "definition",
		StreamID:   req.Msg.Id,
		EventType:  "DefinitionRenamed",
		Data: map[string]any{
			"name": req.Msg.Name,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to rename definition"))
	}

	def, err := h.store.Queries().GetDefinitionByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("definition not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get definition"))
	}

	return connect.NewResponse(&pm.UpdateDefinitionResponse{
		Definition: h.definitionToProto(def),
	}), nil
}

// UpdateDefinitionDescription updates a definition's description.
func (h *DefinitionHandler) UpdateDefinitionDescription(ctx context.Context, req *connect.Request[pm.UpdateDefinitionDescriptionRequest]) (*connect.Response[pm.UpdateDefinitionResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "definition",
		StreamID:   req.Msg.Id,
		EventType:  "DefinitionDescriptionUpdated",
		Data: map[string]any{
			"description": req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update description"))
	}

	def, err := h.store.Queries().GetDefinitionByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("definition not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get definition"))
	}

	return connect.NewResponse(&pm.UpdateDefinitionResponse{
		Definition: h.definitionToProto(def),
	}), nil
}

// DeleteDefinition deletes a definition.
func (h *DefinitionHandler) DeleteDefinition(ctx context.Context, req *connect.Request[pm.DeleteDefinitionRequest]) (*connect.Response[pm.DeleteDefinitionResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "definition",
		StreamID:   req.Msg.Id,
		EventType:  "DefinitionDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete definition"))
	}

	return connect.NewResponse(&pm.DeleteDefinitionResponse{}), nil
}

// AddActionSetToDefinition adds an action set to a definition.
func (h *DefinitionHandler) AddActionSetToDefinition(ctx context.Context, req *connect.Request[pm.AddActionSetToDefinitionRequest]) (*connect.Response[pm.AddActionSetToDefinitionResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Verify definition exists
	_, err := h.store.Queries().GetDefinitionByID(ctx, req.Msg.DefinitionId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("definition not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get definition"))
	}

	// Verify action set exists
	_, err = h.store.Queries().GetActionSetByID(ctx, req.Msg.ActionSetId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("action set not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action set"))
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "definition",
		StreamID:   req.Msg.DefinitionId,
		EventType:  "DefinitionMemberAdded",
		Data: map[string]any{
			"action_set_id": req.Msg.ActionSetId,
			"sort_order":    req.Msg.SortOrder,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to add action set to definition"))
	}

	def, err := h.store.Queries().GetDefinitionByID(ctx, req.Msg.DefinitionId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get definition"))
	}

	return connect.NewResponse(&pm.AddActionSetToDefinitionResponse{
		Definition: h.definitionToProto(def),
	}), nil
}

// RemoveActionSetFromDefinition removes an action set from a definition.
func (h *DefinitionHandler) RemoveActionSetFromDefinition(ctx context.Context, req *connect.Request[pm.RemoveActionSetFromDefinitionRequest]) (*connect.Response[pm.RemoveActionSetFromDefinitionResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "definition",
		StreamID:   req.Msg.DefinitionId,
		EventType:  "DefinitionMemberRemoved",
		Data: map[string]any{
			"action_set_id": req.Msg.ActionSetId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to remove action set from definition"))
	}

	def, err := h.store.Queries().GetDefinitionByID(ctx, req.Msg.DefinitionId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("definition not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get definition"))
	}

	return connect.NewResponse(&pm.RemoveActionSetFromDefinitionResponse{
		Definition: h.definitionToProto(def),
	}), nil
}

// ReorderActionSetInDefinition changes the order of an action set in a definition.
func (h *DefinitionHandler) ReorderActionSetInDefinition(ctx context.Context, req *connect.Request[pm.ReorderActionSetInDefinitionRequest]) (*connect.Response[pm.ReorderActionSetInDefinitionResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "definition",
		StreamID:   req.Msg.DefinitionId,
		EventType:  "DefinitionMemberReordered",
		Data: map[string]any{
			"action_set_id": req.Msg.ActionSetId,
			"sort_order":    req.Msg.NewOrder,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to reorder action set in definition"))
	}

	def, err := h.store.Queries().GetDefinitionByID(ctx, req.Msg.DefinitionId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("definition not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get definition"))
	}

	return connect.NewResponse(&pm.ReorderActionSetInDefinitionResponse{
		Definition: h.definitionToProto(def),
	}), nil
}

func (h *DefinitionHandler) definitionToProto(d db.DefinitionsProjection) *pm.Definition {
	def := &pm.Definition{
		Id:          d.ID,
		Name:        d.Name,
		Description: d.Description,
		MemberCount: d.MemberCount,
		CreatedBy:   d.CreatedBy,
	}

	if d.CreatedAt.Valid {
		def.CreatedAt = timestamppb.New(d.CreatedAt.Time)
	}

	return def
}
