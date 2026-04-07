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

// DefinitionHandler handles definition (collection of action sets) RPCs.
type DefinitionHandler struct {
	store     *store.Store
	logger    *slog.Logger
	searchIdx *search.Index
}

// NewDefinitionHandler creates a new definition handler.
func NewDefinitionHandler(st *store.Store, logger *slog.Logger) *DefinitionHandler {
	return &DefinitionHandler{
		store:  st,
		logger: logger,
	}
}

// SetSearchIndex sets the search index for enqueuing index updates.
func (h *DefinitionHandler) SetSearchIndex(idx *search.Index) {
	h.searchIdx = idx
}

// CreateDefinition creates a new definition.
func (h *DefinitionHandler) CreateDefinition(ctx context.Context, req *connect.Request[pm.CreateDefinitionRequest]) (*connect.Response[pm.CreateDefinitionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	id := ulid.Make().String()

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "definition",
		StreamID:   id,
		EventType:  "DefinitionCreated",
		Data: map[string]any{
			"name":        req.Msg.Name,
			"description": req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to create definition"); err != nil {
		return nil, err
	}

	def, err := h.store.Queries().GetDefinitionByID(ctx, id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get definition")
	}

	h.enqueueDefinitionReindex(ctx, def)

	return connect.NewResponse(&pm.CreateDefinitionResponse{
		Definition: h.definitionToProto(def),
	}), nil
}

// GetDefinition returns a definition by ID.
func (h *DefinitionHandler) GetDefinition(ctx context.Context, req *connect.Request[pm.GetDefinitionRequest]) (*connect.Response[pm.GetDefinitionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	def, err := h.store.Queries().GetDefinitionByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDefinitionNotFound, "definition not found")
	}

	members, err := h.store.Queries().ListDefinitionMembers(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get definition members")
	}

	protoMembers := make([]*pm.DefinitionMember, len(members))
	for i, m := range members {
		protoMembers[i] = &pm.DefinitionMember{
			ActionSetId:   m.ActionSetID,
			SortOrder:     m.SortOrder,
			ActionSetName: m.ActionSetName,
		}
	}

	return connect.NewResponse(&pm.GetDefinitionResponse{
		Definition: h.definitionToProto(def),
		Members:    protoMembers,
	}), nil
}

// ListDefinitions returns a paginated list of definitions.
func (h *DefinitionHandler) ListDefinitions(ctx context.Context, req *connect.Request[pm.ListDefinitionsRequest]) (*connect.Response[pm.ListDefinitionsResponse], error) {
	pageSize, offset, err := parsePagination(int32(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, err
	}

	defs, err := h.store.Queries().ListDefinitions(ctx, db.ListDefinitionsParams{
		Limit:  pageSize,
		Offset: offset,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list definitions")
	}

	count, err := h.store.Queries().CountDefinitions(ctx)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count definitions")
	}

	nextPageToken := buildNextPageToken(int32(len(defs)), offset, pageSize, count)

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
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "definition",
		StreamID:   req.Msg.Id,
		EventType:  "DefinitionRenamed",
		Data: map[string]any{
			"name": req.Msg.Name,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to rename definition"); err != nil {
		return nil, err
	}

	def, err := h.store.Queries().GetDefinitionByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDefinitionNotFound, "definition not found")
	}

	h.enqueueDefinitionReindex(ctx, def)

	return connect.NewResponse(&pm.UpdateDefinitionResponse{
		Definition: h.definitionToProto(def),
	}), nil
}

// UpdateDefinitionDescription updates a definition's description.
func (h *DefinitionHandler) UpdateDefinitionDescription(ctx context.Context, req *connect.Request[pm.UpdateDefinitionDescriptionRequest]) (*connect.Response[pm.UpdateDefinitionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "definition",
		StreamID:   req.Msg.Id,
		EventType:  "DefinitionDescriptionUpdated",
		Data: map[string]any{
			"description": req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to update description"); err != nil {
		return nil, err
	}

	def, err := h.store.Queries().GetDefinitionByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDefinitionNotFound, "definition not found")
	}

	h.enqueueDefinitionReindex(ctx, def)

	return connect.NewResponse(&pm.UpdateDefinitionResponse{
		Definition: h.definitionToProto(def),
	}), nil
}

// DeleteDefinition deletes a definition.
func (h *DefinitionHandler) DeleteDefinition(ctx context.Context, req *connect.Request[pm.DeleteDefinitionRequest]) (*connect.Response[pm.DeleteDefinitionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	var cascadeIDs []string
	if h.searchIdx != nil {
		cascadeIDs = h.searchIdx.GetReverseMembers(ctx, "definition", req.Msg.Id)
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "definition",
		StreamID:   req.Msg.Id,
		EventType:  "DefinitionDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to delete definition"); err != nil {
		return nil, err
	}

	if h.searchIdx != nil {
		if err := h.searchIdx.EnqueueRemove(ctx, "definition", req.Msg.Id, cascadeIDs); err != nil {
			h.logger.Warn("failed to enqueue search index remove", "scope", "definition", "error", err)
		}
	}

	return connect.NewResponse(&pm.DeleteDefinitionResponse{}), nil
}

// AddActionSetToDefinition adds an action set to a definition.
func (h *DefinitionHandler) AddActionSetToDefinition(ctx context.Context, req *connect.Request[pm.AddActionSetToDefinitionRequest]) (*connect.Response[pm.AddActionSetToDefinitionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Verify definition exists
	_, err = h.store.Queries().GetDefinitionByID(ctx, req.Msg.DefinitionId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDefinitionNotFound, "definition not found")
	}

	// Verify action set exists
	actionSet, err := h.store.Queries().GetActionSetByID(ctx, req.Msg.ActionSetId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrActionSetNotFound, "action set not found")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "definition",
		StreamID:   req.Msg.DefinitionId,
		EventType:  "DefinitionMemberAdded",
		Data: map[string]any{
			"action_set_id": req.Msg.ActionSetId,
			"sort_order":    req.Msg.SortOrder,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to add action set to definition"); err != nil {
		return nil, err
	}

	def, err := h.store.Queries().GetDefinitionByID(ctx, req.Msg.DefinitionId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get definition")
	}

	if h.searchIdx != nil {
		if err := h.searchIdx.EnqueueMemberAdded(ctx, "definition", req.Msg.DefinitionId, "action_set", req.Msg.ActionSetId, actionSet.Name); err != nil {
			h.logger.Warn("failed to enqueue search member added", "scope", "definition", "error", err)
		}
	}

	return connect.NewResponse(&pm.AddActionSetToDefinitionResponse{
		Definition: h.definitionToProto(def),
	}), nil
}

// RemoveActionSetFromDefinition removes an action set from a definition.
func (h *DefinitionHandler) RemoveActionSetFromDefinition(ctx context.Context, req *connect.Request[pm.RemoveActionSetFromDefinitionRequest]) (*connect.Response[pm.RemoveActionSetFromDefinitionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "definition",
		StreamID:   req.Msg.DefinitionId,
		EventType:  "DefinitionMemberRemoved",
		Data: map[string]any{
			"action_set_id": req.Msg.ActionSetId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to remove action set from definition"); err != nil {
		return nil, err
	}

	def, err := h.store.Queries().GetDefinitionByID(ctx, req.Msg.DefinitionId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDefinitionNotFound, "definition not found")
	}

	if h.searchIdx != nil {
		if err := h.searchIdx.EnqueueMemberRemoved(ctx, "definition", req.Msg.DefinitionId, "action_set", req.Msg.ActionSetId, ""); err != nil {
			h.logger.Warn("failed to enqueue search member removed", "scope", "definition", "error", err)
		}
	}

	return connect.NewResponse(&pm.RemoveActionSetFromDefinitionResponse{
		Definition: h.definitionToProto(def),
	}), nil
}

// ReorderActionSetInDefinition changes the order of an action set in a definition.
func (h *DefinitionHandler) ReorderActionSetInDefinition(ctx context.Context, req *connect.Request[pm.ReorderActionSetInDefinitionRequest]) (*connect.Response[pm.ReorderActionSetInDefinitionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "definition",
		StreamID:   req.Msg.DefinitionId,
		EventType:  "DefinitionMemberReordered",
		Data: map[string]any{
			"action_set_id": req.Msg.ActionSetId,
			"sort_order":    req.Msg.NewOrder,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to reorder action set in definition"); err != nil {
		return nil, err
	}

	def, err := h.store.Queries().GetDefinitionByID(ctx, req.Msg.DefinitionId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDefinitionNotFound, "definition not found")
	}

	return connect.NewResponse(&pm.ReorderActionSetInDefinitionResponse{
		Definition: h.definitionToProto(def),
	}), nil
}

// enqueueDefinitionReindex enqueues a search index update for a definition.
func (h *DefinitionHandler) enqueueDefinitionReindex(ctx context.Context, d db.DefinitionsProjection) {
	if h.searchIdx == nil {
		return
	}
	var createdAt, updatedAt int64
	if d.CreatedAt != nil {
		createdAt = d.CreatedAt.Unix()
	}
	if d.UpdatedAt != nil {
		updatedAt = d.UpdatedAt.Unix()
	}
	if err := h.searchIdx.EnqueueReindex(ctx, "definition", d.ID, &taskqueue.SearchEntityData{
		Name:        d.Name,
		Description: d.Description,
		MemberCount: d.MemberCount,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}); err != nil {
		h.logger.Warn("failed to enqueue search reindex", "scope", "definition", "error", err)
	}
}

func (h *DefinitionHandler) definitionToProto(d db.DefinitionsProjection) *pm.Definition {
	def := &pm.Definition{
		Id:          d.ID,
		Name:        d.Name,
		Description: d.Description,
		MemberCount: d.MemberCount,
		CreatedBy:   d.CreatedBy,
	}

	if d.CreatedAt != nil {
		def.CreatedAt = timestamppb.New(*d.CreatedAt)
	}

	if d.UpdatedAt != nil {
		def.UpdatedAt = timestamppb.New(*d.UpdatedAt)
	}

	return def
}
