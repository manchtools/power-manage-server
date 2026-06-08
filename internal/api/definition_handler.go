package api

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
)

// DefinitionHandler handles definition (collection of action sets) RPCs.
type DefinitionHandler struct {
	searchIndexHolder
	store  *store.Store
	logger *slog.Logger
}

// NewDefinitionHandler creates a new definition handler.
func NewDefinitionHandler(st *store.Store, logger *slog.Logger) *DefinitionHandler {
	return &DefinitionHandler{
		store:  st,
		logger: logger,
	}
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

	data := map[string]any{
		"name":        req.Msg.Name,
		"description": req.Msg.Description,
	}
	// Schedule is required at the proto layer, but we still build the
	// payload defensively — see action_set_handler.go.CreateActionSet
	// for the rationale (default-schedule fallback in the projector).
	if req.Msg.Schedule != nil {
		if schedule := actionparams.ScheduleToMap(req.Msg.Schedule); len(schedule) > 0 {
			data["schedule"] = schedule
		}
	}
	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "definition",
		StreamID:   id,
		EventType:  string(eventtypes.DefinitionCreated),
		Data:       data,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to create definition"); err != nil {
		return nil, err
	}

	def, err := h.store.Repos().Definition.Get(ctx, id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get definition")
	}

	return connect.NewResponse(&pm.CreateDefinitionResponse{
		Definition: h.definitionToProto(def),
	}), nil
}

// GetDefinition returns a definition by ID.
func (h *DefinitionHandler) GetDefinition(ctx context.Context, req *connect.Request[pm.GetDefinitionRequest]) (*connect.Response[pm.GetDefinitionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	def, err := h.store.Repos().Definition.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDefinitionNotFound, "definition not found")
	}

	members, err := h.store.Repos().Definition.ListMembers(ctx, req.Msg.Id)
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
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	pageSize, offset, err := parsePagination(int32(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, err
	}

	defs, err := h.store.Repos().Definition.List(ctx, store.ListDefinitionsFilter{Limit: pageSize, Offset: offset})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list definitions")
	}

	count, err := h.store.Repos().Definition.Count(ctx)
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
		EventType:  string(eventtypes.DefinitionRenamed),
		Data: payloads.DefinitionRenamed{
			Name: req.Msg.Name,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to rename definition"); err != nil {
		return nil, err
	}

	def, err := h.store.Repos().Definition.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDefinitionNotFound, "definition not found")
	}

	return connect.NewResponse(&pm.UpdateDefinitionResponse{
		Definition: h.definitionToProto(def),
	}), nil
}

// UpdateDefinitionSchedule updates a definition's schedule. The
// definition's schedule triggers every action in every member set when
// it fires; sets and their member actions never run on their own when
// assigned via this definition.
func (h *DefinitionHandler) UpdateDefinitionSchedule(ctx context.Context, req *connect.Request[pm.UpdateDefinitionScheduleRequest]) (*connect.Response[pm.UpdateDefinitionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	data := map[string]any{}
	if req.Msg.Schedule != nil {
		if schedule := actionparams.ScheduleToMap(req.Msg.Schedule); len(schedule) > 0 {
			data["schedule"] = schedule
		}
	}
	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "definition",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.DefinitionScheduleUpdated),
		Data:       data,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to update schedule"); err != nil {
		return nil, err
	}

	def, err := h.store.Repos().Definition.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDefinitionNotFound, "definition not found")
	}

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
		EventType:  string(eventtypes.DefinitionDescriptionUpdated),
		Data: payloads.DefinitionDescriptionUpdated{
			Description: req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to update description"); err != nil {
		return nil, err
	}

	def, err := h.store.Repos().Definition.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDefinitionNotFound, "definition not found")
	}

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

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "definition",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.DefinitionDeleted),
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to delete definition"); err != nil {
		return nil, err
	}

	// Search index removal + cascade-rebuild of parent action_sets
	// is handled by api.SearchListener (Phase 2c of #81): the
	// listener calls GetReverseMembers + EnqueueRemove on
	// DefinitionDeleted.

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
	_, err = h.store.Repos().Definition.Get(ctx, req.Msg.DefinitionId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDefinitionNotFound, "definition not found")
	}

	// Verify action set exists
	actionSet, err := h.store.Repos().ActionSet.Get(ctx, req.Msg.ActionSetId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrActionSetNotFound, "action set not found")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "definition",
		StreamID:   req.Msg.DefinitionId,
		EventType:  string(eventtypes.DefinitionMemberAdded),
		Data: payloads.DefinitionMemberAdded{
			ActionSetID: req.Msg.ActionSetId,
			SortOrder:   req.Msg.SortOrder,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to add action set to definition"); err != nil {
		return nil, err
	}

	def, err := h.store.Repos().Definition.Get(ctx, req.Msg.DefinitionId)
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
		EventType:  string(eventtypes.DefinitionMemberRemoved),
		Data: payloads.DefinitionMemberRemoved{
			ActionSetID: req.Msg.ActionSetId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to remove action set from definition"); err != nil {
		return nil, err
	}

	def, err := h.store.Repos().Definition.Get(ctx, req.Msg.DefinitionId)
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
		EventType:  string(eventtypes.DefinitionMemberReordered),
		Data: payloads.DefinitionMemberReordered{
			ActionSetID: req.Msg.ActionSetId,
			SortOrder:   req.Msg.NewOrder,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to reorder action set in definition"); err != nil {
		return nil, err
	}

	def, err := h.store.Repos().Definition.Get(ctx, req.Msg.DefinitionId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDefinitionNotFound, "definition not found")
	}

	return connect.NewResponse(&pm.ReorderActionSetInDefinitionResponse{
		Definition: h.definitionToProto(def),
	}), nil
}

func (h *DefinitionHandler) definitionToProto(d store.Definition) *pm.Definition {
	def := &pm.Definition{
		Id:          d.ID,
		Name:        d.Name,
		Description: d.Description,
		MemberCount: d.MemberCount,
		CreatedBy:   d.CreatedBy,
		Schedule:    actionparams.ScheduleFromJSON(d.Schedule),
	}

	if d.CreatedAt != nil {
		def.CreatedAt = timestamppb.New(*d.CreatedAt)
	}

	if d.UpdatedAt != nil {
		def.UpdatedAt = timestamppb.New(*d.UpdatedAt)
	}

	return def
}
