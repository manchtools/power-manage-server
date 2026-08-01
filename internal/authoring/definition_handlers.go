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

// docref: begin explicit-definition-rpcs

// CreateDefinition writes one independently scheduled definition.
func (h *Handlers) CreateDefinition(ctx context.Context, req *connect.Request[pmv1.CreateDefinitionRequest]) (*connect.Response[pmv1.CreateDefinitionResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "CreateDefinition", ""); err != nil {
		return nil, err
	}
	row, err := h.state.CreateDefinition(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceCreateDefinitionProcedure, "CreateDefinition"), CreateDefinitionParams{
		Name: req.Msg.Name, Description: req.Msg.Description,
		CreatedBy: actor.ID, Schedule: req.Msg.Schedule,
	})
	if err != nil {
		return nil, h.definitionError(ctx, "create definition", err)
	}
	definition, err := definitionToProto(row, 0)
	if err != nil {
		return nil, h.internal(ctx, "encode created definition", err)
	}
	return connect.NewResponse(&pmv1.CreateDefinitionResponse{Definition: definition}), nil
}

// GetDefinition returns one visible definition and its live ordered members.
func (h *Handlers) GetDefinition(ctx context.Context, req *connect.Request[pmv1.GetDefinitionRequest]) (*connect.Response[pmv1.GetDefinitionResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "GetDefinition", req.Msg.Id); err != nil {
		return nil, err
	}
	row, err := h.operatorDefinition(ctx, req.Msg.Id)
	if err != nil {
		return nil, err
	}
	if err := h.enforceDefinitionReadScope(ctx, req.Msg.Id); err != nil {
		return nil, err
	}
	members, err := h.store.ListDefinitionMembers(ctx, req.Msg.Id)
	if err != nil {
		return nil, h.internal(ctx, "list definition members", err)
	}
	definition, err := definitionToProto(row, int64(len(members)))
	if err != nil {
		return nil, h.internal(ctx, "encode definition", err)
	}
	return connect.NewResponse(&pmv1.GetDefinitionResponse{
		Definition: definition, Members: definitionMembersToProto(members),
	}), nil
}

// ListDefinitions returns a deterministic PostgreSQL keyset page.
func (h *Handlers) ListDefinitions(ctx context.Context, req *connect.Request[pmv1.ListDefinitionsRequest]) (*connect.Response[pmv1.ListDefinitionsResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "ListDefinitions", ""); err != nil {
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
	filter := store.DefinitionListFilter{
		AfterID: req.Msg.PageToken, Limit: limit + 1,
		ScopeRestricted: restricted, ScopeGroupIDs: groupIDs,
	}
	views, err := h.store.ListAuthoringDefinitions(ctx, filter)
	if err != nil {
		return nil, h.internal(ctx, "list definitions", err)
	}
	hasMore := len(views) > int(limit)
	if hasMore {
		views = views[:limit]
	}
	total, err := h.store.CountAuthoringDefinitions(ctx, filter)
	if err != nil {
		return nil, h.internal(ctx, "count definitions", err)
	}
	definitions := make([]*pmv1.Definition, len(views))
	for i, view := range views {
		definitions[i], err = definitionToProto(view.DefinitionRow, view.LiveMemberCount)
		if err != nil {
			return nil, h.internal(ctx, "encode listed definition", err)
		}
	}
	next := ""
	if hasMore {
		next = views[len(views)-1].ID
	}
	return connect.NewResponse(&pmv1.ListDefinitionsResponse{
		Definitions: definitions, NextPageToken: next, TotalCount: boundedCount(total),
	}), nil
}

// RenameDefinition replaces a definition name.
func (h *Handlers) RenameDefinition(ctx context.Context, req *connect.Request[pmv1.RenameDefinitionRequest]) (*connect.Response[pmv1.UpdateDefinitionResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationDefinitionActor(ctx, req.Msg.Id, "RenameDefinition")
	if err != nil {
		return nil, err
	}
	row, err := h.state.RenameDefinition(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceRenameDefinitionProcedure, "RenameDefinition"), req.Msg.Id, req.Msg.Name)
	return h.updatedDefinition(ctx, "rename definition", row, err)
}

// UpdateDefinitionDescription replaces a definition description.
func (h *Handlers) UpdateDefinitionDescription(ctx context.Context, req *connect.Request[pmv1.UpdateDefinitionDescriptionRequest]) (*connect.Response[pmv1.UpdateDefinitionResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationDefinitionActor(ctx, req.Msg.Id, "UpdateDefinitionDescription")
	if err != nil {
		return nil, err
	}
	row, err := h.state.UpdateDefinitionDescription(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceUpdateDefinitionDescriptionProcedure, "UpdateDefinitionDescription"),
		req.Msg.Id, req.Msg.Description)
	return h.updatedDefinition(ctx, "update definition description", row, err)
}

// UpdateDefinitionSchedule replaces only the compilation-time schedule.
func (h *Handlers) UpdateDefinitionSchedule(ctx context.Context, req *connect.Request[pmv1.UpdateDefinitionScheduleRequest]) (*connect.Response[pmv1.UpdateDefinitionResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationDefinitionActor(ctx, req.Msg.Id, "UpdateDefinitionSchedule")
	if err != nil {
		return nil, err
	}
	row, err := h.state.UpdateDefinitionSchedule(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceUpdateDefinitionScheduleProcedure, "UpdateDefinitionSchedule"),
		req.Msg.Id, req.Msg.Schedule)
	return h.updatedDefinition(ctx, "update definition schedule", row, err)
}

// DeleteDefinition soft-deletes a definition and removes its composition
// edges.
func (h *Handlers) DeleteDefinition(ctx context.Context, req *connect.Request[pmv1.DeleteDefinitionRequest]) (*connect.Response[pmv1.DeleteDefinitionResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationDefinitionActor(ctx, req.Msg.Id, "DeleteDefinition")
	if err != nil {
		return nil, err
	}
	if err := h.state.DeleteDefinition(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceDeleteDefinitionProcedure, "DeleteDefinition"), req.Msg.Id); err != nil {
		return nil, h.definitionError(ctx, "delete definition", err)
	}
	return connect.NewResponse(&pmv1.DeleteDefinitionResponse{}), nil
}

// AddActionSetToDefinition adds one visible ActionSet to a definition.
func (h *Handlers) AddActionSetToDefinition(ctx context.Context, req *connect.Request[pmv1.AddActionSetToDefinitionRequest]) (*connect.Response[pmv1.AddActionSetToDefinitionResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationDefinitionActor(ctx, req.Msg.DefinitionId, "AddActionSetToDefinition")
	if err != nil {
		return nil, err
	}
	if err := h.enforceActionSetReadScope(ctx, req.Msg.ActionSetId); err != nil {
		return nil, err
	}
	if _, err := h.operatorActionSet(ctx, req.Msg.ActionSetId); err != nil {
		return nil, err
	}
	if err := h.state.AddActionSetToDefinition(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceAddActionSetToDefinitionProcedure, "AddActionSetToDefinition"),
		req.Msg.DefinitionId, req.Msg.ActionSetId, req.Msg.SortOrder); err != nil {
		return nil, h.definitionError(ctx, "add action set to definition", err)
	}
	definition, err := h.definitionResponse(ctx, req.Msg.DefinitionId)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.AddActionSetToDefinitionResponse{Definition: definition}), nil
}

// RemoveActionSetFromDefinition removes one ActionSet edge.
func (h *Handlers) RemoveActionSetFromDefinition(ctx context.Context, req *connect.Request[pmv1.RemoveActionSetFromDefinitionRequest]) (*connect.Response[pmv1.RemoveActionSetFromDefinitionResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationDefinitionActor(ctx, req.Msg.DefinitionId, "RemoveActionSetFromDefinition")
	if err != nil {
		return nil, err
	}
	if err := h.state.RemoveActionSetFromDefinition(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceRemoveActionSetFromDefinitionProcedure, "RemoveActionSetFromDefinition"),
		req.Msg.DefinitionId, req.Msg.ActionSetId); err != nil {
		return nil, h.definitionError(ctx, "remove action set from definition", err)
	}
	definition, err := h.definitionResponse(ctx, req.Msg.DefinitionId)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.RemoveActionSetFromDefinitionResponse{Definition: definition}), nil
}

// ReorderActionSetInDefinition replaces one ActionSet edge position.
func (h *Handlers) ReorderActionSetInDefinition(ctx context.Context, req *connect.Request[pmv1.ReorderActionSetInDefinitionRequest]) (*connect.Response[pmv1.ReorderActionSetInDefinitionResponse], error) {
	if err := validateAuthoringRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationDefinitionActor(ctx, req.Msg.DefinitionId, "ReorderActionSetInDefinition")
	if err != nil {
		return nil, err
	}
	if err := h.state.ReorderActionSetInDefinition(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceReorderActionSetInDefinitionProcedure, "ReorderActionSetInDefinition"),
		req.Msg.DefinitionId, req.Msg.ActionSetId, req.Msg.NewOrder); err != nil {
		return nil, h.definitionError(ctx, "reorder action set in definition", err)
	}
	definition, err := h.definitionResponse(ctx, req.Msg.DefinitionId)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.ReorderActionSetInDefinitionResponse{Definition: definition}), nil
}

// docref: end explicit-definition-rpcs

func (h *Handlers) definitionError(ctx context.Context, operation string, err error) error {
	switch {
	case errors.Is(err, ErrInvalidInput):
		return authoringRPCError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid definition")
	case errors.Is(err, ErrDefinitionAlreadyMember):
		return authoringRPCError(ctx, errActionSetAlreadyInDef, connect.CodeAlreadyExists, "action set is already in the definition")
	case errors.Is(err, ErrDefinitionMemberMissing):
		return authoringNotFound(ctx, errDefinitionMemberNotFound, "definition member not found")
	case store.IsNotFound(err):
		return authoringNotFound(ctx, errDefinitionNotFound, "definition not found")
	default:
		return h.internal(ctx, operation, err)
	}
}

func (h *Handlers) operatorDefinition(ctx context.Context, id string) (store.DefinitionRow, error) {
	row, err := h.store.GetManifestDefinition(ctx, id)
	if err != nil {
		if store.IsNotFound(err) {
			return store.DefinitionRow{}, authoringNotFound(ctx, errDefinitionNotFound, "definition not found")
		}
		return store.DefinitionRow{}, h.internal(ctx, "read definition", err)
	}
	return row, nil
}

func (h *Handlers) enforceDefinitionReadScope(ctx context.Context, id string) error {
	callerGroups, restricted := auth.ObjectScopeListFilter(ctx)
	if !restricted {
		return nil
	}
	objectGroups, err := h.directScopeGroups(ctx, "definition", id)
	if err != nil {
		return h.internal(ctx, "resolve definition read scope", err)
	}
	if !groupsOverlap(callerGroups, objectGroups) {
		h.logger.Warn("out-of-scope definition read denied", "definition_id", id)
		return authoringNotFound(ctx, errDefinitionNotFound, "definition not found")
	}
	return nil
}

func (h *Handlers) enforceDefinitionWriteScope(ctx context.Context, id string) error {
	callerGroups, restricted := auth.ObjectScopeListFilter(ctx)
	if !restricted {
		return nil
	}
	objectGroups, err := h.directScopeGroups(ctx, "definition", id)
	if err != nil {
		return h.internal(ctx, "resolve definition write scope", err)
	}
	if !groupsOverlap(callerGroups, objectGroups) {
		h.logger.Warn("out-of-scope definition mutation denied", "definition_id", id)
		return authoringRPCError(ctx, errPermissionDenied, connect.CodePermissionDenied, "permission denied")
	}
	return nil
}

func (h *Handlers) mutationDefinitionActor(ctx context.Context, id, permission string) (*auth.UserContext, error) {
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, permission, id); err != nil {
		return nil, err
	}
	if err := h.enforceDefinitionWriteScope(ctx, id); err != nil {
		return nil, err
	}
	if _, err := h.operatorDefinition(ctx, id); err != nil {
		return nil, err
	}
	return actor, nil
}

func (h *Handlers) updatedDefinition(ctx context.Context, operation string, row store.DefinitionRow, err error) (*connect.Response[pmv1.UpdateDefinitionResponse], error) {
	if err != nil {
		return nil, h.definitionError(ctx, operation, err)
	}
	members, err := h.store.ListDefinitionMembers(ctx, row.ID)
	if err != nil {
		return nil, h.internal(ctx, "count updated definition members", err)
	}
	definition, err := definitionToProto(row, int64(len(members)))
	if err != nil {
		return nil, h.internal(ctx, "encode updated definition", err)
	}
	return connect.NewResponse(&pmv1.UpdateDefinitionResponse{Definition: definition}), nil
}

func (h *Handlers) definitionResponse(ctx context.Context, id string) (*pmv1.Definition, error) {
	row, err := h.store.GetManifestDefinition(ctx, id)
	if err != nil {
		return nil, h.definitionError(ctx, "read changed definition", err)
	}
	members, err := h.store.ListDefinitionMembers(ctx, id)
	if err != nil {
		return nil, h.internal(ctx, "count changed definition members", err)
	}
	definition, err := definitionToProto(row, int64(len(members)))
	if err != nil {
		return nil, h.internal(ctx, "encode changed definition", err)
	}
	return definition, nil
}
