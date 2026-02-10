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

// AssignmentHandler handles assignment RPCs.
type AssignmentHandler struct {
	store         *store.Store
	entropy       *ulid.MonotonicEntropy
	actionHandler *ActionHandler
}

// NewAssignmentHandler creates a new assignment handler.
func NewAssignmentHandler(st *store.Store, actionHandler *ActionHandler) *AssignmentHandler {
	return &AssignmentHandler{
		store:         st,
		entropy:       ulid.Monotonic(rand.Reader, 0),
		actionHandler: actionHandler,
	}
}

// CreateAssignment creates a new assignment.
func (h *AssignmentHandler) CreateAssignment(ctx context.Context, req *connect.Request[pm.CreateAssignmentRequest]) (*connect.Response[pm.CreateAssignmentResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Validate source exists
	switch req.Msg.SourceType {
	case "action":
		_, err := h.store.Queries().GetActionByID(ctx, req.Msg.SourceId)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, connect.NewError(connect.CodeNotFound, errors.New("action not found"))
			}
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action"))
		}
	case "action_set":
		_, err := h.store.Queries().GetActionSetByID(ctx, req.Msg.SourceId)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, connect.NewError(connect.CodeNotFound, errors.New("action set not found"))
			}
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action set"))
		}
	case "definition":
		_, err := h.store.Queries().GetDefinitionByID(ctx, req.Msg.SourceId)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, connect.NewError(connect.CodeNotFound, errors.New("definition not found"))
			}
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get definition"))
		}
	}

	// Validate target exists
	switch req.Msg.TargetType {
	case "device":
		_, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.TargetId})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, connect.NewError(connect.CodeNotFound, errors.New("device not found"))
			}
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device"))
		}
	case "device_group":
		_, err := h.store.Queries().GetDeviceGroupByID(ctx, req.Msg.TargetId)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, connect.NewError(connect.CodeNotFound, errors.New("device group not found"))
			}
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device group"))
		}
	}

	// Check if an active assignment already exists
	existingAssignment, err := h.store.Queries().GetAssignment(ctx, db.GetAssignmentParams{
		SourceType: req.Msg.SourceType,
		SourceID:   req.Msg.SourceId,
		TargetType: req.Msg.TargetType,
		TargetID:   req.Msg.TargetId,
	})
	if err == nil {
		// Assignment already exists, return it
		return connect.NewResponse(&pm.CreateAssignmentResponse{
			Assignment: h.assignmentToProto(existingAssignment),
		}), nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to check existing assignment"))
	}

	id := ulid.MustNew(ulid.Timestamp(time.Now()), h.entropy).String()

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "assignment",
		StreamID:   id,
		EventType:  "AssignmentCreated",
		Data: map[string]any{
			"source_type": req.Msg.SourceType,
			"source_id":   req.Msg.SourceId,
			"target_type": req.Msg.TargetType,
			"target_id":   req.Msg.TargetId,
			"mode":        int32(req.Msg.Mode),
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create assignment"))
	}

	// Use GetAssignment instead of GetAssignmentByID because the upsert
	// may have updated an existing soft-deleted record with a different ID
	assignment, err := h.store.Queries().GetAssignment(ctx, db.GetAssignmentParams{
		SourceType: req.Msg.SourceType,
		SourceID:   req.Msg.SourceId,
		TargetType: req.Msg.TargetType,
		TargetID:   req.Msg.TargetId,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get assignment"))
	}

	return connect.NewResponse(&pm.CreateAssignmentResponse{
		Assignment: h.assignmentToProto(assignment),
	}), nil
}

// DeleteAssignment deletes an assignment.
func (h *AssignmentHandler) DeleteAssignment(ctx context.Context, req *connect.Request[pm.DeleteAssignmentRequest]) (*connect.Response[pm.DeleteAssignmentResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "assignment",
		StreamID:   req.Msg.Id,
		EventType:  "AssignmentDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete assignment"))
	}

	return connect.NewResponse(&pm.DeleteAssignmentResponse{}), nil
}

// ListAssignments returns a paginated list of assignments.
func (h *AssignmentHandler) ListAssignments(ctx context.Context, req *connect.Request[pm.ListAssignmentsRequest]) (*connect.Response[pm.ListAssignmentsResponse], error) {
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

	assignments, err := h.store.Queries().ListAssignments(ctx, db.ListAssignmentsParams{
		Column1: req.Msg.SourceType,
		Column2: req.Msg.SourceId,
		Column3: req.Msg.TargetType,
		Column4: req.Msg.TargetId,
		Limit:   pageSize,
		Offset:  offset,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list assignments"))
	}

	count, err := h.store.Queries().CountAssignments(ctx, db.CountAssignmentsParams{
		Column1: req.Msg.SourceType,
		Column2: req.Msg.SourceId,
		Column3: req.Msg.TargetType,
		Column4: req.Msg.TargetId,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to count assignments"))
	}

	var nextPageToken string
	if int32(len(assignments)) == pageSize && int64(offset)+int64(pageSize) < count {
		nextPageToken = formatPageToken(int64(offset) + int64(pageSize))
	}

	protoAssignments := make([]*pm.Assignment, len(assignments))
	for i, a := range assignments {
		protoAssignments[i] = h.assignmentToProto(a)
	}

	return connect.NewResponse(&pm.ListAssignmentsResponse{
		Assignments:   protoAssignments,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// GetDeviceAssignments returns all resolved assignments for a device.
func (h *AssignmentHandler) GetDeviceAssignments(ctx context.Context, req *connect.Request[pm.GetDeviceAssignmentsRequest]) (*connect.Response[pm.GetDeviceAssignmentsResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Get all actions assigned to this device (directly or via groups/sets/definitions)
	actions, err := h.store.Queries().ListAssignedActionsForDevice(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get assigned actions"))
	}

	protoActions := make([]*pm.ManagedAction, len(actions))
	for i, a := range actions {
		protoActions[i] = h.actionHandler.actionToProto(db.ActionsProjection{
			ID:                a.ID,
			Name:              a.Name,
			Description:       a.Description,
			ActionType:        a.ActionType,
			Params:            a.Params,
			TimeoutSeconds:    a.TimeoutSeconds,
			CreatedAt:         a.CreatedAt,
			CreatedBy:         a.CreatedBy,
			IsDeleted:         a.IsDeleted,
			ProjectionVersion: a.ProjectionVersion,
		})
	}

	// Get direct action set assignments
	directAssignments, err := h.store.Queries().ListDirectAssignmentsForDevice(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get direct assignments"))
	}

	// Get group-based assignments
	groupAssignments, err := h.store.Queries().ListGroupAssignmentsForDevice(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get group assignments"))
	}

	// Collect unique action set IDs and definition IDs
	actionSetIDs := make(map[string]bool)
	definitionIDs := make(map[string]bool)

	for _, a := range directAssignments {
		switch a.SourceType {
		case "action_set":
			actionSetIDs[a.SourceID] = true
		case "definition":
			definitionIDs[a.SourceID] = true
		}
	}
	for _, a := range groupAssignments {
		switch a.SourceType {
		case "action_set":
			actionSetIDs[a.SourceID] = true
		case "definition":
			definitionIDs[a.SourceID] = true
		}
	}

	// Fetch action sets
	protoActionSets := make([]*pm.ActionSet, 0, len(actionSetIDs))
	for id := range actionSetIDs {
		set, err := h.store.Queries().GetActionSetByID(ctx, id)
		if err == nil {
			protoActionSets = append(protoActionSets, &pm.ActionSet{
				Id:          set.ID,
				Name:        set.Name,
				Description: set.Description,
				MemberCount: set.MemberCount,
				CreatedBy:   set.CreatedBy,
				CreatedAt:   timestamppb.New(set.CreatedAt.Time),
			})
		}
	}

	// Fetch definitions
	protoDefinitions := make([]*pm.Definition, 0, len(definitionIDs))
	for id := range definitionIDs {
		def, err := h.store.Queries().GetDefinitionByID(ctx, id)
		if err == nil {
			protoDefinitions = append(protoDefinitions, &pm.Definition{
				Id:          def.ID,
				Name:        def.Name,
				Description: def.Description,
				MemberCount: def.MemberCount,
				CreatedBy:   def.CreatedBy,
				CreatedAt:   timestamppb.New(def.CreatedAt.Time),
			})
		}
	}

	return connect.NewResponse(&pm.GetDeviceAssignmentsResponse{
		Actions:     protoActions,
		ActionSets:  protoActionSets,
		Definitions: protoDefinitions,
	}), nil
}

func (h *AssignmentHandler) assignmentToProto(a db.AssignmentsProjection) *pm.Assignment {
	assignment := &pm.Assignment{
		Id:         a.ID,
		SourceType: a.SourceType,
		SourceId:   a.SourceID,
		TargetType: a.TargetType,
		TargetId:   a.TargetID,
		CreatedBy:  a.CreatedBy,
		Mode:       pm.AssignmentMode(a.Mode),
	}

	if a.CreatedAt.Valid {
		assignment.CreatedAt = timestamppb.New(a.CreatedAt.Time)
	}

	return assignment
}
