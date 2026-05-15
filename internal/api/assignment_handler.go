package api

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// AssignmentHandler handles assignment RPCs.
type AssignmentHandler struct {
	store         *store.Store
	logger        *slog.Logger
	actionHandler *ActionHandler
}

// NewAssignmentHandler creates a new assignment handler.
func NewAssignmentHandler(st *store.Store, logger *slog.Logger, actionHandler *ActionHandler) *AssignmentHandler {
	return &AssignmentHandler{
		store:         st,
		logger:        logger,
		actionHandler: actionHandler,
	}
}

// CreateAssignment creates a new assignment.
func (h *AssignmentHandler) CreateAssignment(ctx context.Context, req *connect.Request[pm.CreateAssignmentRequest]) (*connect.Response[pm.CreateAssignmentResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Validate source exists
	switch req.Msg.SourceType {
	case pm.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION:
		_, err := h.store.Queries().GetActionByID(ctx, req.Msg.SourceId)
		if err != nil {
			if store.IsNotFound(err) {
				return nil, apiErrorCtx(ctx, ErrActionNotFound, connect.CodeNotFound, "action not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action")
		}
	case pm.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION_SET:
		_, err := h.store.Queries().GetActionSetByID(ctx, req.Msg.SourceId)
		if err != nil {
			if store.IsNotFound(err) {
				return nil, apiErrorCtx(ctx, ErrActionSetNotFound, connect.CodeNotFound, "action set not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action set")
		}
	case pm.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_DEFINITION:
		_, err := h.store.Queries().GetDefinitionByID(ctx, req.Msg.SourceId)
		if err != nil {
			if store.IsNotFound(err) {
				return nil, apiErrorCtx(ctx, ErrDefinitionNotFound, connect.CodeNotFound, "definition not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get definition")
		}
	case pm.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_COMPLIANCE_POLICY:
		_, err := h.store.Queries().GetCompliancePolicyByID(ctx, req.Msg.SourceId)
		if err != nil {
			if store.IsNotFound(err) {
				return nil, apiErrorCtx(ctx, ErrCompliancePolicyNotFound, connect.CodeNotFound, "compliance policy not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get compliance policy")
		}
	}

	// Validate target exists
	switch req.Msg.TargetType {
	case pm.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE:
		_, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.TargetId})
		if err != nil {
			if store.IsNotFound(err) {
				return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device")
		}
	case pm.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE_GROUP:
		_, err := h.store.Repos().DeviceGroup.Get(ctx, req.Msg.TargetId)
		if err != nil {
			if store.IsNotFound(err) {
				return nil, apiErrorCtx(ctx, ErrDeviceGroupNotFound, connect.CodeNotFound, "device group not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
		}
	case pm.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER:
		_, err := h.store.Queries().GetUserByID(ctx, req.Msg.TargetId)
		if err != nil {
			if store.IsNotFound(err) {
				return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeNotFound, "user not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
		}
	case pm.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER_GROUP:
		_, err := h.store.Repos().UserGroup.Get(ctx, req.Msg.TargetId)
		if err != nil {
			if store.IsNotFound(err) {
				return nil, apiErrorCtx(ctx, ErrUserGroupNotFound, connect.CodeNotFound, "user group not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user group")
		}
	}

	// Translate the wire enums to the legacy lowercase strings used
	// by the event payload, projection rows, and SQL filters. The
	// enum is the contract; the strings are an internal storage
	// detail that pre-dates the enum.
	sourceTypeStr := assignmentSourceTypeToString(req.Msg.SourceType)
	targetTypeStr := assignmentTargetTypeToString(req.Msg.TargetType)

	// Check if an active assignment already exists
	existingAssignment, err := h.store.Queries().GetAssignment(ctx, db.GetAssignmentParams{
		SourceType: sourceTypeStr,
		SourceID:   req.Msg.SourceId,
		TargetType: targetTypeStr,
		TargetID:   req.Msg.TargetId,
	})
	if err == nil {
		// Assignment already exists, return it
		return connect.NewResponse(&pm.CreateAssignmentResponse{
			Assignment: h.assignmentToProto(existingAssignment),
		}), nil
	} else if !store.IsNotFound(err) {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to check existing assignment")
	}

	id := ulid.Make().String()

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "assignment",
		StreamID:   id,
		EventType:  string(eventtypes.AssignmentCreated),
		Data: payloads.AssignmentCreated{
			SourceType: sourceTypeStr,
			SourceID:   req.Msg.SourceId,
			TargetType: targetTypeStr,
			TargetID:   req.Msg.TargetId,
			Mode:       func() *int32 { m := int32(req.Msg.Mode); return &m }(),
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to create assignment"); err != nil {
		return nil, err
	}

	// Use GetAssignment instead of GetAssignmentByID because the upsert
	// may have updated an existing soft-deleted record with a different ID
	assignment, err := h.store.Queries().GetAssignment(ctx, db.GetAssignmentParams{
		SourceType: sourceTypeStr,
		SourceID:   req.Msg.SourceId,
		TargetType: targetTypeStr,
		TargetID:   req.Msg.TargetId,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get assignment")
	}

	return connect.NewResponse(&pm.CreateAssignmentResponse{
		Assignment: h.assignmentToProto(assignment),
	}), nil
}

// DeleteAssignment deletes an assignment.
func (h *AssignmentHandler) DeleteAssignment(ctx context.Context, req *connect.Request[pm.DeleteAssignmentRequest]) (*connect.Response[pm.DeleteAssignmentResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Verify assignment exists before emitting delete event
	_, err = h.store.Queries().GetAssignmentByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrAssignmentNotFound, "assignment not found")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "assignment",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.AssignmentDeleted),
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to delete assignment"); err != nil {
		return nil, err
	}

	return connect.NewResponse(&pm.DeleteAssignmentResponse{}), nil
}

// ListAssignments returns a paginated list of assignments.
func (h *AssignmentHandler) ListAssignments(ctx context.Context, req *connect.Request[pm.ListAssignmentsRequest]) (*connect.Response[pm.ListAssignmentsResponse], error) {
	pageSize, offset, err := parsePagination(int32(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, err
	}

	// Wire enums map back to the legacy lowercase strings stored in
	// the projection. UNSPECIFIED becomes the empty string, which
	// the SQL filter treats as "no filter".
	sourceTypeStr := assignmentSourceTypeToString(req.Msg.SourceType)
	targetTypeStr := assignmentTargetTypeToString(req.Msg.TargetType)

	assignments, err := h.store.Queries().ListAssignments(ctx, db.ListAssignmentsParams{
		Column1: sourceTypeStr,
		Column2: req.Msg.SourceId,
		Column3: targetTypeStr,
		Column4: req.Msg.TargetId,
		Limit:   pageSize,
		Offset:  offset,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list assignments")
	}

	count, err := h.store.Queries().CountAssignments(ctx, db.CountAssignmentsParams{
		Column1: sourceTypeStr,
		Column2: req.Msg.SourceId,
		Column3: targetTypeStr,
		Column4: req.Msg.TargetId,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count assignments")
	}

	nextPageToken := buildNextPageToken(int32(len(assignments)), offset, pageSize, count)

	protoAssignments := make([]*pm.Assignment, len(assignments))
	for i, a := range assignments {
		assignment := &pm.Assignment{
			Id:         a.ID,
			SourceType: assignmentSourceTypeFromString(a.SourceType),
			SourceId:   a.SourceID,
			TargetType: assignmentTargetTypeFromString(a.TargetType),
			TargetId:   a.TargetID,
			CreatedBy:  a.CreatedBy,
			Mode:       pm.AssignmentMode(a.Mode),
			SourceName: a.SourceName,
			TargetName: a.TargetName,
		}
		if a.CreatedAt != nil {
			assignment.CreatedAt = timestamppb.New(*a.CreatedAt)
		}
		protoAssignments[i] = assignment
	}

	return connect.NewResponse(&pm.ListAssignmentsResponse{
		Assignments:   protoAssignments,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// GetDeviceAssignments returns all resolved assignments for a device.
func (h *AssignmentHandler) GetDeviceAssignments(ctx context.Context, req *connect.Request[pm.GetDeviceAssignmentsRequest]) (*connect.Response[pm.GetDeviceAssignmentsResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Get all actions assigned to this device (directly or via groups/sets/definitions)
	actions, err := h.store.Queries().ListAssignedActionsForDevice(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get assigned actions")
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
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get direct assignments")
	}

	// Get group-based assignments
	groupAssignments, err := h.store.Queries().ListGroupAssignmentsForDevice(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get group assignments")
	}

	// Collect unique action set IDs, definition IDs, and compliance policy IDs
	actionSetIDs := make(map[string]bool)
	definitionIDs := make(map[string]bool)
	compliancePolicyIDs := make(map[string]bool)

	for _, a := range directAssignments {
		switch a.SourceType {
		case "action_set":
			actionSetIDs[a.SourceID] = true
		case "definition":
			definitionIDs[a.SourceID] = true
		case "compliance_policy":
			compliancePolicyIDs[a.SourceID] = true
		}
	}
	for _, a := range groupAssignments {
		switch a.SourceType {
		case "action_set":
			actionSetIDs[a.SourceID] = true
		case "definition":
			definitionIDs[a.SourceID] = true
		case "compliance_policy":
			compliancePolicyIDs[a.SourceID] = true
		}
	}

	// Fetch action sets with members
	protoActionSets := make([]*pm.ActionSet, 0, len(actionSetIDs))
	protoActionSetDetails := make([]*pm.GetActionSetResponse, 0, len(actionSetIDs))
	for id := range actionSetIDs {
		set, err := h.store.Queries().GetActionSetByID(ctx, id)
		if err != nil {
			continue
		}
		protoSet := &pm.ActionSet{
			Id:          set.ID,
			Name:        set.Name,
			Description: set.Description,
			MemberCount: set.MemberCount,
			CreatedBy:   set.CreatedBy,
		}
		if set.CreatedAt != nil {
			protoSet.CreatedAt = timestamppb.New(*set.CreatedAt)
		}
		protoActionSets = append(protoActionSets, protoSet)

		members, err := h.store.Queries().ListActionSetMembers(ctx, id)
		if err != nil {
			continue
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
		protoActionSetDetails = append(protoActionSetDetails, &pm.GetActionSetResponse{
			Set:     protoSet,
			Members: protoMembers,
		})
	}

	// Fetch definitions with members
	protoDefinitions := make([]*pm.Definition, 0, len(definitionIDs))
	protoDefinitionDetails := make([]*pm.GetDefinitionResponse, 0, len(definitionIDs))
	for id := range definitionIDs {
		def, err := h.store.Queries().GetDefinitionByID(ctx, id)
		if err != nil {
			continue
		}
		protoDef := &pm.Definition{
			Id:          def.ID,
			Name:        def.Name,
			Description: def.Description,
			MemberCount: def.MemberCount,
			CreatedBy:   def.CreatedBy,
		}
		if def.CreatedAt != nil {
			protoDef.CreatedAt = timestamppb.New(*def.CreatedAt)
		}
		protoDefinitions = append(protoDefinitions, protoDef)

		members, err := h.store.Queries().ListDefinitionMembers(ctx, id)
		if err != nil {
			continue
		}
		protoMembers := make([]*pm.DefinitionMember, len(members))
		for i, m := range members {
			protoMembers[i] = &pm.DefinitionMember{
				ActionSetId:   m.ActionSetID,
				SortOrder:     m.SortOrder,
				ActionSetName: m.ActionSetName,
			}
		}
		protoDefinitionDetails = append(protoDefinitionDetails, &pm.GetDefinitionResponse{
			Definition: protoDef,
			Members:    protoMembers,
		})
	}

	// Fetch compliance policies
	protoCompliancePolicies := make([]*pm.CompliancePolicy, 0, len(compliancePolicyIDs))
	for id := range compliancePolicyIDs {
		cp, err := h.store.Queries().GetCompliancePolicyByID(ctx, id)
		if err != nil {
			logEnrichmentErr("GetCompliancePolicyByID", "compliance_policy_id", id, err)
			continue
		}
		protoPolicy := &pm.CompliancePolicy{
			Id:          cp.ID,
			Name:        cp.Name,
			Description: cp.Description,
			RuleCount:   cp.RuleCount,
			CreatedBy:   cp.CreatedBy,
		}
		if cp.CreatedAt != nil {
			protoPolicy.CreatedAt = timestamppb.New(*cp.CreatedAt)
		}
		protoCompliancePolicies = append(protoCompliancePolicies, protoPolicy)
	}

	return connect.NewResponse(&pm.GetDeviceAssignmentsResponse{
		Actions:            protoActions,
		ActionSets:         protoActionSets,
		Definitions:        protoDefinitions,
		CompliancePolicies: protoCompliancePolicies,
		ActionSetDetails:   protoActionSetDetails,
		DefinitionDetails:  protoDefinitionDetails,
	}), nil
}

// GetUserAssignments returns all assignments targeting a user (directly or via user groups).
func (h *AssignmentHandler) GetUserAssignments(ctx context.Context, req *connect.Request[pm.GetUserAssignmentsRequest]) (*connect.Response[pm.GetUserAssignmentsResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	assignments, err := h.store.Queries().ListAssignmentsForUser(ctx, req.Msg.UserId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list user assignments")
	}

	protoAssignments := make([]*pm.Assignment, len(assignments))
	for i, a := range assignments {
		protoAssignments[i] = h.assignmentToProto(a)
	}

	return connect.NewResponse(&pm.GetUserAssignmentsResponse{
		Assignments: protoAssignments,
	}), nil
}

func (h *AssignmentHandler) assignmentToProto(a db.AssignmentsProjection) *pm.Assignment {
	assignment := &pm.Assignment{
		Id:         a.ID,
		SourceType: assignmentSourceTypeFromString(a.SourceType),
		SourceId:   a.SourceID,
		TargetType: assignmentTargetTypeFromString(a.TargetType),
		TargetId:   a.TargetID,
		CreatedBy:  a.CreatedBy,
		Mode:       pm.AssignmentMode(a.Mode),
	}

	if a.CreatedAt != nil {
		assignment.CreatedAt = timestamppb.New(*a.CreatedAt)
	}

	return assignment
}

// assignmentSourceTypeToString converts the wire enum to the legacy
// lowercase string used in event payloads, projection rows, and
// SQL-side string filtering. Returns the empty string for
// UNSPECIFIED so callers can pass it straight into the optional
// filter columns on List/Count queries (an empty string is the
// stored signal for "no filter").
func assignmentSourceTypeToString(t pm.AssignmentSourceType) string {
	switch t {
	case pm.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION:
		return "action"
	case pm.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION_SET:
		return "action_set"
	case pm.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_DEFINITION:
		return "definition"
	case pm.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_COMPLIANCE_POLICY:
		return "compliance_policy"
	default:
		return ""
	}
}

// assignmentSourceTypeFromString is the inverse: it parses the
// projection / event-payload string back into the wire enum.
// Unknown / empty values map to UNSPECIFIED so a stale row never
// crashes the handler — the caller then surfaces UNSPECIFIED in the
// response and the client treats it as "unknown source".
func assignmentSourceTypeFromString(s string) pm.AssignmentSourceType {
	switch s {
	case "action":
		return pm.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION
	case "action_set":
		return pm.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION_SET
	case "definition":
		return pm.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_DEFINITION
	case "compliance_policy":
		return pm.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_COMPLIANCE_POLICY
	default:
		return pm.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_UNSPECIFIED
	}
}

// assignmentTargetTypeToString mirrors assignmentSourceTypeToString
// for the four supported target kinds. Same UNSPECIFIED-as-empty
// convention so the helper feeds the optional List/Count filter
// columns directly.
func assignmentTargetTypeToString(t pm.AssignmentTargetType) string {
	switch t {
	case pm.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE:
		return "device"
	case pm.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE_GROUP:
		return "device_group"
	case pm.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER:
		return "user"
	case pm.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER_GROUP:
		return "user_group"
	default:
		return ""
	}
}

// assignmentTargetTypeFromString parses the projection /
// event-payload string back into the wire enum. Unknown / empty
// values map to UNSPECIFIED, same rationale as the source helper.
func assignmentTargetTypeFromString(s string) pm.AssignmentTargetType {
	switch s {
	case "device":
		return pm.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE
	case "device_group":
		return pm.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE_GROUP
	case "user":
		return pm.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER
	case "user_group":
		return pm.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER_GROUP
	default:
		return pm.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_UNSPECIFIED
	}
}
