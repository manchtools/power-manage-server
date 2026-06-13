package api

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/go/maintenance"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/dynamicquery"
	"github.com/manchtools/power-manage/server/internal/dyngroupeval"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// DeviceGroupHandler handles device group RPCs.
type DeviceGroupHandler struct {
	searchIndexHolder
	store  *store.Store
	logger *slog.Logger
}

// NewDeviceGroupHandler creates a new device group handler.
func NewDeviceGroupHandler(st *store.Store, logger *slog.Logger) *DeviceGroupHandler {
	return &DeviceGroupHandler{
		store:  st,
		logger: logger,
	}
}

// CreateDeviceGroup creates a new device group.
//
// Permission dispatch (server #7 T-S2): the AuthzInterceptor passes
// the caller through if they hold EITHER CreateStaticDeviceGroup or
// CreateDynamicDeviceGroup (per ProcedureAlternatives). The handler
// then narrows to the specific permission against the request
// shape: a dynamic-query request requires the dynamic permission, a
// non-dynamic request requires the static permission. Without this
// narrowing, a static-only admin could create dynamic groups and
// perturb other actors' scopes.
func (h *DeviceGroupHandler) CreateDeviceGroup(ctx context.Context, req *connect.Request[pm.CreateDeviceGroupRequest]) (*connect.Response[pm.CreateDeviceGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Reject the (IsDynamic=true, DynamicQuery="") combination
	// BEFORE the permission narrowing: without this guard the
	// `wantsDynamic` predicate below would compute false (because
	// DynamicQuery is empty), letting a holder of
	// CreateStaticDeviceGroup pass the static-perm check while the
	// event still persists IsDynamic=true with an empty query —
	// an empty query is treated as match-all at evaluation time,
	// so the resulting "static" group would actually scoop up every
	// device. T-S2 bypass; flagged in #333 review.
	if req.Msg.IsDynamic && req.Msg.DynamicQuery == "" {
		return nil, apiErrorCtx(ctx, ErrInvalidQuery, connect.CodeInvalidArgument, "is_dynamic=true requires a non-empty dynamic_query")
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	wantsDynamic := req.Msg.IsDynamic && req.Msg.DynamicQuery != ""
	requiredPerm := "CreateStaticDeviceGroup"
	if wantsDynamic {
		requiredPerm = "CreateDynamicDeviceGroup"
	}
	if !auth.HasPermission(ctx, requiredPerm) {
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "missing required permission for the requested device group shape")
	}

	id := ulid.Make().String()

	// Validate dynamic query if provided
	if wantsDynamic {
		if len(req.Msg.DynamicQuery) > maxDynamicQueryLength {
			return nil, apiErrorCtx(ctx, ErrInvalidQuery, connect.CodeInvalidArgument, "dynamic_query exceeds maximum length")
		}
		if err := dynamicquery.ValidateDeviceQuery(req.Msg.DynamicQuery); err != nil {
			return nil, apiErrorCtx(ctx, ErrInvalidQuery, connect.CodeInvalidArgument, err.Error())
		}
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "device_group",
		StreamID:   id,
		EventType:  string(eventtypes.DeviceGroupCreated),
		Data: payloads.DeviceGroupCreated{
			Name:         req.Msg.Name,
			Description:  req.Msg.Description,
			IsDynamic:    req.Msg.IsDynamic,
			DynamicQuery: req.Msg.DynamicQuery,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to create device group"); err != nil {
		return nil, err
	}

	group, err := h.store.Repos().DeviceGroup.Get(ctx, id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	return connect.NewResponse(&pm.CreateDeviceGroupResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// GetDeviceGroup returns a device group by ID.
func (h *DeviceGroupHandler) GetDeviceGroup(ctx context.Context, req *connect.Request[pm.GetDeviceGroupRequest]) (*connect.Response[pm.GetDeviceGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if err := auth.EnforceDeviceGroupScope(ctx, "GetDeviceGroup", req.Msg.Id); err != nil {
		return nil, err
	}

	group, err := h.store.Repos().DeviceGroup.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceGroupNotFound, "device group not found")
	}

	members, err := h.store.Repos().DeviceGroup.ListMembers(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group members")
	}

	deviceIDs := make([]string, len(members))
	devices := make([]*pm.DeviceGroupMember, len(members))
	for i, m := range members {
		deviceIDs[i] = m.DeviceID
		devices[i] = &pm.DeviceGroupMember{
			DeviceId:     m.DeviceID,
			Hostname:     m.Hostname,
			AgentVersion: m.AgentVersion,
		}
		if m.LastSeenAt != nil {
			devices[i].LastSeenAt = timestamppb.New(*m.LastSeenAt)
		}
	}

	return connect.NewResponse(&pm.GetDeviceGroupResponse{
		Group:     h.deviceGroupToProto(group),
		DeviceIds: deviceIDs,
		Devices:   devices,
	}), nil
}

// ListDeviceGroups returns a paginated list of device groups.
func (h *DeviceGroupHandler) ListDeviceGroups(ctx context.Context, req *connect.Request[pm.ListDeviceGroupsRequest]) (*connect.Response[pm.ListDeviceGroupsResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	pageSize, offset, err := parsePagination(int32(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, err
	}

	// Device-group scope (#3): a scope-limited ListDeviceGroups holder sees only
	// the groups in their scope (direct id-match); a global holder is unrestricted.
	// Same restriction drives the count so pagination totals stay honest.
	scopeGroups, scopeRestricted := auth.DeviceScopeListFilter(ctx, "ListDeviceGroups")
	scope := store.ScopeGroupFilter{Restricted: scopeRestricted, GroupIDs: scopeGroups}

	groups, err := h.store.Repos().DeviceGroup.List(ctx, store.ListDeviceGroupsFilter{Limit: pageSize, Offset: offset, Scope: scope})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list device groups")
	}

	count, err := h.store.Repos().DeviceGroup.Count(ctx, scope)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count device groups")
	}

	nextPageToken := buildNextPageToken(int32(len(groups)), offset, pageSize, count)

	protoGroups := make([]*pm.DeviceGroup, len(groups))
	for i, g := range groups {
		protoGroups[i] = h.deviceGroupToProto(g)
	}

	return connect.NewResponse(&pm.ListDeviceGroupsResponse{
		Groups:        protoGroups,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// ListDeviceGroupsForDevice returns all device groups that a specific device belongs to.
func (h *DeviceGroupHandler) ListDeviceGroupsForDevice(ctx context.Context, req *connect.Request[pm.ListDeviceGroupsForDeviceRequest]) (*connect.Response[pm.ListDeviceGroupsForDeviceResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	groups, err := h.store.Repos().DeviceGroup.ListForDevice(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list groups for device")
	}

	// Device-group scope (#3): restrict the returned groups to the caller's scope
	// in Go — the underlying ListForDevice query is shared with the scope resolver
	// and must stay unfiltered there. A global holder keeps all groups.
	if scopeGroups, restricted := auth.DeviceScopeListFilter(ctx, "ListDeviceGroupsForDevice"); restricted {
		allowed := make(map[string]struct{}, len(scopeGroups))
		for _, id := range scopeGroups {
			allowed[id] = struct{}{}
		}
		kept := groups[:0]
		for _, g := range groups {
			if _, ok := allowed[g.ID]; ok {
				kept = append(kept, g)
			}
		}
		groups = kept
	}

	protoGroups := make([]*pm.DeviceGroup, len(groups))
	for i, g := range groups {
		protoGroups[i] = h.deviceGroupToProto(g)
	}

	return connect.NewResponse(&pm.ListDeviceGroupsForDeviceResponse{
		Groups: protoGroups,
	}), nil
}

// RenameDeviceGroup renames a device group.
func (h *DeviceGroupHandler) RenameDeviceGroup(ctx context.Context, req *connect.Request[pm.RenameDeviceGroupRequest]) (*connect.Response[pm.UpdateDeviceGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := auth.EnforceDeviceGroupScope(ctx, "RenameDeviceGroup", req.Msg.Id); err != nil {
		return nil, err
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "device_group",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.DeviceGroupRenamed),
		Data: payloads.DeviceGroupRenamed{
			Name: req.Msg.Name,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to rename device group"); err != nil {
		return nil, err
	}

	group, err := h.store.Repos().DeviceGroup.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceGroupNotFound, "device group not found")
	}

	return connect.NewResponse(&pm.UpdateDeviceGroupResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// UpdateDeviceGroupDescription updates a device group's description.
func (h *DeviceGroupHandler) UpdateDeviceGroupDescription(ctx context.Context, req *connect.Request[pm.UpdateDeviceGroupDescriptionRequest]) (*connect.Response[pm.UpdateDeviceGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := auth.EnforceDeviceGroupScope(ctx, "UpdateDeviceGroupDescription", req.Msg.Id); err != nil {
		return nil, err
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "device_group",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.DeviceGroupDescriptionUpdated),
		Data: payloads.DeviceGroupDescriptionUpdated{
			Description: req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to update description"); err != nil {
		return nil, err
	}

	group, err := h.store.Repos().DeviceGroup.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceGroupNotFound, "device group not found")
	}

	return connect.NewResponse(&pm.UpdateDeviceGroupResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// DeleteDeviceGroup deletes a device group.
func (h *DeviceGroupHandler) DeleteDeviceGroup(ctx context.Context, req *connect.Request[pm.DeleteDeviceGroupRequest]) (*connect.Response[pm.DeleteDeviceGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := auth.EnforceDeviceGroupScope(ctx, "DeleteDeviceGroup", req.Msg.Id); err != nil {
		return nil, err
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "device_group",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.DeviceGroupDeleted),
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to delete device group"); err != nil {
		return nil, err
	}

	if h.searchIdx != nil {
		if err := h.searchIdx.EnqueueRemove(ctx, search.ScopeDeviceGroup, req.Msg.Id, nil); err != nil {
			h.logger.Warn("failed to enqueue search remove", "scope", "device_group", "error", err)
		}
	}

	return connect.NewResponse(&pm.DeleteDeviceGroupResponse{}), nil
}

// AddDeviceToGroup adds a device to a group.
func (h *DeviceGroupHandler) AddDeviceToGroup(ctx context.Context, req *connect.Request[pm.AddDeviceToGroupRequest]) (*connect.Response[pm.AddDeviceToGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Collect device IDs from single + repeated fields
	deviceIDs := append([]string{}, req.Msg.DeviceIds...)
	if req.Msg.DeviceId != "" {
		deviceIDs = append(deviceIDs, req.Msg.DeviceId)
	}
	if len(deviceIDs) == 0 {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "at least one device_id or device_ids must be set")
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Scope (#3): the target group must be in the caller's device-group scope
	// (direct id-match), AND every device being added must already be within the
	// caller's scope (membership). The device check is load-bearing: without it a
	// device-group-scoped admin could pull any fleet device into a group they
	// control and thereby expand their own scope — a scope escape. RemoveDevice
	// needs only the group check (removal cannot expand scope).
	if err := auth.EnforceDeviceGroupScope(ctx, "AddDeviceToGroup", req.Msg.GroupId); err != nil {
		return nil, err
	}
	resolver := newScopeResolver(h.store)
	for _, deviceID := range deviceIDs {
		if err := auth.EnforceDeviceScopeOnBaseTier(ctx, resolver, "AddDeviceToGroup", deviceID); err != nil {
			return nil, err
		}
	}

	q := h.store.Queries()

	// Verify group exists and is not dynamic
	group, err := h.store.Repos().DeviceGroup.Get(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceGroupNotFound, "device group not found")
	}

	// Cannot manually add members to dynamic groups
	if group.IsDynamic {
		return nil, apiErrorCtx(ctx, ErrDynamicGroupManualModify, connect.CodeFailedPrecondition, "cannot manually add members to dynamic groups")
	}

	for _, deviceID := range deviceIDs {
		// Verify device exists
		_, err = q.GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: deviceID})
		if err != nil {
			if store.IsNotFound(err) {
				return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device")
		}

		if err := appendEvent(ctx, h.store, h.logger, store.Event{
			StreamType: "device_group",
			StreamID:   req.Msg.GroupId,
			EventType:  string(eventtypes.DeviceGroupMemberAdded),
			Data: payloads.DeviceGroupMemberAdded{
				DeviceID: deviceID,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		}, "failed to add device to group"); err != nil {
			return nil, err
		}
	}

	group, err = h.store.Repos().DeviceGroup.Get(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	return connect.NewResponse(&pm.AddDeviceToGroupResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// RemoveDeviceFromGroup removes a device from a group.
func (h *DeviceGroupHandler) RemoveDeviceFromGroup(ctx context.Context, req *connect.Request[pm.RemoveDeviceFromGroupRequest]) (*connect.Response[pm.RemoveDeviceFromGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := auth.EnforceDeviceGroupScope(ctx, "RemoveDeviceFromGroup", req.Msg.GroupId); err != nil {
		return nil, err
	}

	// Verify group exists and is not dynamic
	group, err := h.store.Repos().DeviceGroup.Get(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceGroupNotFound, "device group not found")
	}

	// Cannot manually remove members from dynamic groups
	if group.IsDynamic {
		return nil, apiErrorCtx(ctx, ErrDynamicGroupManualModify, connect.CodeFailedPrecondition, "cannot manually remove members from dynamic groups")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "device_group",
		StreamID:   req.Msg.GroupId,
		EventType:  string(eventtypes.DeviceGroupMemberRemoved),
		Data: payloads.DeviceGroupMemberRemoved{
			DeviceID: req.Msg.DeviceId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to remove device from group"); err != nil {
		return nil, err
	}

	group, err = h.store.Repos().DeviceGroup.Get(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	return connect.NewResponse(&pm.RemoveDeviceFromGroupResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// UpdateDeviceGroupQuery updates a device group's dynamic query.
//
// Defensive check (server #7 T-S2 update pathway): the target group
// MUST currently be dynamic. This RPC does NOT promote a static
// group to dynamic — that would let a holder of
// UpdateDynamicDeviceGroupQuery silently convert a static group
// into a dynamic one, bypassing the CreateDynamicDeviceGroup gate.
// A separate (future) RPC owns the convert operation if anyone
// needs it. Permission gating (via ProcedureAlternatives) is
// already exclusively UpdateDynamicDeviceGroupQuery, so this check
// belt-and-suspenders against accidental misuse.
func (h *DeviceGroupHandler) UpdateDeviceGroupQuery(ctx context.Context, req *connect.Request[pm.UpdateDeviceGroupQueryRequest]) (*connect.Response[pm.UpdateDeviceGroupQueryResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Same T-S2 bypass guard as CreateDeviceGroup: empty dynamic
	// query evaluates as match-all, so an IsDynamic=true with an
	// empty query would persist a group that scoops up every
	// device. Reject at the boundary. Flagged in #333 review.
	if req.Msg.IsDynamic && req.Msg.DynamicQuery == "" {
		return nil, apiErrorCtx(ctx, ErrInvalidQuery, connect.CodeInvalidArgument, "is_dynamic=true requires a non-empty dynamic_query")
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Defensive: the target group must already be dynamic.
	current, err := h.store.Repos().DeviceGroup.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceGroupNotFound, "device group not found")
	}
	if !current.IsDynamic {
		return nil, apiErrorCtx(ctx, ErrInvalidQuery, connect.CodeFailedPrecondition,
			"cannot apply UpdateDeviceGroupQuery to a static device group; use a dedicated convert operation if you need to change the group's kind")
	}

	// Validate dynamic query if provided
	if req.Msg.IsDynamic && req.Msg.DynamicQuery != "" {
		if len(req.Msg.DynamicQuery) > maxDynamicQueryLength {
			return nil, apiErrorCtx(ctx, ErrInvalidQuery, connect.CodeInvalidArgument, "dynamic_query exceeds maximum length")
		}
		if err := dynamicquery.ValidateDeviceQuery(req.Msg.DynamicQuery); err != nil {
			return nil, apiErrorCtx(ctx, ErrInvalidQuery, connect.CodeInvalidArgument, err.Error())
		}
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "device_group",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.DeviceGroupQueryUpdated),
		Data: payloads.DeviceGroupQueryUpdated{
			IsDynamic:    req.Msg.IsDynamic,
			DynamicQuery: req.Msg.DynamicQuery,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to update query"); err != nil {
		return nil, err
	}

	group, err := h.store.Repos().DeviceGroup.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceGroupNotFound, "device group not found")
	}

	return connect.NewResponse(&pm.UpdateDeviceGroupQueryResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// ValidateDynamicQuery validates a dynamic query without creating a group.
func (h *DeviceGroupHandler) ValidateDynamicQuery(ctx context.Context, req *connect.Request[pm.ValidateDynamicQueryRequest]) (*connect.Response[pm.ValidateDynamicQueryResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if err := dynamicquery.ValidateDeviceQuery(req.Msg.Query); err != nil {
		return connect.NewResponse(&pm.ValidateDynamicQueryResponse{
			Valid: false,
			Error: err.Error(),
		}), nil
	}

	// Count matching devices via the in-process evaluator (Wave C.3).
	matchingCount, err := dyngroupeval.New(h.store, h.logger).CountMatchingDevices(ctx, req.Msg.Query)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count matching devices")
	}

	return connect.NewResponse(&pm.ValidateDynamicQueryResponse{
		Valid:               true,
		MatchingDeviceCount: int32(matchingCount),
	}), nil
}

// EvaluateDynamicGroup triggers re-evaluation of a dynamic group.
func (h *DeviceGroupHandler) EvaluateDynamicGroup(ctx context.Context, req *connect.Request[pm.EvaluateDynamicGroupRequest]) (*connect.Response[pm.EvaluateDynamicGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Verify group exists and is dynamic
	group, err := h.store.Repos().DeviceGroup.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceGroupNotFound, "device group not found")
	}

	if !group.IsDynamic {
		return nil, apiErrorCtx(ctx, ErrGroupNotDynamic, connect.CodeFailedPrecondition, "group is not dynamic")
	}

	// Get current member count before evaluation
	membersBefore := group.MemberCount

	// Trigger in-process evaluation (Wave C.3).
	if err := dyngroupeval.New(h.store, h.logger).EvaluateDeviceGroup(ctx, req.Msg.Id); err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to evaluate dynamic group")
	}

	// Get updated group
	group, err = h.store.Repos().DeviceGroup.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	// Calculate added/removed (simplified - actual counts would need more tracking)
	devicesAdded := int32(0)
	devicesRemoved := int32(0)
	if group.MemberCount > membersBefore {
		devicesAdded = group.MemberCount - membersBefore
	} else if group.MemberCount < membersBefore {
		devicesRemoved = membersBefore - group.MemberCount
	}

	return connect.NewResponse(&pm.EvaluateDynamicGroupResponse{
		Group:          h.deviceGroupToProto(group),
		DevicesAdded:   devicesAdded,
		DevicesRemoved: devicesRemoved,
	}), nil
}

// SetDeviceGroupSyncInterval sets the sync interval for a device group.
func (h *DeviceGroupHandler) SetDeviceGroupSyncInterval(ctx context.Context, req *connect.Request[pm.SetDeviceGroupSyncIntervalRequest]) (*connect.Response[pm.UpdateDeviceGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := auth.EnforceDeviceGroupScope(ctx, "SetDeviceGroupSyncInterval", req.Msg.Id); err != nil {
		return nil, err
	}

	// Validate interval (0 = default, max 1440 = 24 hours)
	if req.Msg.SyncIntervalMinutes < 0 || req.Msg.SyncIntervalMinutes > 1440 {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "sync interval must be between 0 and 1440 minutes")
	}

	// Verify group exists
	_, err = h.store.Repos().DeviceGroup.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceGroupNotFound, "device group not found")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "device_group",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.DeviceGroupSyncIntervalSet),
		Data: payloads.DeviceGroupSyncIntervalSet{
			SyncIntervalMinutes: req.Msg.SyncIntervalMinutes,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to set sync interval"); err != nil {
		return nil, err
	}

	group, err := h.store.Repos().DeviceGroup.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	return connect.NewResponse(&pm.UpdateDeviceGroupResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// SetDeviceGroupMaintenanceWindow replaces the device group's
// maintenance window. The agent ORs each reaching group's window
// into a device-side union and gates non-instant action dispatch by
// the result; passing an empty MaintenanceWindow clears the group's
// contribution. See manchtools/power-manage-server#58.
func (h *DeviceGroupHandler) SetDeviceGroupMaintenanceWindow(ctx context.Context, req *connect.Request[pm.SetDeviceGroupMaintenanceWindowRequest]) (*connect.Response[pm.UpdateDeviceGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := auth.EnforceDeviceGroupScope(ctx, "SetDeviceGroupMaintenanceWindow", req.Msg.Id); err != nil {
		return nil, err
	}

	if err := maintenance.Validate(req.Msg.MaintenanceWindow); err != nil {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, err.Error())
	}

	if _, err := h.store.Repos().DeviceGroup.Get(ctx, req.Msg.Id); err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceGroupNotFound, "device group not found")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "device_group",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.DeviceGroupMaintenanceWindowSet),
		Data: payloads.DeviceGroupMaintenanceWindowSet{
			MaintenanceWindow: maintenanceWindowToMap(req.Msg.MaintenanceWindow),
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to set maintenance window"); err != nil {
		return nil, err
	}

	group, err := h.store.Repos().DeviceGroup.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	return connect.NewResponse(&pm.UpdateDeviceGroupResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

func (h *DeviceGroupHandler) deviceGroupToProto(g store.DeviceGroup) *pm.DeviceGroup {
	group := &pm.DeviceGroup{
		Id:                  g.ID,
		Name:                g.Name,
		Description:         g.Description,
		MemberCount:         g.MemberCount,
		CreatedBy:           g.CreatedBy,
		IsDynamic:           g.IsDynamic,
		SyncIntervalMinutes: g.SyncIntervalMinutes,
		MaintenanceWindow:   maintenanceWindowFromJSON(g.MaintenanceWindow),
	}

	if g.DynamicQuery != nil {
		group.DynamicQuery = *g.DynamicQuery
	}

	if g.CreatedAt != nil {
		group.CreatedAt = timestamppb.New(*g.CreatedAt)
	}

	return group
}
