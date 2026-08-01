package devicegroup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/go-playground/validator/v10"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage-sdk/maintenance"
	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/store"
)

const defaultPageSize = int32(50)

// HandlersConfig supplies the direct store and process-local seams.
type HandlersConfig struct {
	Store  *store.Store
	Logger *slog.Logger
	Now    func() time.Time
}

// Handlers implements explicit device-group CRUD and static membership.
type Handlers struct {
	store     *store.Store
	state     *State
	logger    *slog.Logger
	validator *validator.Validate
}

// NewHandlers constructs direct device-group handlers.
func NewHandlers(cfg HandlersConfig) *Handlers {
	if cfg.Store == nil {
		panic("device group: handler store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Handlers{
		store: cfg.Store, state: NewState(Config{Store: cfg.Store, Now: cfg.Now}),
		logger: cfg.Logger, validator: sdkvalidate.NewValidator(),
	}
}

func validateRequest[T any](h *Handlers, ctx context.Context, req *connect.Request[T]) error {
	if req == nil || req.Msg == nil {
		return rpcError(ctx, "validation_failed", connect.CodeInvalidArgument, "request is required")
	}
	if detail, ok := sdkvalidate.Struct(h.validator, req.Msg); !ok {
		return rpcError(ctx, "validation_failed", connect.CodeInvalidArgument, detail)
	}
	return nil
}

func (h *Handlers) actor(ctx context.Context) (*auth.UserContext, error) {
	actor, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, rpcError(ctx, "not_authenticated", connect.CodeUnauthenticated, "not authenticated")
	}
	return actor, nil
}

func (h *Handlers) authorize(ctx context.Context, permission, resourceID string) error {
	if !auth.AuthorizeContext(ctx, permission, resourceID) {
		return rpcError(ctx, "permission_denied", connect.CodePermissionDenied, "permission denied")
	}
	return nil
}

func (h *Handlers) readScope(ctx context.Context, permission, id string) error {
	if err := h.authorize(ctx, permission, id); err != nil {
		return err
	}
	groups, restricted := auth.DeviceScopeListFilter(ctx, permission)
	if restricted && !contains(groups, id) {
		return rpcError(ctx, "device_group_not_found", connect.CodeNotFound, "device group not found")
	}
	return nil
}

func (h *Handlers) writeScope(ctx context.Context, permission, id string) error {
	if err := h.authorize(ctx, permission, id); err != nil {
		return err
	}
	groups, restricted := auth.DeviceScopeListFilter(ctx, permission)
	if restricted && !contains(groups, id) {
		return rpcError(ctx, "permission_denied", connect.CodePermissionDenied, "permission denied")
	}
	return nil
}

func (h *Handlers) operation(req connect.AnyRequest, actor *auth.UserContext, procedure, permission string) store.AuditOperation {
	op := store.AuditOperation{
		Class: store.ClassMutation, ActorType: string(actor.Kind), Origin: auth.ControlRPCOrigin,
		RequestDescriptor: procedure, AuthorizationOutcome: store.AuthorizationAllowed,
		AuthorizationDetail: permission, Result: store.ResultSuccess, ResultCode: "OK",
	}
	if actor.CanOwnResources() {
		op.ActorID = actor.ID
	}
	if ip := auth.ClientIP(req); ip != "" {
		op.OriginFingerprint = auth.Fingerprint(ip)
	}
	return op
}

// CreateDeviceGroup creates one static or dynamic group.
func (h *Handlers) CreateDeviceGroup(ctx context.Context, req *connect.Request[pmv1.CreateDeviceGroupRequest]) (*connect.Response[pmv1.CreateDeviceGroupResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	permission := "CreateStaticDeviceGroup"
	if req.Msg.IsDynamic {
		permission = "CreateDynamicDeviceGroup"
	}
	if !auth.HasPermission(ctx, permission) {
		return nil, rpcError(ctx, "permission_denied", connect.CodePermissionDenied, "permission denied")
	}
	row, err := h.state.Create(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceCreateDeviceGroupProcedure, permission), CreateParams{
		Name: req.Msg.Name, Description: req.Msg.Description, CreatedBy: actor.ID,
		Dynamic: req.Msg.IsDynamic, Query: req.Msg.DynamicQuery,
	})
	if err != nil {
		return nil, h.mapError(ctx, "create device group", err)
	}
	group, err := h.groupProto(row)
	if err != nil {
		return nil, h.internal(ctx, "encode created device group", err)
	}
	return connect.NewResponse(&pmv1.CreateDeviceGroupResponse{Group: group}), nil
}

// GetDeviceGroup returns one visible group and its live members.
func (h *Handlers) GetDeviceGroup(ctx context.Context, req *connect.Request[pmv1.GetDeviceGroupRequest]) (*connect.Response[pmv1.GetDeviceGroupResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	if err := h.readScope(ctx, "GetDeviceGroup", req.Msg.Id); err != nil {
		return nil, err
	}
	row, err := h.store.GetDeviceGroup(ctx, req.Msg.Id)
	if err != nil {
		return nil, h.mapError(ctx, "get device group", err)
	}
	members, err := h.store.ListDeviceGroupMembers(ctx, req.Msg.Id)
	if err != nil {
		return nil, h.internal(ctx, "list device group members", err)
	}
	group, err := h.groupProto(row)
	if err != nil {
		return nil, h.internal(ctx, "decode device group", err)
	}
	ids := make([]string, len(members))
	devices := make([]*pmv1.DeviceGroupMember, len(members))
	for i, member := range members {
		ids[i] = member.DeviceID
		devices[i] = &pmv1.DeviceGroupMember{
			DeviceId: member.DeviceID, Hostname: member.Hostname, AgentVersion: member.AgentVersion,
		}
		if member.LastSeenAt != nil {
			devices[i].LastSeenAt = timestamppb.New(*member.LastSeenAt)
		}
	}
	return connect.NewResponse(&pmv1.GetDeviceGroupResponse{
		Group: group, DeviceIds: ids, Devices: devices,
	}), nil
}

// ListDeviceGroups returns a scoped PostgreSQL keyset page.
func (h *Handlers) ListDeviceGroups(ctx context.Context, req *connect.Request[pmv1.ListDeviceGroupsRequest]) (*connect.Response[pmv1.ListDeviceGroupsResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "ListDeviceGroups", ""); err != nil {
		return nil, err
	}
	if !validPageToken(req.Msg.PageToken) {
		return nil, rpcError(ctx, "invalid_page_token", connect.CodeInvalidArgument, "invalid page token")
	}
	limit := req.Msg.PageSize
	if limit == 0 {
		limit = defaultPageSize
	}
	groups, restricted := auth.DeviceScopeListFilter(ctx, "ListDeviceGroups")
	filter := store.DeviceGroupListFilter{
		AfterID: req.Msg.PageToken, Limit: limit + 1,
		ScopeRestricted: restricted, ScopeGroupIDs: groups,
	}
	rows, err := h.store.ListDeviceGroups(ctx, filter)
	if err != nil {
		return nil, h.internal(ctx, "list device groups", err)
	}
	hasMore := len(rows) > int(limit)
	if hasMore {
		rows = rows[:limit]
	}
	count, err := h.store.CountDeviceGroups(ctx, filter)
	if err != nil {
		return nil, h.internal(ctx, "count device groups", err)
	}
	out := make([]*pmv1.DeviceGroup, len(rows))
	for i, row := range rows {
		out[i], err = h.groupProto(row)
		if err != nil {
			return nil, h.internal(ctx, "decode listed device group", err)
		}
	}
	next := ""
	if hasMore {
		next = rows[len(rows)-1].ID
	}
	return connect.NewResponse(&pmv1.ListDeviceGroupsResponse{
		Groups: out, NextPageToken: next, TotalCount: boundedCount(count),
	}), nil
}

// ListDeviceGroupsForDevice returns visible groups containing one live device.
func (h *Handlers) ListDeviceGroupsForDevice(ctx context.Context, req *connect.Request[pmv1.ListDeviceGroupsForDeviceRequest]) (*connect.Response[pmv1.ListDeviceGroupsForDeviceResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "ListDeviceGroupsForDevice", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	if _, err := h.store.GetDevice(ctx, req.Msg.DeviceId); err != nil {
		if store.IsNotFound(err) {
			return nil, rpcError(ctx, "device_not_found", connect.CodeNotFound, "device not found")
		}
		return nil, h.internal(ctx, "read device for groups", err)
	}
	groups, restricted := auth.DeviceScopeListFilter(ctx, "ListDeviceGroupsForDevice")
	rows, err := h.store.ListDeviceGroupsForDevice(ctx, req.Msg.DeviceId, store.DeviceGroupListFilter{
		ScopeRestricted: restricted, ScopeGroupIDs: groups,
	})
	if err != nil {
		return nil, h.internal(ctx, "list groups for device", err)
	}
	out := make([]*pmv1.DeviceGroup, len(rows))
	for i, row := range rows {
		out[i], err = h.groupProto(row)
		if err != nil {
			return nil, h.internal(ctx, "decode device group for device", err)
		}
	}
	return connect.NewResponse(&pmv1.ListDeviceGroupsForDeviceResponse{Groups: out}), nil
}

// RenameDeviceGroup replaces a group name.
func (h *Handlers) RenameDeviceGroup(ctx context.Context, req *connect.Request[pmv1.RenameDeviceGroupRequest]) (*connect.Response[pmv1.UpdateDeviceGroupResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActor(ctx, req.Msg.Id, "RenameDeviceGroup")
	if err != nil {
		return nil, err
	}
	row, err := h.state.Rename(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceRenameDeviceGroupProcedure, "RenameDeviceGroup"), req.Msg.Id, req.Msg.Name)
	return h.updated(ctx, "rename device group", row, err)
}

// UpdateDeviceGroupDescription replaces a description.
func (h *Handlers) UpdateDeviceGroupDescription(ctx context.Context, req *connect.Request[pmv1.UpdateDeviceGroupDescriptionRequest]) (*connect.Response[pmv1.UpdateDeviceGroupResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActor(ctx, req.Msg.Id, "UpdateDeviceGroupDescription")
	if err != nil {
		return nil, err
	}
	row, err := h.state.UpdateDescription(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceUpdateDeviceGroupDescriptionProcedure, "UpdateDeviceGroupDescription"),
		req.Msg.Id, req.Msg.Description)
	return h.updated(ctx, "update device group description", row, err)
}

// UpdateDeviceGroupQuery replaces the group's membership mode and query.
func (h *Handlers) UpdateDeviceGroupQuery(ctx context.Context, req *connect.Request[pmv1.UpdateDeviceGroupQueryRequest]) (*connect.Response[pmv1.UpdateDeviceGroupQueryResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	const permission = "UpdateDynamicDeviceGroupQuery"
	actor, err := h.mutationActor(ctx, req.Msg.Id, permission)
	if err != nil {
		return nil, err
	}
	row, err := h.state.UpdateQuery(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceUpdateDeviceGroupQueryProcedure, permission),
		req.Msg.Id, req.Msg.IsDynamic, req.Msg.DynamicQuery)
	if err != nil {
		return nil, h.mapError(ctx, "update device group query", err)
	}
	group, err := h.groupProto(row)
	if err != nil {
		return nil, h.internal(ctx, "decode updated device group query", err)
	}
	return connect.NewResponse(&pmv1.UpdateDeviceGroupQueryResponse{Group: group}), nil
}

// DeleteDeviceGroup deletes a group and ordinary dependent state.
func (h *Handlers) DeleteDeviceGroup(ctx context.Context, req *connect.Request[pmv1.DeleteDeviceGroupRequest]) (*connect.Response[pmv1.DeleteDeviceGroupResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActor(ctx, req.Msg.Id, "DeleteDeviceGroup")
	if err != nil {
		return nil, err
	}
	if err := h.state.Delete(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceDeleteDeviceGroupProcedure, "DeleteDeviceGroup"), req.Msg.Id); err != nil {
		return nil, h.mapError(ctx, "delete device group", err)
	}
	return connect.NewResponse(&pmv1.DeleteDeviceGroupResponse{}), nil
}

// AddDeviceToGroup adds one or more devices to a static group.
func (h *Handlers) AddDeviceToGroup(ctx context.Context, req *connect.Request[pmv1.AddDeviceToGroupRequest]) (*connect.Response[pmv1.AddDeviceToGroupResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	ids := append([]string(nil), req.Msg.DeviceIds...)
	if req.Msg.DeviceId != "" {
		ids = append(ids, req.Msg.DeviceId)
	}
	if len(ids) == 0 || len(ids) > maxBatchDevices {
		return nil, rpcError(ctx, "validation_failed", connect.CodeInvalidArgument, "at least one device is required")
	}
	actor, err := h.mutationActor(ctx, req.Msg.GroupId, "AddDeviceToGroup")
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if err := h.enforceDeviceScope(ctx, "AddDeviceToGroup", id); err != nil {
			return nil, err
		}
		if _, err := h.store.GetDevice(ctx, id); err != nil {
			if store.IsNotFound(err) {
				return nil, rpcError(ctx, "device_not_found", connect.CodeNotFound, "device not found")
			}
			return nil, h.internal(ctx, "read device membership target", err)
		}
	}
	if _, err := h.state.AddDevices(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceAddDeviceToGroupProcedure, "AddDeviceToGroup"), req.Msg.GroupId, ids); err != nil {
		return nil, h.mapError(ctx, "add devices to group", err)
	}
	group, err := h.groupResponse(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.AddDeviceToGroupResponse{Group: group}), nil
}

// RemoveDeviceFromGroup removes one device from a static group.
func (h *Handlers) RemoveDeviceFromGroup(ctx context.Context, req *connect.Request[pmv1.RemoveDeviceFromGroupRequest]) (*connect.Response[pmv1.RemoveDeviceFromGroupResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActor(ctx, req.Msg.GroupId, "RemoveDeviceFromGroup")
	if err != nil {
		return nil, err
	}
	if err := h.state.RemoveDevice(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceRemoveDeviceFromGroupProcedure, "RemoveDeviceFromGroup"),
		req.Msg.GroupId, req.Msg.DeviceId); err != nil {
		return nil, h.mapError(ctx, "remove device from group", err)
	}
	group, err := h.groupResponse(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.RemoveDeviceFromGroupResponse{Group: group}), nil
}

// SetDeviceGroupSyncInterval replaces the sync contribution.
func (h *Handlers) SetDeviceGroupSyncInterval(ctx context.Context, req *connect.Request[pmv1.SetDeviceGroupSyncIntervalRequest]) (*connect.Response[pmv1.UpdateDeviceGroupResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActor(ctx, req.Msg.Id, "SetDeviceGroupSyncInterval")
	if err != nil {
		return nil, err
	}
	row, err := h.state.SetSyncInterval(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceSetDeviceGroupSyncIntervalProcedure, "SetDeviceGroupSyncInterval"),
		req.Msg.Id, req.Msg.SyncIntervalMinutes)
	return h.updated(ctx, "set device group sync interval", row, err)
}

// SetDeviceGroupInventoryInterval replaces the inventory contribution.
func (h *Handlers) SetDeviceGroupInventoryInterval(ctx context.Context, req *connect.Request[pmv1.SetDeviceGroupInventoryIntervalRequest]) (*connect.Response[pmv1.UpdateDeviceGroupResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.mutationActor(ctx, req.Msg.Id, "SetDeviceGroupInventoryInterval")
	if err != nil {
		return nil, err
	}
	row, err := h.state.SetInventoryInterval(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceSetDeviceGroupInventoryIntervalProcedure, "SetDeviceGroupInventoryInterval"),
		req.Msg.Id, req.Msg.InventoryIntervalMinutes)
	return h.updated(ctx, "set device group inventory interval", row, err)
}

// SetDeviceGroupMaintenanceWindow replaces the device-local dispatch window.
func (h *Handlers) SetDeviceGroupMaintenanceWindow(ctx context.Context, req *connect.Request[pmv1.SetDeviceGroupMaintenanceWindowRequest]) (*connect.Response[pmv1.UpdateDeviceGroupResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if err := maintenance.Validate(req.Msg.MaintenanceWindow); err != nil {
		return nil, rpcError(ctx, "validation_failed", connect.CodeInvalidArgument, err.Error())
	}
	actor, err := h.mutationActor(ctx, req.Msg.Id, "SetDeviceGroupMaintenanceWindow")
	if err != nil {
		return nil, err
	}
	raw := []byte("{}")
	if req.Msg.MaintenanceWindow != nil && len(req.Msg.MaintenanceWindow.Schedule) > 0 {
		raw, err = protojson.Marshal(req.Msg.MaintenanceWindow)
		if err != nil {
			return nil, h.internal(ctx, "encode maintenance window", err)
		}
	}
	row, err := h.state.SetMaintenanceWindow(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceSetDeviceGroupMaintenanceWindowProcedure, "SetDeviceGroupMaintenanceWindow"),
		req.Msg.Id, raw)
	return h.updated(ctx, "set device group maintenance window", row, err)
}

func (h *Handlers) mutationActor(ctx context.Context, id, permission string) (*auth.UserContext, error) {
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.writeScope(ctx, permission, id); err != nil {
		return nil, err
	}
	if _, err := h.store.GetDeviceGroup(ctx, id); err != nil {
		return nil, h.mapError(ctx, "read mutation target", err)
	}
	return actor, nil
}

type scopeResolver struct{ store *store.Store }

func (r scopeResolver) DeviceGroupsForDevice(ctx context.Context, deviceID string) ([]string, error) {
	ids, err := r.store.ListDeviceGroupIDs(ctx, deviceID)
	if store.IsNotFound(err) {
		return nil, nil
	}
	return ids, err
}

func (scopeResolver) UserGroupsForUser(context.Context, string) ([]string, error) {
	return nil, fmt.Errorf("user scope resolution is unavailable in the device-group domain")
}

func (h *Handlers) enforceDeviceScope(ctx context.Context, permission, deviceID string) error {
	err := auth.EnforceDeviceScopeOnBaseTier(ctx, scopeResolver{h.store}, permission, deviceID)
	if err == nil {
		return nil
	}
	if connect.CodeOf(err) == connect.CodeInternal {
		return h.internal(ctx, "resolve device scope", err)
	}
	return rpcError(ctx, "permission_denied", connect.CodePermissionDenied, "permission denied")
}

func (h *Handlers) updated(ctx context.Context, operation string, row store.DeviceGroupView, err error) (*connect.Response[pmv1.UpdateDeviceGroupResponse], error) {
	if err != nil {
		return nil, h.mapError(ctx, operation, err)
	}
	group, err := h.groupProto(row)
	if err != nil {
		return nil, h.internal(ctx, "decode updated device group", err)
	}
	return connect.NewResponse(&pmv1.UpdateDeviceGroupResponse{Group: group}), nil
}

func (h *Handlers) groupResponse(ctx context.Context, id string) (*pmv1.DeviceGroup, error) {
	row, err := h.store.GetDeviceGroup(ctx, id)
	if err != nil {
		return nil, h.mapError(ctx, "read changed device group", err)
	}
	group, err := h.groupProto(row)
	if err != nil {
		return nil, h.internal(ctx, "decode changed device group", err)
	}
	return group, nil
}

func (h *Handlers) groupProto(row store.DeviceGroupView) (*pmv1.DeviceGroup, error) {
	group := &pmv1.DeviceGroup{
		Id: row.ID, Name: row.Name, Description: row.Description,
		MemberCount: boundedCount(row.LiveMemberCount), CreatedBy: row.CreatedBy,
		IsDynamic: row.IsDynamic, SyncIntervalMinutes: row.SyncIntervalMinutes,
		InventoryIntervalMinutes: row.InventoryIntervalMinutes,
	}
	if row.DynamicQuery != nil {
		group.DynamicQuery = *row.DynamicQuery
	}
	if row.CreatedAt != nil {
		group.CreatedAt = timestamppb.New(*row.CreatedAt)
	}
	if len(row.MaintenanceWindow) > 0 && string(row.MaintenanceWindow) != "{}" {
		window := &pmv1.MaintenanceWindow{}
		if err := protojson.Unmarshal(row.MaintenanceWindow, window); err != nil {
			return nil, err
		}
		if len(window.Schedule) > 0 {
			group.MaintenanceWindow = window
		}
	}
	return group, nil
}

func (h *Handlers) mapError(ctx context.Context, operation string, err error) error {
	switch {
	case errors.Is(err, ErrInvalidInput):
		return rpcError(ctx, "validation_failed", connect.CodeInvalidArgument, "invalid device group")
	case errors.Is(err, ErrInvalidQuery):
		return rpcError(ctx, "invalid_dynamic_query", connect.CodeInvalidArgument, "invalid dynamic query")
	case errors.Is(err, ErrStaticGroup):
		return rpcError(ctx, "static_group_has_no_dynamic_query", connect.CodeFailedPrecondition, "static device group has no dynamic query")
	case errors.Is(err, ErrDynamicGroup):
		return rpcError(ctx, "dynamic_group_membership_managed", connect.CodeFailedPrecondition, "dynamic group membership is evaluator-managed")
	case errors.Is(err, ErrMemberNotFound):
		return rpcError(ctx, "device_group_member_not_found", connect.CodeNotFound, "device group member not found")
	case store.IsNotFound(err):
		return rpcError(ctx, "device_group_not_found", connect.CodeNotFound, "device group not found")
	default:
		return h.internal(ctx, operation, err)
	}
}

func (h *Handlers) internal(ctx context.Context, operation string, err error) *connect.Error {
	h.logger.Error("device-group RPC failed", "operation", operation, "error", err)
	return rpcError(ctx, "internal_error", connect.CodeInternal, "internal error")
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func validPageToken(token string) bool {
	if token == "" {
		return true
	}
	_, err := ulid.ParseStrict(token)
	return err == nil
}

func boundedCount(value int64) int32 {
	if value > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(value)
}

func rpcError(ctx context.Context, code string, connectCode connect.Code, message string) *connect.Error {
	err := connect.NewError(connectCode, errors.New(message))
	detail, detailErr := connect.NewErrorDetail(&pmv1.ErrorDetail{
		Code: code, RequestId: middleware.RequestIDFromContext(ctx),
	})
	if detailErr == nil {
		err.AddDetail(detail)
	}
	return err
}

// Mount registers the direct device-group surface. The two evaluator RPCs are
// mounted with the evaluator checkpoint, not as stubs.
func (h *Handlers) Mount(mux *http.ServeMux, opts ...connect.HandlerOption) []string {
	if mux == nil {
		panic("device group: mux is required")
	}
	mounted := make([]string, 0, 13)
	register := func(procedure string, handler http.Handler) {
		mux.Handle(procedure, handler)
		mounted = append(mounted, procedure)
	}
	register(powermanagev1connect.ControlServiceCreateDeviceGroupProcedure, connect.NewUnaryHandler(powermanagev1connect.ControlServiceCreateDeviceGroupProcedure, h.CreateDeviceGroup, opts...))
	register(powermanagev1connect.ControlServiceGetDeviceGroupProcedure, connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetDeviceGroupProcedure, h.GetDeviceGroup, opts...))
	register(powermanagev1connect.ControlServiceListDeviceGroupsProcedure, connect.NewUnaryHandler(powermanagev1connect.ControlServiceListDeviceGroupsProcedure, h.ListDeviceGroups, opts...))
	register(powermanagev1connect.ControlServiceListDeviceGroupsForDeviceProcedure, connect.NewUnaryHandler(powermanagev1connect.ControlServiceListDeviceGroupsForDeviceProcedure, h.ListDeviceGroupsForDevice, opts...))
	register(powermanagev1connect.ControlServiceRenameDeviceGroupProcedure, connect.NewUnaryHandler(powermanagev1connect.ControlServiceRenameDeviceGroupProcedure, h.RenameDeviceGroup, opts...))
	register(powermanagev1connect.ControlServiceUpdateDeviceGroupDescriptionProcedure, connect.NewUnaryHandler(powermanagev1connect.ControlServiceUpdateDeviceGroupDescriptionProcedure, h.UpdateDeviceGroupDescription, opts...))
	register(powermanagev1connect.ControlServiceUpdateDeviceGroupQueryProcedure, connect.NewUnaryHandler(powermanagev1connect.ControlServiceUpdateDeviceGroupQueryProcedure, h.UpdateDeviceGroupQuery, opts...))
	register(powermanagev1connect.ControlServiceDeleteDeviceGroupProcedure, connect.NewUnaryHandler(powermanagev1connect.ControlServiceDeleteDeviceGroupProcedure, h.DeleteDeviceGroup, opts...))
	register(powermanagev1connect.ControlServiceAddDeviceToGroupProcedure, connect.NewUnaryHandler(powermanagev1connect.ControlServiceAddDeviceToGroupProcedure, h.AddDeviceToGroup, opts...))
	register(powermanagev1connect.ControlServiceRemoveDeviceFromGroupProcedure, connect.NewUnaryHandler(powermanagev1connect.ControlServiceRemoveDeviceFromGroupProcedure, h.RemoveDeviceFromGroup, opts...))
	register(powermanagev1connect.ControlServiceSetDeviceGroupSyncIntervalProcedure, connect.NewUnaryHandler(powermanagev1connect.ControlServiceSetDeviceGroupSyncIntervalProcedure, h.SetDeviceGroupSyncInterval, opts...))
	register(powermanagev1connect.ControlServiceSetDeviceGroupInventoryIntervalProcedure, connect.NewUnaryHandler(powermanagev1connect.ControlServiceSetDeviceGroupInventoryIntervalProcedure, h.SetDeviceGroupInventoryInterval, opts...))
	register(powermanagev1connect.ControlServiceSetDeviceGroupMaintenanceWindowProcedure, connect.NewUnaryHandler(powermanagev1connect.ControlServiceSetDeviceGroupMaintenanceWindowProcedure, h.SetDeviceGroupMaintenanceWindow, opts...))
	return mounted
}

// MutationProcedures is the exact audited device-group mutation surface.
func MutationProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceCreateDeviceGroupProcedure,
		powermanagev1connect.ControlServiceRenameDeviceGroupProcedure,
		powermanagev1connect.ControlServiceUpdateDeviceGroupDescriptionProcedure,
		powermanagev1connect.ControlServiceUpdateDeviceGroupQueryProcedure,
		powermanagev1connect.ControlServiceDeleteDeviceGroupProcedure,
		powermanagev1connect.ControlServiceAddDeviceToGroupProcedure,
		powermanagev1connect.ControlServiceRemoveDeviceFromGroupProcedure,
		powermanagev1connect.ControlServiceSetDeviceGroupSyncIntervalProcedure,
		powermanagev1connect.ControlServiceSetDeviceGroupInventoryIntervalProcedure,
		powermanagev1connect.ControlServiceSetDeviceGroupMaintenanceWindowProcedure,
	}
}

// ReadProcedures is the exact non-mutating device-group surface.
func ReadProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceGetDeviceGroupProcedure,
		powermanagev1connect.ControlServiceListDeviceGroupsProcedure,
		powermanagev1connect.ControlServiceListDeviceGroupsForDeviceProcedure,
	}
}
