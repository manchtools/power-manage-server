package device

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"time"

	"connectrpc.com/connect"
	"github.com/go-playground/validator/v10"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	defaultPageSize          = int32(50)
	maxLabelFilters          = 64
	maxInventoryTableFilters = 128
	resultTimeout            = 5 * time.Minute
)

// Config supplies the direct PostgreSQL store and process-local seams used by
// the device handlers.
type Config struct {
	Store       *store.Store
	Logger      *slog.Logger
	Now         func() time.Time
	CloseStream func(deviceID string)
}

// Handlers implements the device CRUD procedures.
type Handlers struct {
	store       *store.Store
	logger      *slog.Logger
	now         func() time.Time
	closeStream func(string)
	validator   *validator.Validate
}

// New constructs the device handlers. A missing store is a boot-time wiring
// defect and is rejected immediately.
func New(cfg Config) *Handlers {
	if cfg.Store == nil {
		panic("device: store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.CloseStream == nil {
		panic("device: stream closer is required")
	}
	return &Handlers{
		store: cfg.Store, logger: cfg.Logger, now: cfg.Now,
		closeStream: cfg.CloseStream, validator: sdkvalidate.NewValidator(),
	}
}

func (h *Handlers) validate(ctx context.Context, message any) error {
	if detail, ok := sdkvalidate.Struct(h.validator, message); !ok {
		return rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, detail)
	}
	return nil
}

func validateRequest[T any](h *Handlers, ctx context.Context, req *connect.Request[T]) error {
	if req == nil || req.Msg == nil {
		return rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "request is required")
	}
	return h.validate(ctx, req.Msg)
}

func (h *Handlers) actor(ctx context.Context) (*auth.UserContext, error) {
	actor, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, rpcError(ctx, errNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}
	return actor, nil
}

func (h *Handlers) authorize(ctx context.Context, permission, resourceID string) error {
	if !auth.AuthorizeContext(ctx, permission, resourceID) {
		return rpcError(ctx, errPermissionDenied, connect.CodePermissionDenied, "permission denied")
	}
	return nil
}

func (h *Handlers) internal(ctx context.Context, operation string, err error) *connect.Error {
	h.logger.Error("device RPC failed", "operation", operation, "error", err)
	return rpcError(ctx, errInternal, connect.CodeInternal, "internal error")
}

type scopeResolver struct{ store *store.Store }

func (r scopeResolver) DeviceGroupsForDevice(ctx context.Context, deviceID string) ([]string, error) {
	return r.store.ListDeviceGroupIDs(ctx, deviceID)
}

func (scopeResolver) UserGroupsForUser(context.Context, string) ([]string, error) {
	return nil, fmt.Errorf("user scope resolution is unavailable in the device domain")
}

func (h *Handlers) enforceDeviceScope(ctx context.Context, permission, deviceID string) error {
	err := auth.EnforceDeviceScopeOnBaseTier(ctx, scopeResolver{h.store}, permission, deviceID)
	if err == nil {
		return nil
	}
	if connect.CodeOf(err) == connect.CodeInternal {
		return h.internal(ctx, "resolve device scope", err)
	}
	return notFound(ctx, errDeviceNotFound, "device not found")
}

func (h *Handlers) readDevice(ctx context.Context, permission, deviceID string) (store.DeviceView, error) {
	if err := h.authorize(ctx, permission, deviceID); err != nil {
		return store.DeviceView{}, err
	}
	view, err := h.store.GetDeviceView(ctx, deviceID)
	if err != nil {
		if store.IsNotFound(err) {
			return store.DeviceView{}, notFound(ctx, errDeviceNotFound, "device not found")
		}
		return store.DeviceView{}, h.internal(ctx, "read device", err)
	}
	if auth.HasPermission(ctx, permission) {
		if err := h.enforceDeviceScope(ctx, permission, deviceID); err != nil {
			return store.DeviceView{}, err
		}
		return view, nil
	}
	actor, _ := auth.UserFromContext(ctx)
	assigned, err := h.store.IsDeviceAssignedToUser(ctx, deviceID, actor.ID)
	if err != nil {
		return store.DeviceView{}, h.internal(ctx, "check device assignment", err)
	}
	if !assigned {
		return store.DeviceView{}, notFound(ctx, errDeviceNotFound, "device not found")
	}
	return view, nil
}

func (h *Handlers) mutationDevice(ctx context.Context, permission, deviceID string) (store.DeviceView, error) {
	if err := h.authorize(ctx, permission, deviceID); err != nil {
		return store.DeviceView{}, err
	}
	view, err := h.store.GetDeviceView(ctx, deviceID)
	if err != nil {
		if store.IsNotFound(err) {
			return store.DeviceView{}, notFound(ctx, errDeviceNotFound, "device not found")
		}
		return store.DeviceView{}, h.internal(ctx, "read mutation target", err)
	}
	if err := h.enforceDeviceScope(ctx, permission, deviceID); err != nil {
		return store.DeviceView{}, err
	}
	return view, nil
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

func (h *Handlers) recordSensitiveRead(
	ctx context.Context,
	req connect.AnyRequest,
	actor *auth.UserContext,
	procedure, permission, resourceType, resourceID string,
) error {
	op := h.operation(req, actor, procedure, permission)
	op.Class = store.ClassSensitiveRead
	if _, err := h.store.RecordOperation(ctx, op, store.AuditEffect{
		ResourceType: resourceType, ResourceID: resourceID,
		Action: "READ", Outcome: store.EffectApplied,
	}); err != nil {
		return h.internal(ctx, "record sensitive read", err)
	}
	return nil
}

// ListDevices returns a keyset page narrowed in SQL by assignment, device
// scope, status, and exact label matches.
func (h *Handlers) ListDevices(ctx context.Context, req *connect.Request[pmv1.ListDevicesRequest]) (*connect.Response[pmv1.ListDevicesResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "ListDevices", ""); err != nil {
		return nil, err
	}
	if len(req.Msg.LabelFilter) > maxLabelFilters {
		return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "too many label filters")
	}
	if req.Msg.PageToken != "" {
		if _, err := ulid.ParseStrict(req.Msg.PageToken); err != nil {
			return nil, rpcError(ctx, errInvalidPageToken, connect.CodeInvalidArgument, "invalid page token")
		}
	}
	limit := req.Msg.PageSize
	if limit == 0 {
		limit = defaultPageSize
	}
	filter := store.DeviceListFilter{
		AfterID: req.Msg.PageToken, Limit: limit + 1,
		Status: store.DeviceStatusFilter(req.Msg.StatusFilter), Labels: req.Msg.LabelFilter,
		OnlineSince: h.now().Add(-onlineWindow),
	}
	if req.Msg.MyDevicesOnly || !auth.HasPermission(ctx, "ListDevices") {
		filter.AssignedUserID = &actor.ID
	}
	filter.ScopeGroupIDs, filter.ScopeRestricted = auth.DeviceScopeListFilter(ctx, "ListDevices")
	views, err := h.store.ListDeviceViews(ctx, filter)
	if err != nil {
		return nil, h.internal(ctx, "list devices", err)
	}
	hasMore := len(views) > int(limit)
	if hasMore {
		views = views[:limit]
	}
	countFilter := filter
	countFilter.AfterID = ""
	countFilter.Limit = 0
	total, err := h.store.CountDeviceViews(ctx, countFilter)
	if err != nil {
		return nil, h.internal(ctx, "count devices", err)
	}
	devices := make([]*pmv1.Device, len(views))
	for i := range views {
		devices[i] = h.toProto(views[i])
	}
	next := ""
	if hasMore {
		next = views[len(views)-1].ID
	}
	if total > math.MaxInt32 {
		total = math.MaxInt32
	}
	return connect.NewResponse(&pmv1.ListDevicesResponse{
		Devices: devices, NextPageToken: next, TotalCount: int32(total),
	}), nil
}

// GetDevice returns one visible device without revealing hidden device IDs.
func (h *Handlers) GetDevice(ctx context.Context, req *connect.Request[pmv1.GetDeviceRequest]) (*connect.Response[pmv1.GetDeviceResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	view, err := h.readDevice(ctx, "GetDevice", req.Msg.Id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.GetDeviceResponse{Device: h.toProto(view)}), nil
}

// GetDeviceInventory returns the latest directly stored osquery tables for a
// visible device.
func (h *Handlers) GetDeviceInventory(ctx context.Context, req *connect.Request[pmv1.GetDeviceInventoryRequest]) (*connect.Response[pmv1.GetDeviceInventoryResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if len(req.Msg.TableNames) > maxInventoryTableFilters {
		return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "too many inventory table filters")
	}
	if _, err := h.readDevice(ctx, "GetDeviceInventory", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	rows, err := h.store.ListDeviceInventory(ctx, req.Msg.DeviceId, req.Msg.TableNames)
	if err != nil {
		return nil, h.internal(ctx, "list device inventory", err)
	}
	tables := make([]*pmv1.InventoryTableResult, len(rows))
	for i, row := range rows {
		var values []map[string]string
		if err := json.Unmarshal(row.Rows, &values); err != nil {
			return nil, h.internal(ctx, "decode device inventory", err)
		}
		protoRows := make([]*pmv1.OSQueryRow, len(values))
		for j, value := range values {
			protoRows[j] = &pmv1.OSQueryRow{Data: value}
		}
		tables[i] = &pmv1.InventoryTableResult{
			TableName: row.TableName, Rows: protoRows,
			CollectedAt: timestamppb.New(row.CollectedAt),
		}
	}
	if err := h.recordSensitiveRead(ctx, req, actor,
		powermanagev1connect.ControlServiceGetDeviceInventoryProcedure, "GetDeviceInventory",
		"device_inventory", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.GetDeviceInventoryResponse{Tables: tables}), nil
}

// GetOSQueryResult returns one directly stored on-demand query result.
func (h *Handlers) GetOSQueryResult(ctx context.Context, req *connect.Request[pmv1.GetOSQueryResultRequest]) (*connect.Response[pmv1.GetOSQueryResultResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "GetOSQueryResult", ""); err != nil {
		return nil, err
	}
	result, err := h.store.GetOSQueryResult(ctx, req.Msg.QueryId)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, errQueryResultMissing, "query result not found")
		}
		return nil, h.internal(ctx, "read osquery result", err)
	}
	if _, err := h.readDevice(ctx, "GetOSQueryResult", result.DeviceID); err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			return nil, notFound(ctx, errQueryResultMissing, "query result not found")
		}
		return nil, err
	}

	response := &pmv1.GetOSQueryResultResponse{
		QueryId: result.QueryID, Completed: result.Completed,
		Success: result.Success, Error: result.Error,
	}
	if !result.Completed && h.now().Sub(result.CreatedAt) > resultTimeout {
		response.Completed = true
		response.Success = false
		response.Error = "query timed out: device did not respond within 5 minutes"
	} else if result.Completed && result.Success {
		var values []map[string]string
		if err := json.Unmarshal(result.Rows, &values); err != nil {
			return nil, h.internal(ctx, "decode osquery result", err)
		}
		response.Rows = make([]*pmv1.OSQueryRow, len(values))
		for i, value := range values {
			response.Rows[i] = &pmv1.OSQueryRow{Data: value}
		}
	}
	if err := h.recordSensitiveRead(ctx, req, actor,
		powermanagev1connect.ControlServiceGetOSQueryResultProcedure, "GetOSQueryResult",
		"osquery_result", result.QueryID); err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

// GetDeviceLogResult returns one directly stored remote log query result.
func (h *Handlers) GetDeviceLogResult(ctx context.Context, req *connect.Request[pmv1.GetDeviceLogResultRequest]) (*connect.Response[pmv1.GetDeviceLogResultResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "GetDeviceLogResult", ""); err != nil {
		return nil, err
	}
	result, err := h.store.GetDeviceLogResult(ctx, req.Msg.QueryId)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, errQueryResultMissing, "log query result not found")
		}
		return nil, h.internal(ctx, "read device log result", err)
	}
	if _, err := h.readDevice(ctx, "GetDeviceLogResult", result.DeviceID); err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			return nil, notFound(ctx, errQueryResultMissing, "log query result not found")
		}
		return nil, err
	}

	response := &pmv1.GetDeviceLogResultResponse{
		QueryId: result.QueryID, Completed: result.Completed,
		Success: result.Success, Error: result.Error, Logs: result.Logs,
	}
	if !result.Completed && h.now().Sub(result.CreatedAt) > resultTimeout {
		response.Completed = true
		response.Success = false
		response.Error = "log query timed out: device did not respond within 5 minutes"
		response.Logs = ""
	}
	if err := h.recordSensitiveRead(ctx, req, actor,
		powermanagev1connect.ControlServiceGetDeviceLogResultProcedure, "GetDeviceLogResult",
		"device_log_result", result.QueryID); err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

// ListDeviceAssignees returns the live users and groups assigned to a device.
func (h *Handlers) ListDeviceAssignees(ctx context.Context, req *connect.Request[pmv1.ListDeviceAssigneesRequest]) (*connect.Response[pmv1.ListDeviceAssigneesResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "ListDeviceAssignees", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	rows, err := h.store.ListDeviceAssignees(ctx, req.Msg.DeviceId)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, errDeviceNotFound, "device not found")
		}
		return nil, h.internal(ctx, "list device assignees", err)
	}
	assignees := make([]*pmv1.DeviceAssignee, len(rows))
	for i, row := range rows {
		var kind pmv1.AssignmentTargetType
		switch row.Kind {
		case "user":
			kind = pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER
		case "user_group":
			kind = pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER_GROUP
		default:
			return nil, h.internal(ctx, "list device assignees", fmt.Errorf("unknown assignee kind"))
		}
		assignees[i] = &pmv1.DeviceAssignee{Id: row.ID, Type: kind, Name: row.Name}
	}
	return connect.NewResponse(&pmv1.ListDeviceAssigneesResponse{Assignees: assignees}), nil
}
