package device

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/go-playground/validator/v10"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/terminal"
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
	Store            *store.Store
	Logger           *slog.Logger
	Now              func() time.Time
	CloseStream      func(deviceID string)
	AgentSender      AgentSender
	Decryptor        *crypto.Encryptor
	TerminalTokens   *terminal.TokenStore
	TerminalSessions *connection.TerminalSessionRegistry
	TerminalURL      string
	IsConnected      func(deviceID string) bool
}

// AgentSender is the only outbound transport capability an instant device
// operation needs. The connection manager satisfies it directly.
type AgentSender interface {
	Send(deviceID string, message *pmv1.ServerMessage) error
}

// Handlers implements the device CRUD procedures.
type Handlers struct {
	store            *store.Store
	logger           *slog.Logger
	now              func() time.Time
	closeStream      func(string)
	agentSender      AgentSender
	decryptor        *crypto.Encryptor
	terminalTokens   *terminal.TokenStore
	terminalSessions *connection.TerminalSessionRegistry
	terminalURL      string
	isConnected      func(string) bool
	validator        *validator.Validate
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
	if cfg.AgentSender == nil {
		panic("device: agent sender is required")
	}
	if cfg.Decryptor == nil {
		panic("device: secret decryptor is required")
	}
	if cfg.TerminalTokens == nil || cfg.TerminalSessions == nil || cfg.IsConnected == nil {
		panic("device: terminal transport is required")
	}
	terminalURL := normalizeTerminalURL(cfg.TerminalURL)
	if terminalURL == "" {
		panic("device: secure terminal URL is required")
	}
	return &Handlers{
		store: cfg.Store, logger: cfg.Logger, now: cfg.Now,
		closeStream: cfg.CloseStream, agentSender: cfg.AgentSender, decryptor: cfg.Decryptor,
		terminalTokens: cfg.TerminalTokens, terminalSessions: cfg.TerminalSessions,
		terminalURL: terminalURL, isConnected: cfg.IsConnected,
		validator: sdkvalidate.NewValidator(),
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
	ids, err := r.store.ListDeviceGroupIDs(ctx, deviceID)
	if store.IsNotFound(err) {
		// Scope checks run before existence lookups. Unknown and out-of-scope
		// identifiers must therefore both reduce to "not in an allowed group".
		return nil, nil
	}
	return ids, err
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
	if resourceID == "" {
		if _, err := h.store.RecordOperation(ctx, op); err != nil {
			return h.internal(ctx, "record sensitive read", err)
		}
		return nil
	}
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

// GetDeviceCompliance returns the current direct compliance rows for one
// visible device.
func (h *Handlers) GetDeviceCompliance(ctx context.Context, req *connect.Request[pmv1.GetDeviceComplianceRequest]) (*connect.Response[pmv1.GetDeviceComplianceResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	view, err := h.readDevice(ctx, "GetDeviceCompliance", req.Msg.DeviceId)
	if err != nil {
		return nil, err
	}
	if !validComplianceStatus(view.ComplianceStatus) {
		return nil, h.internal(ctx, "decode device compliance status", fmt.Errorf("unknown status %d", view.ComplianceStatus))
	}
	rows, err := h.store.ListDeviceComplianceResults(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, h.internal(ctx, "list device compliance", err)
	}
	checks := make([]*pmv1.ComplianceCheckResult, len(rows))
	for i, row := range rows {
		output, err := decodeCommandOutput(row.DetectionOutput)
		if err != nil {
			return nil, h.internal(ctx, "decode compliance output", err)
		}
		checks[i] = &pmv1.ComplianceCheckResult{
			ActionId: row.ActionID, ActionName: row.ActionName,
			Compliant: row.Compliant, DetectionOutput: output,
			CheckedAt: timestamppb.New(row.CheckedAt),
		}
	}
	if err := h.recordSensitiveRead(ctx, req, actor,
		powermanagev1connect.ControlServiceGetDeviceComplianceProcedure, "GetDeviceCompliance",
		"device_compliance", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.GetDeviceComplianceResponse{
		Status: pmv1.ComplianceStatus(view.ComplianceStatus), Checks: checks,
	}), nil
}

// GetDeviceCompliancePolicyStatus returns the current direct policy-rule
// evaluations for one visible device.
func (h *Handlers) GetDeviceCompliancePolicyStatus(ctx context.Context, req *connect.Request[pmv1.GetDeviceCompliancePolicyStatusRequest]) (*connect.Response[pmv1.GetDeviceCompliancePolicyStatusResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	view, err := h.readDevice(ctx, "GetDeviceCompliancePolicyStatus", req.Msg.DeviceId)
	if err != nil {
		return nil, err
	}
	if !validComplianceStatus(view.ComplianceStatus) {
		return nil, h.internal(ctx, "decode device compliance status", fmt.Errorf("unknown status %d", view.ComplianceStatus))
	}
	rows, err := h.store.ListDeviceComplianceEvaluations(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, h.internal(ctx, "list device compliance policies", err)
	}

	policies := make([]*pmv1.DevicePolicyEvaluation, 0)
	var policy *pmv1.DevicePolicyEvaluation
	for _, row := range rows {
		if !validComplianceStatus(row.Status) {
			return nil, h.internal(ctx, "decode policy compliance status", fmt.Errorf("unknown status %d", row.Status))
		}
		if policy == nil || policy.PolicyId != row.PolicyID {
			policy = &pmv1.DevicePolicyEvaluation{
				PolicyId: row.PolicyID, PolicyName: row.PolicyName,
				Status: pmv1.ComplianceStatus_COMPLIANCE_STATUS_COMPLIANT,
			}
			policies = append(policies, policy)
		}
		output, err := decodeCommandOutput(row.DetectionOutput)
		if err != nil {
			return nil, h.internal(ctx, "decode policy compliance output", err)
		}
		rule := &pmv1.DevicePolicyRuleEvaluation{
			ActionId: row.ActionID, ActionName: row.ActionName,
			Status: pmv1.ComplianceStatus(row.Status), Compliant: row.Compliant,
			GracePeriodHours: row.GracePeriodHours, DetectionOutput: output,
		}
		if row.CheckedAt != nil {
			rule.CheckedAt = timestamppb.New(*row.CheckedAt)
		}
		if row.FirstFailedAt != nil {
			rule.FirstFailedAt = timestamppb.New(*row.FirstFailedAt)
			if row.GracePeriodHours > 0 {
				rule.GraceExpiresAt = timestamppb.New(row.FirstFailedAt.Add(
					time.Duration(row.GracePeriodHours) * time.Hour,
				))
			}
		}
		policy.Rules = append(policy.Rules, rule)
		policy.Status = worseComplianceStatus(policy.Status, rule.Status)
	}
	if err := h.recordSensitiveRead(ctx, req, actor,
		powermanagev1connect.ControlServiceGetDeviceCompliancePolicyStatusProcedure,
		"GetDeviceCompliancePolicyStatus", "device_compliance_policy_status", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.GetDeviceCompliancePolicyStatusResponse{
		OverallStatus: pmv1.ComplianceStatus(view.ComplianceStatus), Policies: policies,
	}), nil
}

func decodeCommandOutput(raw []byte) (*pmv1.CommandOutput, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	output := &pmv1.CommandOutput{}
	if err := protojson.Unmarshal(raw, output); err != nil {
		return nil, err
	}
	return output, nil
}

func validComplianceStatus(status int32) bool {
	switch pmv1.ComplianceStatus(status) {
	case pmv1.ComplianceStatus_COMPLIANCE_STATUS_UNKNOWN,
		pmv1.ComplianceStatus_COMPLIANCE_STATUS_COMPLIANT,
		pmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT,
		pmv1.ComplianceStatus_COMPLIANCE_STATUS_IN_GRACE_PERIOD:
		return true
	default:
		return false
	}
}

func worseComplianceStatus(left, right pmv1.ComplianceStatus) pmv1.ComplianceStatus {
	priority := func(status pmv1.ComplianceStatus) int {
		switch status {
		case pmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT:
			return 3
		case pmv1.ComplianceStatus_COMPLIANCE_STATUS_IN_GRACE_PERIOD:
			return 2
		case pmv1.ComplianceStatus_COMPLIANCE_STATUS_UNKNOWN:
			return 1
		default:
			return 0
		}
	}
	if priority(right) > priority(left) {
		return right
	}
	return left
}

// GetExecution returns one visible execution and its protected output.
func (h *Handlers) GetExecution(ctx context.Context, req *connect.Request[pmv1.GetExecutionRequest]) (*connect.Response[pmv1.GetExecutionResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "GetExecution", ""); err != nil {
		return nil, err
	}
	row, err := h.store.GetExecution(ctx, req.Msg.Id)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, errExecutionNotFound, "execution not found")
		}
		return nil, h.internal(ctx, "read execution", err)
	}
	if _, err := h.readDevice(ctx, "GetExecution", row.DeviceID); err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			return nil, notFound(ctx, errExecutionNotFound, "execution not found")
		}
		return nil, err
	}
	execution, err := executionToProto(row)
	if err != nil {
		return nil, h.internal(ctx, "decode execution", err)
	}
	if err := h.recordSensitiveRead(ctx, req, actor,
		powermanagev1connect.ControlServiceGetExecutionProcedure, "GetExecution",
		"execution", row.ID); err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.GetExecutionResponse{Execution: execution}), nil
}

// ListExecutions returns a newest-first direct keyset page narrowed by the
// caller's device visibility.
func (h *Handlers) ListExecutions(ctx context.Context, req *connect.Request[pmv1.ListExecutionsRequest]) (*connect.Response[pmv1.ListExecutionsResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "ListExecutions", ""); err != nil {
		return nil, err
	}
	if req.Msg.PageToken != "" {
		if _, err := ulid.ParseStrict(req.Msg.PageToken); err != nil {
			return nil, rpcError(ctx, errInvalidPageToken, connect.CodeInvalidArgument, "invalid page token")
		}
	}
	status, ok := executionStatusToString(req.Msg.StatusFilter)
	if !ok {
		return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid execution status")
	}
	if req.Msg.TypeFilter != pmv1.ActionType_ACTION_TYPE_UNSPECIFIED {
		if _, ok := pmv1.ActionType_name[int32(req.Msg.TypeFilter)]; !ok {
			return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid action type")
		}
	}
	limit := req.Msg.PageSize
	if limit == 0 {
		limit = defaultPageSize
	}
	filter := store.ExecutionListFilter{
		AfterID: req.Msg.PageToken, Limit: limit + 1,
		DeviceID: req.Msg.DeviceId, Status: status,
		ActionType: int32(req.Msg.TypeFilter), Search: strings.TrimSpace(req.Msg.Search),
	}
	filter.ScopeGroupIDs, filter.ScopeRestricted = auth.DeviceScopeListFilter(ctx, "ListExecutions")
	if !auth.HasPermission(ctx, "ListExecutions") {
		filter.AssignedUserID = &actor.ID
	}
	rows, err := h.store.ListExecutions(ctx, filter)
	if err != nil {
		return nil, h.internal(ctx, "list executions", err)
	}
	hasMore := len(rows) > int(limit)
	if hasMore {
		rows = rows[:limit]
	}
	countFilter := filter
	countFilter.AfterID = ""
	countFilter.Limit = 0
	total, err := h.store.CountExecutions(ctx, countFilter)
	if err != nil {
		return nil, h.internal(ctx, "count executions", err)
	}
	executions := make([]*pmv1.ActionExecution, len(rows))
	for i, row := range rows {
		executions[i], err = executionToProto(row)
		if err != nil {
			return nil, h.internal(ctx, "decode listed execution", err)
		}
	}
	next := ""
	if hasMore {
		next = rows[len(rows)-1].ID
	}
	if err := h.recordSensitiveRead(ctx, req, actor,
		powermanagev1connect.ControlServiceListExecutionsProcedure, "ListExecutions",
		"execution", ""); err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.ListExecutionsResponse{
		Executions: executions, NextPageToken: next, TotalCount: boundedInt32(total),
	}), nil
}

func executionToProto(row store.ExecutionView) (*pmv1.ActionExecution, error) {
	if _, ok := pmv1.ActionType_name[row.ActionType]; !ok || row.ActionType == 0 {
		return nil, fmt.Errorf("invalid action type %d", row.ActionType)
	}
	if _, ok := pmv1.DesiredState_name[row.DesiredState]; !ok {
		return nil, fmt.Errorf("invalid desired state %d", row.DesiredState)
	}
	status, ok := executionStatusFromString(row.Status)
	if !ok {
		return nil, fmt.Errorf("invalid execution status %q", row.Status)
	}
	output, err := decodeCommandOutput(row.Output)
	if err != nil {
		return nil, fmt.Errorf("decode output: %w", err)
	}
	detectionOutput, err := decodeCommandOutput(row.DetectionOutput)
	if err != nil {
		return nil, fmt.Errorf("decode detection output: %w", err)
	}
	execution := &pmv1.ActionExecution{
		Id: row.ID, DeviceId: row.DeviceID, Type: pmv1.ActionType(row.ActionType),
		Status: status, DesiredState: pmv1.DesiredState(row.DesiredState),
		Output: output, DetectionOutput: detectionOutput,
		Changed: row.Changed, Compliant: row.Compliant,
		CreatedBy: row.CreatedByID, ActionName: row.ActionName,
	}
	if row.ActionID != nil {
		execution.ActionId = *row.ActionID
	}
	if row.Error != nil {
		execution.Error = *row.Error
	}
	if row.DurationMs != nil {
		execution.DurationMs = *row.DurationMs
	}
	if row.CreatedAt != nil {
		execution.CreatedAt = timestamppb.New(*row.CreatedAt)
	}
	if row.ScheduledFor != nil {
		execution.ScheduledFor = timestamppb.New(*row.ScheduledFor)
	}
	if row.DispatchedAt != nil {
		execution.DispatchedAt = timestamppb.New(*row.DispatchedAt)
	}
	if row.CompletedAt != nil {
		execution.CompletedAt = timestamppb.New(*row.CompletedAt)
	}
	return execution, nil
}

func executionStatusToString(status pmv1.ExecutionStatus) (string, bool) {
	switch status {
	case pmv1.ExecutionStatus_EXECUTION_STATUS_UNSPECIFIED:
		return "", true
	case pmv1.ExecutionStatus_EXECUTION_STATUS_PENDING:
		return "pending", true
	case pmv1.ExecutionStatus_EXECUTION_STATUS_RUNNING:
		return "running", true
	case pmv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS:
		return "success", true
	case pmv1.ExecutionStatus_EXECUTION_STATUS_FAILED:
		return "failed", true
	case pmv1.ExecutionStatus_EXECUTION_STATUS_SKIPPED:
		return "skipped", true
	case pmv1.ExecutionStatus_EXECUTION_STATUS_TIMEOUT:
		return "timeout", true
	case pmv1.ExecutionStatus_EXECUTION_STATUS_SCHEDULED:
		return "scheduled", true
	case pmv1.ExecutionStatus_EXECUTION_STATUS_CANCELLED:
		return "cancelled", true
	case pmv1.ExecutionStatus_EXECUTION_STATUS_NOT_APPLICABLE:
		return "not_applicable", true
	case pmv1.ExecutionStatus_EXECUTION_STATUS_INDETERMINATE:
		return "indeterminate", true
	default:
		return "", false
	}
}

func executionStatusFromString(status string) (pmv1.ExecutionStatus, bool) {
	for value := pmv1.ExecutionStatus_EXECUTION_STATUS_PENDING; value <= pmv1.ExecutionStatus_EXECUTION_STATUS_INDETERMINATE; value++ {
		if name, _ := executionStatusToString(value); name == status {
			return value, true
		}
	}
	return pmv1.ExecutionStatus_EXECUTION_STATUS_UNSPECIFIED, false
}

func boundedInt32(value int64) int32 {
	if value > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(value)
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
