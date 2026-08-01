package assignment

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net/http"

	"connectrpc.com/connect"
	"github.com/go-playground/validator/v10"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/store"
)

const defaultPageSize = int32(50)

// Handlers implements explicit assignment CRUD.
type Handlers struct {
	store     *store.Store
	state     *State
	logger    *slog.Logger
	validator *validator.Validate
}

// New constructs direct assignment handlers.
func New(cfg Config) *Handlers {
	if cfg.Store == nil {
		panic("assignment: handler store is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Handlers{
		store: cfg.Store, state: NewState(cfg), logger: logger,
		validator: sdkvalidate.NewValidator(),
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

// CreateAssignment creates or idempotently returns one source-target edge.
func (h *Handlers) CreateAssignment(ctx context.Context, req *connect.Request[pmv1.CreateAssignmentRequest]) (*connect.Response[pmv1.CreateAssignmentResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "CreateAssignment", ""); err != nil {
		return nil, err
	}
	row, err := h.state.Create(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceCreateAssignmentProcedure, "CreateAssignment"), CreateParams{
		SourceType: req.Msg.SourceType, SourceID: req.Msg.SourceId,
		TargetType: req.Msg.TargetType, TargetID: req.Msg.TargetId,
		Mode: req.Msg.Mode, CreatedBy: actor.ID,
	})
	if err != nil {
		return nil, h.mapError(ctx, "create assignment", err)
	}
	return connect.NewResponse(&pmv1.CreateAssignmentResponse{Assignment: assignmentToProto(row)}), nil
}

// DeleteAssignment soft-deletes one assignment edge.
func (h *Handlers) DeleteAssignment(ctx context.Context, req *connect.Request[pmv1.DeleteAssignmentRequest]) (*connect.Response[pmv1.DeleteAssignmentResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "DeleteAssignment", req.Msg.Id); err != nil {
		return nil, err
	}
	if err := h.state.Delete(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceDeleteAssignmentProcedure, "DeleteAssignment"), req.Msg.Id); err != nil {
		return nil, h.mapError(ctx, "delete assignment", err)
	}
	return connect.NewResponse(&pmv1.DeleteAssignmentResponse{}), nil
}

// ListAssignments returns a deterministic keyset page.
func (h *Handlers) ListAssignments(ctx context.Context, req *connect.Request[pmv1.ListAssignmentsRequest]) (*connect.Response[pmv1.ListAssignmentsResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "ListAssignments", ""); err != nil {
		return nil, err
	}
	if req.Msg.PageToken != "" {
		if _, err := ulid.ParseStrict(req.Msg.PageToken); err != nil {
			return nil, rpcError(ctx, "invalid_page_token", connect.CodeInvalidArgument, "invalid page token")
		}
	}
	sourceType, _ := sourceTypeName(req.Msg.SourceType)
	targetType, _ := targetTypeName(req.Msg.TargetType)
	limit := req.Msg.PageSize
	if limit == 0 {
		limit = defaultPageSize
	}
	filter := store.AssignmentListFilter{
		AfterID: req.Msg.PageToken, Limit: limit + 1,
		SourceType: sourceType, SourceID: req.Msg.SourceId,
		TargetType: targetType, TargetID: req.Msg.TargetId,
	}
	rows, err := h.store.ListAssignments(ctx, filter)
	if err != nil {
		return nil, h.internal(ctx, "list assignments", err)
	}
	hasMore := len(rows) > int(limit)
	if hasMore {
		rows = rows[:limit]
	}
	count, err := h.store.CountAssignments(ctx, filter)
	if err != nil {
		return nil, h.internal(ctx, "count assignments", err)
	}
	out := make([]*pmv1.Assignment, len(rows))
	for i, row := range rows {
		out[i] = assignmentToProto(row)
	}
	next := ""
	if hasMore {
		next = rows[len(rows)-1].ID
	}
	return connect.NewResponse(&pmv1.ListAssignmentsResponse{
		Assignments: out, NextPageToken: next, TotalCount: boundedCount(count),
	}), nil
}

// GetUserAssignments resolves direct and current user-group targets.
func (h *Handlers) GetUserAssignments(ctx context.Context, req *connect.Request[pmv1.GetUserAssignmentsRequest]) (*connect.Response[pmv1.GetUserAssignmentsResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if _, err := h.actor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "GetUserAssignments", ""); err != nil {
		return nil, err
	}
	rows, err := h.store.ListAssignmentsForUser(ctx, req.Msg.UserId)
	if err != nil {
		return nil, h.internal(ctx, "get user assignments", err)
	}
	out := make([]*pmv1.Assignment, len(rows))
	for i, row := range rows {
		out[i] = assignmentToProto(row)
	}
	return connect.NewResponse(&pmv1.GetUserAssignmentsResponse{Assignments: out}), nil
}

func (h *Handlers) mapError(ctx context.Context, operation string, err error) error {
	switch {
	case errors.Is(err, ErrInvalidInput):
		return rpcError(ctx, "validation_failed", connect.CodeInvalidArgument, "invalid assignment")
	case errors.Is(err, ErrSourceNotFound):
		return rpcError(ctx, "assignment_source_not_found", connect.CodeNotFound, "assignment source not found")
	case errors.Is(err, ErrTargetNotFound):
		return rpcError(ctx, "assignment_target_not_found", connect.CodeNotFound, "assignment target not found")
	case errors.Is(err, ErrNotFound), store.IsNotFound(err):
		return rpcError(ctx, "assignment_not_found", connect.CodeNotFound, "assignment not found")
	case errors.Is(err, ErrSystemAction):
		return rpcError(ctx, "cannot_modify_system_action", connect.CodeFailedPrecondition, "system action cannot be assigned directly")
	default:
		return h.internal(ctx, operation, err)
	}
}

func (h *Handlers) internal(ctx context.Context, operation string, err error) *connect.Error {
	h.logger.Error("assignment RPC failed", "operation", operation, "error", err)
	return rpcError(ctx, "internal_error", connect.CodeInternal, "internal error")
}

func assignmentToProto(row store.AssignmentView) *pmv1.Assignment {
	sourceType, _ := sourceTypeValue(row.SourceType)
	targetType, _ := targetTypeValue(row.TargetType)
	out := &pmv1.Assignment{
		Id: row.ID, SourceType: sourceType, SourceId: row.SourceID,
		TargetType: targetType, TargetId: row.TargetID, Mode: pmv1.AssignmentMode(row.Mode),
		CreatedBy: row.CreatedBy, SourceName: row.SourceName, TargetName: row.TargetName,
	}
	if row.CreatedAt != nil {
		out.CreatedAt = timestamppb.New(*row.CreatedAt)
	}
	return out
}

func sourceTypeValue(value string) (pmv1.AssignmentSourceType, bool) {
	switch value {
	case "action":
		return pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION, true
	case "action_set":
		return pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION_SET, true
	case "definition":
		return pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_DEFINITION, true
	case "compliance_policy":
		return pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_COMPLIANCE_POLICY, true
	default:
		return pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_UNSPECIFIED, false
	}
}

func targetTypeValue(value string) (pmv1.AssignmentTargetType, bool) {
	switch value {
	case "device":
		return pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE, true
	case "device_group":
		return pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE_GROUP, true
	case "user":
		return pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER, true
	case "user_group":
		return pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER_GROUP, true
	default:
		return pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_UNSPECIFIED, false
	}
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

// Mount registers exactly the implemented assignment CRUD procedures.
func (h *Handlers) Mount(mux *http.ServeMux, opts ...connect.HandlerOption) []string {
	if mux == nil {
		panic("assignment: mux is required")
	}
	mounted := make([]string, 0, 4)
	register := func(procedure string, handler http.Handler) {
		mux.Handle(procedure, handler)
		mounted = append(mounted, procedure)
	}
	register(powermanagev1connect.ControlServiceCreateAssignmentProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceCreateAssignmentProcedure, h.CreateAssignment, opts...))
	register(powermanagev1connect.ControlServiceDeleteAssignmentProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDeleteAssignmentProcedure, h.DeleteAssignment, opts...))
	register(powermanagev1connect.ControlServiceListAssignmentsProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListAssignmentsProcedure, h.ListAssignments, opts...))
	register(powermanagev1connect.ControlServiceGetUserAssignmentsProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetUserAssignmentsProcedure, h.GetUserAssignments, opts...))
	return mounted
}

// MutationProcedures is the exact audited assignment mutation surface.
func MutationProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceCreateAssignmentProcedure,
		powermanagev1connect.ControlServiceDeleteAssignmentProcedure,
	}
}

// ReadProcedures is the exact non-mutating assignment CRUD surface.
func ReadProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceListAssignmentsProcedure,
		powermanagev1connect.ControlServiceGetUserAssignmentsProcedure,
	}
}
