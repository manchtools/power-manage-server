package dispatch

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/go-playground/validator/v10"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/authoring"
	"github.com/manchtools/power-manage/server/internal/manifest"
	"github.com/manchtools/power-manage/server/internal/store"
)

// HandlersConfig supplies the durable store and bounded dispatcher wake seam.
type HandlersConfig struct {
	Store  *store.Store
	Waker  Waker
	Logger *slog.Logger
	Now    func() time.Time
}

// Handlers implements direct manifest dispatch RPCs.
type Handlers struct {
	store     *store.Store
	compiler  *manifest.Compiler
	submitter *Service
	logger    *slog.Logger
	validator *validator.Validate
}

// NewHandlers constructs direct dispatch handlers. Missing durable state or a
// wake target is a boot-time wiring defect.
func NewHandlers(cfg HandlersConfig) *Handlers {
	if cfg.Store == nil || cfg.Waker == nil {
		panic("dispatch: handler store and waker are required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Handlers{
		store: cfg.Store, compiler: manifest.New(cfg.Store),
		submitter: New(Config{Store: cfg.Store, Waker: cfg.Waker, Now: cfg.Now}),
		logger:    cfg.Logger, validator: sdkvalidate.NewValidator(),
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

type deviceScopeResolver struct{ store *store.Store }

func (r deviceScopeResolver) DeviceGroupsForDevice(ctx context.Context, deviceID string) ([]string, error) {
	return r.store.ListDeviceGroupIDs(ctx, deviceID)
}

func (deviceScopeResolver) UserGroupsForUser(context.Context, string) ([]string, error) {
	return nil, errors.New("dispatch: user scope resolution is unavailable")
}

func (h *Handlers) target(ctx context.Context, actor *auth.UserContext, permission, deviceID string) error {
	if !auth.AuthorizeContext(ctx, permission, deviceID) {
		return rpcError(ctx, errPermissionDenied, connect.CodePermissionDenied, "permission denied")
	}
	if _, err := h.store.GetDeviceView(ctx, deviceID); err != nil {
		if store.IsNotFound(err) {
			return notFound(ctx, errDeviceNotFound, "device not found")
		}
		return h.internal(ctx, "read dispatch device", err)
	}
	if auth.HasPermission(ctx, permission) {
		if err := auth.EnforceDeviceScopeOnBaseTier(ctx, deviceScopeResolver{h.store}, permission, deviceID); err != nil {
			if connect.CodeOf(err) == connect.CodeInternal {
				return h.internal(ctx, "resolve dispatch device scope", err)
			}
			return notFound(ctx, errDeviceNotFound, "device not found")
		}
		return nil
	}
	assigned, err := h.store.IsDeviceAssignedToUser(ctx, deviceID, actor.ID)
	if err != nil {
		return h.internal(ctx, "check dispatch device assignment", err)
	}
	if !assigned {
		return notFound(ctx, errDeviceNotFound, "device not found")
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

func (h *Handlers) internal(ctx context.Context, operation string, err error) *connect.Error {
	h.logger.Error("dispatch RPC failed", "operation", operation, "error", err)
	return rpcError(ctx, errInternal, connect.CodeInternal, "internal error")
}

// DispatchAction compiles one catalog or inline Action and durably submits it.
func (h *Handlers) DispatchAction(ctx context.Context, req *connect.Request[pmv1.DispatchActionRequest]) (*connect.Response[pmv1.DispatchActionResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.target(ctx, actor, "DispatchAction", req.Msg.DeviceId); err != nil {
		return nil, err
	}

	var input ManifestInput
	switch source := req.Msg.ActionSource.(type) {
	case *pmv1.DispatchActionRequest_ActionId:
		compiled, err := h.compiler.Action(ctx, source.ActionId)
		if err != nil {
			return nil, h.compileError(ctx, "compile dispatched action", err)
		}
		visible, err := authoring.ActionVisibleToCaller(ctx, h.store, source.ActionId)
		if err != nil {
			return nil, h.internal(ctx, "resolve dispatched action scope", err)
		}
		if !visible {
			return nil, notFound(ctx, errActionNotFound, "action not found")
		}
		compiled.Schedule = &pmv1.ActionSchedule{}
		input = ManifestInput{Manifest: compiled, PersistActionIDs: true}
	case *pmv1.DispatchActionRequest_InlineAction:
		if source.InlineAction == nil {
			return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid inline action")
		}
		inline := proto.Clone(source.InlineAction).(*pmv1.Action)
		if inline.TimeoutSeconds == 0 {
			inline.TimeoutSeconds = 300
		}
		if err := authoring.ValidateExecutableAction(inline); err != nil {
			return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid inline action")
		}
		compiled, err := manifest.OneShotAction(inline)
		if err != nil {
			return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid inline action")
		}
		input = ManifestInput{Manifest: compiled}
	default:
		return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument,
			"either action_id or inline_action is required")
	}

	scheduledFor, err := futureTime(req.Msg.RunAt)
	if err != nil {
		return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "run_at must be a valid future timestamp")
	}
	result, err := h.submitter.Submit(ctx, SubmitParams{
		Operation: h.operation(req, actor, powermanagev1connect.ControlServiceDispatchActionProcedure, "DispatchAction"),
		DeviceID:  req.Msg.DeviceId, Manifests: []ManifestInput{input}, ScheduledFor: scheduledFor,
	})
	if err != nil {
		if errors.Is(err, ErrInvalidInput) {
			return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid dispatch")
		}
		return nil, h.internal(ctx, "submit action dispatch", err)
	}
	return connect.NewResponse(&pmv1.DispatchActionResponse{
		Execution: createdExecutionToProto(result.Executions[0]),
	}), nil
}

// DispatchInstantAction submits an agent-builtin REBOOT or SYNC occurrence.
func (h *Handlers) DispatchInstantAction(ctx context.Context, req *connect.Request[pmv1.DispatchInstantActionRequest]) (*connect.Response[pmv1.DispatchInstantActionResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if req.Msg.InstantAction != pmv1.ActionType_ACTION_TYPE_REBOOT && req.Msg.InstantAction != pmv1.ActionType_ACTION_TYPE_SYNC {
		return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid instant action")
	}
	if err := h.target(ctx, actor, "DispatchInstantAction", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	timeout := int32(60)
	if req.Msg.InstantAction == pmv1.ActionType_ACTION_TYPE_REBOOT {
		timeout = 600
	}
	action := &pmv1.Action{
		Id: &pmv1.ActionId{Value: ulid.Make().String()}, Type: req.Msg.InstantAction,
		DesiredState: pmv1.DesiredState_DESIRED_STATE_PRESENT, TimeoutSeconds: timeout,
	}
	compiled, err := manifest.OneShotAction(action)
	if err != nil {
		return nil, h.internal(ctx, "compile instant action", err)
	}
	scheduledFor, err := futureTime(req.Msg.RunAt)
	if err != nil {
		return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "run_at must be a valid future timestamp")
	}
	result, err := h.submitter.Submit(ctx, SubmitParams{
		Operation: h.operation(req, actor, powermanagev1connect.ControlServiceDispatchInstantActionProcedure, "DispatchInstantAction"),
		DeviceID:  req.Msg.DeviceId, Manifests: []ManifestInput{{Manifest: compiled}}, ScheduledFor: scheduledFor,
	})
	if err != nil {
		if errors.Is(err, ErrInvalidInput) {
			return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid instant dispatch")
		}
		return nil, h.internal(ctx, "submit instant dispatch", err)
	}
	return connect.NewResponse(&pmv1.DispatchInstantActionResponse{
		Execution: createdExecutionToProto(result.Executions[0]),
	}), nil
}

// DispatchActionSet compiles the set once and submits its ordered occurrences
// as one complete delivery.
func (h *Handlers) DispatchActionSet(ctx context.Context, req *connect.Request[pmv1.DispatchActionSetRequest]) (*connect.Response[pmv1.DispatchActionSetResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.target(ctx, actor, "DispatchActionSet", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	compiled, err := h.compiler.ActionSet(ctx, req.Msg.ActionSetId)
	if err != nil {
		return nil, h.collectionCompileError(ctx, "action set", errActionSetMissing, "compile dispatched action set", err)
	}
	visible, err := authoring.ActionSetVisibleToCaller(ctx, h.store, req.Msg.ActionSetId)
	if err != nil {
		return nil, h.internal(ctx, "resolve dispatched action set scope", err)
	}
	if !visible {
		return nil, notFound(ctx, errActionSetMissing, "action set not found")
	}
	result, err := h.submitter.Submit(ctx, SubmitParams{
		Operation: h.operation(req, actor, powermanagev1connect.ControlServiceDispatchActionSetProcedure, "DispatchActionSet"),
		DeviceID:  req.Msg.DeviceId, Manifests: catalogManifests(compiled),
	})
	if err != nil {
		return nil, h.submitError(ctx, "submit action set dispatch", err)
	}
	return connect.NewResponse(&pmv1.DispatchActionSetResponse{
		Executions: createdExecutionsToProto(result.Executions),
	}), nil
}

// DispatchDefinition compiles one manifest per contained ActionSet and commits
// the complete batch atomically without mutating any authored schedule.
func (h *Handlers) DispatchDefinition(ctx context.Context, req *connect.Request[pmv1.DispatchDefinitionRequest]) (*connect.Response[pmv1.DispatchDefinitionResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.target(ctx, actor, "DispatchDefinition", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	compiled, err := h.compiler.Definition(ctx, req.Msg.DefinitionId)
	if err != nil {
		return nil, h.collectionCompileError(ctx, "definition", errDefinitionMissing, "compile dispatched definition", err)
	}
	visible, err := authoring.DefinitionVisibleToCaller(ctx, h.store, req.Msg.DefinitionId)
	if err != nil {
		return nil, h.internal(ctx, "resolve dispatched definition scope", err)
	}
	if !visible {
		return nil, notFound(ctx, errDefinitionMissing, "definition not found")
	}
	result, err := h.submitter.Submit(ctx, SubmitParams{
		Operation: h.operation(req, actor, powermanagev1connect.ControlServiceDispatchDefinitionProcedure, "DispatchDefinition"),
		DeviceID:  req.Msg.DeviceId, Manifests: catalogManifests(compiled...),
	})
	if err != nil {
		return nil, h.submitError(ctx, "submit definition dispatch", err)
	}
	return connect.NewResponse(&pmv1.DispatchDefinitionResponse{
		Executions: createdExecutionsToProto(result.Executions),
	}), nil
}

func (h *Handlers) compileError(ctx context.Context, operation string, err error) error {
	switch {
	case store.IsNotFound(err):
		return notFound(ctx, errActionNotFound, "action not found")
	case errors.Is(err, manifest.ErrInvalidInput), errors.Is(err, manifest.ErrEmptyManifest):
		return rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid action")
	default:
		return h.internal(ctx, operation, err)
	}
}

func (h *Handlers) collectionCompileError(ctx context.Context, resource, code, operation string, err error) error {
	switch {
	case store.IsNotFound(err):
		return notFound(ctx, code, resource+" not found")
	case errors.Is(err, manifest.ErrInvalidInput):
		return rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid "+resource)
	case errors.Is(err, manifest.ErrEmptyManifest):
		return rpcError(ctx, errValidationFailed, connect.CodeFailedPrecondition, resource+" contains no executable actions")
	default:
		return h.internal(ctx, operation, err)
	}
}

func (h *Handlers) submitError(ctx context.Context, operation string, err error) error {
	if errors.Is(err, ErrInvalidInput) {
		return rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid dispatch")
	}
	return h.internal(ctx, operation, err)
}

func catalogManifests(manifests ...*pmv1.Manifest) []ManifestInput {
	inputs := make([]ManifestInput, len(manifests))
	for i, compiled := range manifests {
		// Explicit Dispatch* RPCs are one-shot. The compiler has already
		// resolved Definition-over-ActionSet schedule precedence; replacing the
		// emitted schedule here does not rewrite either authored object.
		compiled.Schedule = &pmv1.ActionSchedule{}
		inputs[i] = ManifestInput{Manifest: compiled, PersistActionIDs: true}
	}
	return inputs
}

func futureTime(value *timestamppb.Timestamp) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	if err := value.CheckValid(); err != nil {
		return nil, err
	}
	result := value.AsTime().UTC()
	return &result, nil
}

func createdExecutionToProto(row store.ExecutionView) *pmv1.ActionExecution {
	status := pmv1.ExecutionStatus_EXECUTION_STATUS_PENDING
	if row.Status == "scheduled" {
		status = pmv1.ExecutionStatus_EXECUTION_STATUS_SCHEDULED
	}
	result := &pmv1.ActionExecution{
		Id: row.ID, DeviceId: row.DeviceID, Type: pmv1.ActionType(row.ActionType),
		DesiredState: pmv1.DesiredState(row.DesiredState), Status: status,
		CreatedBy: row.CreatedByID,
	}
	if row.ActionID != nil {
		result.ActionId = *row.ActionID
	}
	if row.CreatedAt != nil {
		result.CreatedAt = timestamppb.New(*row.CreatedAt)
	}
	if row.ScheduledFor != nil {
		result.ScheduledFor = timestamppb.New(*row.ScheduledFor)
	}
	return result
}

func createdExecutionsToProto(rows []store.ExecutionView) []*pmv1.ActionExecution {
	result := make([]*pmv1.ActionExecution, len(rows))
	for i := range rows {
		result[i] = createdExecutionToProto(rows[i])
	}
	return result
}
