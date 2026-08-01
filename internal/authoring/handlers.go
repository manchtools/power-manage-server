package authoring

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"time"

	"connectrpc.com/connect"
	"github.com/go-playground/validator/v10"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/proto"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
)

const defaultAuthoringPageSize = int32(50)

// HandlersConfig supplies the direct PostgreSQL store and process-local seams
// used by the authoring RPC handlers.
type HandlersConfig struct {
	Store  *store.Store
	Logger *slog.Logger
	Now    func() time.Time
}

// Handlers implements the explicit Action, ActionSet and Definition authoring
// RPCs.
type Handlers struct {
	store     *store.Store
	state     *Service
	logger    *slog.Logger
	validator *validator.Validate
}

// NewHandlers constructs the explicit authoring RPC handlers.
func NewHandlers(cfg HandlersConfig) *Handlers {
	if cfg.Store == nil {
		panic("authoring: handler store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Handlers{
		store: cfg.Store, state: New(Config{Store: cfg.Store, Now: cfg.Now}),
		logger: cfg.Logger, validator: sdkvalidate.NewValidator(),
	}
}

func (h *Handlers) validate(ctx context.Context, message any) error {
	if detail, ok := sdkvalidate.Struct(h.validator, message); !ok {
		return authoringRPCError(ctx, errValidationFailed, connect.CodeInvalidArgument, detail)
	}
	return nil
}

func validateAuthoringRequest[T any](h *Handlers, ctx context.Context, req *connect.Request[T]) error {
	if req == nil || req.Msg == nil {
		return authoringRPCError(ctx, errValidationFailed, connect.CodeInvalidArgument, "request is required")
	}
	return h.validate(ctx, req.Msg)
}

func (h *Handlers) actor(ctx context.Context) (*auth.UserContext, error) {
	actor, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, authoringRPCError(ctx, errNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}
	return actor, nil
}

func (h *Handlers) authorize(ctx context.Context, permission, resourceID string) error {
	if !auth.AuthorizeContext(ctx, permission, resourceID) {
		return authoringRPCError(ctx, errPermissionDenied, connect.CodePermissionDenied, "permission denied")
	}
	return nil
}

func (h *Handlers) internal(ctx context.Context, operation string, err error) *connect.Error {
	h.logger.Error("authoring RPC failed", "operation", operation, "error", err)
	return authoringRPCError(ctx, errInternal, connect.CodeInternal, "internal error")
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

func requestParams(message proto.Message, actionType pmv1.ActionType) ([]byte, error) {
	params := actionparams.ExtractParamsMsg(message)
	if params == nil {
		return []byte("{}"), nil
	}
	if !actionparams.ParamsMatchType(message, actionType) {
		return nil, ErrInvalidInput
	}
	raw, err := actionparams.MarshalActionParams(params)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return raw, nil
}

func (h *Handlers) actionError(ctx context.Context, operation string, err error) error {
	switch {
	case errors.Is(err, ErrInvalidInput):
		return authoringRPCError(ctx, errValidationFailed, connect.CodeInvalidArgument, "invalid action")
	case errors.Is(err, ErrSystemAction):
		return authoringRPCError(ctx, errCannotModifySystemAction, connect.CodeFailedPrecondition, "system-managed action cannot be modified")
	case store.IsNotFound(err):
		return authoringNotFound(ctx, errActionNotFound, "action not found")
	default:
		return h.internal(ctx, operation, err)
	}
}

func validPageToken(token string) bool {
	if token == "" {
		return true
	}
	_, err := ulid.ParseStrict(token)
	return err == nil
}

func boundedCount(n int64) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(n)
}
