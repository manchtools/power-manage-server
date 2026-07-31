package identity

import (
	"context"

	"connectrpc.com/connect"
	"github.com/go-playground/validator/v10"

	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
)

// ValidationInterceptor enforces every request's declared constraints
// at the transport boundary, BEFORE authentication runs.
//
// The order is deliberate: a malformed message is refused without the
// server having done any credential work, so a caller cannot use a
// broken request to probe timing on the authentication path, and a
// handler never sees a message whose shape it did not expect.
//
// Handlers validate again. The interceptor covers the wire path; the
// second call covers every in-process caller and means removing the
// interceptor from a chain cannot silently disable validation.
type ValidationInterceptor struct {
	validator *validator.Validate
}

// NewValidationInterceptor creates the boundary validator.
func NewValidationInterceptor() *ValidationInterceptor {
	return &ValidationInterceptor{validator: sdkvalidate.NewValidator()}
}

// WrapUnary implements connect.Interceptor.
func (i *ValidationInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if detail, ok := sdkvalidate.Struct(i.validator, req.Any()); !ok {
			return nil, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, detail)
		}
		return next(ctx, req)
	}
}

// WrapStreamingClient implements connect.Interceptor.
func (i *ValidationInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler implements connect.Interceptor. The control API
// is unary only; the authentication interceptor refuses streaming, and
// this one passes through rather than duplicating that refusal.
func (i *ValidationInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

var _ connect.Interceptor = (*ValidationInterceptor)(nil)
