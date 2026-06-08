package api

import (
	"context"

	"connectrpc.com/connect"
)

// ValidationInterceptor runs Validate on every inbound Connect-RPC
// request before it reaches the handler. Wire it into the production
// interceptor chain after the auth interceptor and before authz, so
// authz still sees a well-formed message but doesn't waste cycles on
// requests that can't pass validation.
//
// Why every handler ALSO calls Validate(ctx, req.Msg) at its
// top-of-function:
//   - The interceptor only sees requests that traverse the configured
//     interceptor chain. Direct handler calls from tests or from
//     in-process callers (e.g. a future internal RPC bridge that bypasses
//     the chain) would skip it.
//   - Defense in depth — the cost is one map lookup + a fast-path bool
//     check inside Validate; the benefit is that adding the interceptor
//     can't accidentally silently disable validation if it's ever
//     removed from cmd/control/main.go's chain.
//
// Validation here covers the proto-level rules (protovalidate tags).
// Handlers still own their own semantic checks — authz, cross-field
// invariants, target-existence — those are *not* a job for this
// interceptor.
type ValidationInterceptor struct{}

// NewValidationInterceptor creates a Connect-RPC interceptor for
// boundary validation. See ValidationInterceptor's doc comment for the
// chain ordering and the rationale for the redundant handler-level
// Validate calls.
func NewValidationInterceptor() *ValidationInterceptor {
	return &ValidationInterceptor{}
}

// WrapUnary implements connect.Interceptor.
func (i *ValidationInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if err := Validate(ctx, req.Any()); err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

// WrapStreamingClient implements connect.Interceptor.
func (i *ValidationInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler implements connect.Interceptor.
func (i *ValidationInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

var _ connect.Interceptor = (*ValidationInterceptor)(nil)
