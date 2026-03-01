package api

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"
)

// LoggingInterceptor logs all Connect-RPC errors returned from handlers.
// It should be registered as the outermost interceptor to capture errors
// from all downstream interceptors (auth, authz) and handlers.
type LoggingInterceptor struct {
	logger *slog.Logger
}

// NewLoggingInterceptor creates a new logging interceptor.
func NewLoggingInterceptor(logger *slog.Logger) *LoggingInterceptor {
	return &LoggingInterceptor{logger: logger}
}

// WrapUnary implements connect.Interceptor.
func (i *LoggingInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		resp, err := next(ctx, req)
		if err != nil {
			i.logError(req.Spec().Procedure, err)
		}
		return resp, err
	}
}

// WrapStreamingClient implements connect.Interceptor.
func (i *LoggingInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler implements connect.Interceptor.
func (i *LoggingInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

// logError logs a Connect-RPC error with appropriate severity.
// Client errors (invalid argument, not found, etc.) are logged at Warn level.
// Server errors (internal, unknown, etc.) are logged at Error level.
func (i *LoggingInterceptor) logError(procedure string, err error) {
	connectErr, ok := err.(*connect.Error)
	if !ok {
		i.logger.Error("rpc failed", "procedure", procedure, "error", err)
		return
	}

	code := connectErr.Code()
	attrs := []any{
		"procedure", procedure,
		"code", code.String(),
		"message", connectErr.Message(),
	}

	switch code {
	case connect.CodeInvalidArgument,
		connect.CodeNotFound,
		connect.CodeAlreadyExists,
		connect.CodePermissionDenied,
		connect.CodeUnauthenticated,
		connect.CodeFailedPrecondition,
		connect.CodeResourceExhausted:
		i.logger.Warn("rpc error", attrs...)
	default:
		i.logger.Error("rpc error", attrs...)
	}
}
