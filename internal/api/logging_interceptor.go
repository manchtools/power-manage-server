package api

import (
	"context"
	"log/slog"
	"time"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/middleware"
)

// LoggingInterceptor logs all Connect-RPC requests with request ID, duration,
// and user context. Errors are logged at Warn (client) or Error (server) level.
// Successful requests are logged at Debug level.
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
		start := time.Now()

		resp, err := next(ctx, req)

		duration := time.Since(start)
		attrs := []any{
			"procedure", req.Spec().Procedure,
			"request_id", middleware.RequestIDFromContext(ctx),
			"duration_ms", duration.Milliseconds(),
		}

		// Add user ID if available (set by auth interceptor downstream)
		if userCtx, ok := auth.UserFromContext(ctx); ok {
			attrs = append(attrs, "user_id", userCtx.ID)
		}

		if err != nil {
			i.logError(attrs, err)
		} else {
			i.logger.Debug("rpc ok", attrs...)
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
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		start := time.Now()
		reqID := middleware.RequestIDFromContext(ctx)

		err := next(ctx, conn)

		duration := time.Since(start)
		attrs := []any{
			"procedure", conn.Spec().Procedure,
			"request_id", reqID,
			"duration_ms", duration.Milliseconds(),
		}

		if err != nil {
			i.logError(attrs, err)
		} else {
			i.logger.Debug("stream ok", attrs...)
		}

		return err
	}
}

// logError logs a Connect-RPC error with appropriate severity.
// Client errors (invalid argument, not found, etc.) are logged at Warn level.
// Server errors (internal, unknown, etc.) are logged at Error level.
func (i *LoggingInterceptor) logError(attrs []any, err error) {
	connectErr, ok := err.(*connect.Error)
	if !ok {
		attrs = append(attrs, "error", err)
		i.logger.Error("rpc failed", attrs...)
		return
	}

	code := connectErr.Code()
	attrs = append(attrs,
		"code", code.String(),
		"message", connectErr.Message(),
	)

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
