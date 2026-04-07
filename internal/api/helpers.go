package api

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/store"
)

// requireAuth extracts the authenticated user from context.
// Returns the user context or a standardized unauthenticated error.
func requireAuth(ctx context.Context) (*auth.UserContext, error) {
	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}
	return userCtx, nil
}

// handleGetError returns a NotFound error for pgx.ErrNoRows, or an Internal error otherwise.
func handleGetError(ctx context.Context, err error, notFoundCode, notFoundMsg string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return apiErrorCtx(ctx, notFoundCode, connect.CodeNotFound, notFoundMsg)
	}
	return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get resource")
}

// appendEvent appends an event and logs it. Returns a Connect error on failure.
func appendEvent(ctx context.Context, st *store.Store, logger *slog.Logger, evt store.Event, failMsg string) error {
	if err := st.AppendEvent(ctx, evt); err != nil {
		logger.Error("failed to append event", "error", err, "event_type", evt.EventType, "stream_id", evt.StreamID)
		return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, failMsg)
	}
	logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", evt.StreamType,
		"stream_id", evt.StreamID,
		"event_type", evt.EventType,
	)
	return nil
}

// parsePagination extracts page size and offset from request fields.
// Default page size is 50, max is 100.
func parsePagination(pageSize int32, pageToken string) (size int32, offset int32, err error) {
	size = pageSize
	if size <= 0 {
		size = 50
	} else if size > 100 {
		size = 100
	}
	if pageToken != "" {
		offset64, parseErr := parsePageToken(pageToken)
		if parseErr != nil {
			return 0, 0, apiError(ErrInvalidPageToken, connect.CodeInvalidArgument, "invalid page token")
		}
		offset = int32(offset64)
	}
	return size, offset, nil
}

// buildNextPageToken returns the next page token, or empty string if no more pages.
func buildNextPageToken(resultCount int32, offset int32, pageSize int32, totalCount int64) string {
	if resultCount == pageSize && int64(offset)+int64(pageSize) < totalCount {
		return formatPageToken(int64(offset) + int64(pageSize))
	}
	return ""
}
