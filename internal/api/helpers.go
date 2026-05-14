package api

import (
	"context"
	"log/slog"
	"math"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/store"
)

// maxDynamicQueryLength caps the size of user-supplied dynamic-group
// queries (device groups, user groups). Keeps event-store payload
// sizes bounded and stops pathological queries from stressing the
// validator / projector.
const maxDynamicQueryLength = 10_000

// requireAuth extracts the authenticated user from context.
// Returns the user context or a standardized unauthenticated error.
func requireAuth(ctx context.Context) (*auth.UserContext, error) {
	userCtx, ok := auth.UserFromContext(ctx)
	if !ok || userCtx == nil {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}
	return userCtx, nil
}

// handleGetError returns a NotFound error when err signals a missing
// row from any supported storage backend, or an Internal error
// otherwise. Backend recognition is centralized in store.IsNotFound;
// see tracker #242 for the abstraction motivation.
func handleGetError(ctx context.Context, err error, notFoundCode, notFoundMsg string) error {
	if store.IsNotFound(err) {
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
		if parseErr != nil || offset64 < 0 || offset64 > math.MaxInt32 {
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

// logEnrichmentErr logs an enrichment-lookup failure with consistent
// shape. Used by handler response-building loops where the lookup
// degrades the response (missing field) but doesn't fail the RPC.
// Replaces the silent `if err == nil { use(x) }` anti-pattern flagged
// by audit findings F006/F007 ("always log errors and never ignore
// them"). Pass operation as the underlying call site (e.g.
// "GetActionByID") so an operator searching logs can find every
// failed enrichment of that specific lookup across handlers.
func logEnrichmentErr(operation, idKey, idValue string, err error) {
	slog.Warn("enrichment lookup failed",
		"operation", operation,
		idKey, idValue,
		"error", err)
}

// ptrBool returns a *bool for the value. Used by typed-payload emit
// sites that take pointer-bool fields with omitempty so the projector
// can distinguish "absent" (nil) from "set to false" (non-nil pointer
// to false).
func ptrBool(b bool) *bool { return &b }

// ptrStr returns a *string for the value. Same shape as ptrBool —
// pointer fields with omitempty distinguish absent from explicit on
// the wire.
func ptrStr(s string) *string { return &s }
