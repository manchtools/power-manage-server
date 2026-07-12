package api

import (
	"context"
	"errors"
	"log/slog"

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

// deviceScopeMissError returns the error a caller should see when a device-scoped
// object (an execution, a log-query result) is NOT visible to them — covering
// BOTH "genuinely absent" and "exists on a device outside their scope" with the
// SAME code, so existence does not leak (spec 29 S10). These handlers must load
// the row to learn its device before they can scope-check, so the check cannot
// run first (unlike the user-group handlers); instead the miss is resolved to
// match the out-of-scope path.
//
// A device_group-scoped (restricted) caller gets a PermissionDenied byte-identical
// to the one auth.EnforceDeviceScope returns for the out-of-scope path, so the two
// are indistinguishable. A global/unrestricted caller — who can see every device
// (or is confined by an owner filter elsewhere) — gets the honest NotFound, since
// for them absence carries no scope signal.
func deviceScopeMissError(ctx context.Context, permission, notFoundCode, notFoundMsg string) error {
	if _, restricted := auth.DeviceScopeListFilter(ctx, permission); restricted {
		return connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
	}
	return apiErrorCtx(ctx, notFoundCode, connect.CodeNotFound, notFoundMsg)
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

// maxListOffset caps the pagination offset (WS13 #3). A client-controlled deep
// OFFSET forces the database to scan and discard `offset` rows on every list
// RPC — an asymmetric-work DoS. 100_000 matches the Search backbone's ceiling
// (search_handler.maxSearchOffset); beyond it, list pages should route through
// Search (server#84/#325) rather than raw OFFSET. A token past the ceiling is
// REJECTED, not silently clamped, so the client learns to stop paginating.
const maxListOffset = 100_000

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
		if parseErr != nil || offset64 < 0 || offset64 > maxListOffset {
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
