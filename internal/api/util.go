package api

import (
	"context"
	"fmt"
	"strconv"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/auth"
)

// parsePageToken parses a page token to an offset.
func parsePageToken(token string) (int64, error) {
	return strconv.ParseInt(token, 10, 64)
}

// formatPageToken formats an offset as a page token.
func formatPageToken(offset int64) string {
	return fmt.Sprintf("%d", offset)
}

// userFilterID returns the user's ID when the user only has scoped (:assigned)
// access, or nil when the user has unrestricted access (sees all rows).
// The action parameter is the unscoped permission name (e.g. "ListDevices").
func userFilterID(ctx context.Context, action string) *string {
	// RBAC: check if user has the unrestricted permission
	if auth.HasPermission(ctx, action) {
		return nil
	}
	// Scoped — return user ID for SQL-level filtering
	if u, ok := auth.UserFromContext(ctx); ok {
		return &u.ID
	}
	return nil
}

// newULID generates a new ULID string (thread-safe).
func newULID() string {
	return ulid.Make().String()
}
