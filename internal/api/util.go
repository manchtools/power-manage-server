package api

import (
	"context"
	"fmt"
	"strconv"

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

// userFilterID returns the user's ID for non-admin users (to filter queries),
// or nil for admins (no filter, see all rows).
func userFilterID(ctx context.Context) *string {
	if u, ok := auth.UserFromContext(ctx); ok && u.Role != "admin" {
		return &u.ID
	}
	return nil
}
