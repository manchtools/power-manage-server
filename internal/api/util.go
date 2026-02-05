package api

import (
	"fmt"
	"strconv"
)

// parsePageToken parses a page token to an offset.
func parsePageToken(token string) (int64, error) {
	return strconv.ParseInt(token, 10, 64)
}

// formatPageToken formats an offset as a page token.
func formatPageToken(offset int64) string {
	return fmt.Sprintf("%d", offset)
}
