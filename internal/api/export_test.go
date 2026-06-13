package api

import (
	"context"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// ScopedSessionsForTest exposes the unexported device-scope session filter so the
// external api_test package can exercise it without standing up the gateway
// fan-out plumbing ListActiveTerminalSessions otherwise requires.
func (h *TerminalHandler) ScopedSessionsForTest(ctx context.Context, sessions []*pm.TerminalSessionInfo) ([]*pm.TerminalSessionInfo, error) {
	return h.scopedSessions(ctx, sessions)
}
