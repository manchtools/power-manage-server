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

// SetRenewCertTestHook installs the test-only seam invoked between the
// fingerprint check and certificate issuance in RenewCertificate, letting the
// concurrency regression test widen the read→append window. Compiled only into
// test binaries. Pass nil to clear.
func SetRenewCertTestHook(fn func()) { renewCertTestHook = fn }
