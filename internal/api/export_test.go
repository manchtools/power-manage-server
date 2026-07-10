package api

import (
	"context"
	"time"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
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

// SetDummyVerifyForTest overrides this handler's per-instance dummy-bcrypt seam
// (the discarded timing-equalisation comparison on the Login miss paths) so a
// test can confirm the control runs. Per-instance: no shared global, so it is
// race-free even across parallel tests. Compiled only into test binaries; the
// real password check (auth.VerifyPassword) is unaffected.
func (h *AuthHandler) SetDummyVerifyForTest(fn func(password, hash string) bool) {
	h.dummyVerify = fn
}

// SetNowForTest overrides the DeviceHandler clock seam so the spec-22
// freshness boundary tests can pin "now" against a fixed collected_at.
// Compiled only into test binaries.
func (h *DeviceHandler) SetNowForTest(now func() time.Time) { h.now = now }

// SetExportPageSizeForTest shrinks the ExportAuditEvents page seam so
// chunking tests can prove multi-chunk exports without seeding a
// thousand events. Returns a restore func. Compiled only into test
// binaries.
func SetExportPageSizeForTest(n int) (restore func()) {
	prev := exportPageSize
	exportPageSize = n
	return func() { exportPageSize = prev }
}
