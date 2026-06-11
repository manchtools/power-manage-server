package api

import (
	"context"
	"log/slog"
	"time"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// userSessionTerminator closes a user's live terminal sessions. *TerminalHandler
// implements it; the interface keeps TerminalRevocationListener unit-testable
// without the gateway fan-out.
type userSessionTerminator interface {
	TerminateUserSessions(ctx context.Context, userID string)
}

// terminalRevocationCloseTimeout bounds the background close fan-out.
const terminalRevocationCloseTimeout = 30 * time.Second

// TerminalRevocationListener returns a post-commit event listener that closes a
// user's LIVE terminal sessions when their access is revoked — on UserDisabled
// or UserDeleted. The close (a gateway fan-out) runs on a background goroutine
// with its own timeout context, so it NEVER blocks the disable/delete RPC that
// triggered it and survives that request's context being cancelled when the RPC
// returns. Best-effort by design (audit l.174: a revoked user's already-open
// root shell must be killed, not left running until they disconnect).
//
// Scope: disable + delete only. Role-revoke is intentionally excluded — a user
// may retain terminal access via another role, so closing on every role-revoke
// could be wrong; that needs a "does the user still have terminal access?"
// recompute and is tracked separately.
func TerminalRevocationListener(term userSessionTerminator, logger *slog.Logger) store.EventListener {
	return func(_ context.Context, ev store.PersistedEvent) {
		if ev.StreamType != "user" {
			return
		}
		if ev.EventType != string(eventtypes.UserDisabled) && ev.EventType != string(eventtypes.UserDeleted) {
			return
		}
		userID := ev.StreamID
		logger.Info("revoking terminal access: closing user's live sessions", "user_id", userID, "event", ev.EventType)
		go func() {
			// Recover: an unrecovered panic in a spawned goroutine crashes the
			// whole control process — a best-effort session close must never do
			// that. Also log completion (with any context error) for observability.
			defer func() {
				if r := recover(); r != nil {
					logger.Error("panic while closing terminal sessions for a revoked user", "user_id", userID, "panic", r)
				}
			}()
			bgCtx, cancel := context.WithTimeout(context.Background(), terminalRevocationCloseTimeout)
			defer cancel()
			term.TerminateUserSessions(bgCtx, userID)
			logger.Info("closed terminal sessions for a revoked user", "user_id", userID, "context_error", bgCtx.Err())
		}()
	}
}
