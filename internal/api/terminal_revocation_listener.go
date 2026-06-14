package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"time"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
)

// permStartTerminal is the permission that lets a user open a terminal session.
// Losing it across every role/group is what ends terminal access. Matches the
// literal used throughout the handlers (there is no exported constant).
const permStartTerminal = "StartTerminal"

// userSessionTerminator closes a user's live terminal sessions. *TerminalHandler
// implements it; the interface keeps TerminalRevocationListener unit-testable
// without the gateway fan-out.
type userSessionTerminator interface {
	TerminateUserSessions(ctx context.Context, userID string)
}

// userPermissionChecker returns a user's flattened effective permissions
// (direct + group). store.Repos().User satisfies it; the interface keeps the
// listener unit-testable.
type userPermissionChecker interface {
	Permissions(ctx context.Context, userID string) ([]string, error)
}

// terminalRevocationCloseTimeout bounds the background close fan-out.
const terminalRevocationCloseTimeout = 30 * time.Second

// TerminalRevocationListener returns a post-commit event listener that closes a
// user's LIVE terminal sessions when their terminal access is revoked:
//
//   - UserDisabled / UserDeleted — all access is gone; close unconditionally.
//   - UserRoleRevoked — close ONLY if the revoke removed the user's last
//     StartTerminal grant. They may still hold it via another role or group, so
//     closing on every role-revoke would be wrong; this rechecks effective
//     permissions first (#391). A scoped revoke that leaves StartTerminal intact
//     is therefore a no-op.
//
// The close (a gateway fan-out) and the permission recheck run on a background
// goroutine with their own timeout context, so they never block the
// disable/delete/revoke RPC and survive that request's context being cancelled
// when it returns. Best-effort and panic-recovered — an unrecovered panic in a
// spawned goroutine would crash control. Audit l.174 / #391.
func TerminalRevocationListener(term userSessionTerminator, perms userPermissionChecker, logger *slog.Logger) store.EventListener {
	return func(_ context.Context, ev store.PersistedEvent) {
		var userID string
		recheckStartTerminal := false

		switch ev.EventType {
		case string(eventtypes.UserDisabled), string(eventtypes.UserDeleted):
			if ev.StreamType != "user" {
				return
			}
			userID = ev.StreamID
		case string(eventtypes.UserRoleRevoked):
			var p payloads.UserRoleRevoked
			if err := json.Unmarshal(ev.Data, &p); err != nil {
				logger.Error("terminal revocation: malformed UserRoleRevoked payload", "error", err)
				return
			}
			userID = p.UserID
			recheckStartTerminal = true
		case string(eventtypes.UserSessionInvalidated):
			// Role grants are revoked/updated via RoleHandler.bumpUserSessionVersion
			// (and the user-group equivalent), which emits UserSessionInvalidated —
			// NOT UserRoleRevoked. Treat it like a role revoke: recheck effective
			// permissions and close iff StartTerminal is gone. The stream is "user"
			// and StreamID is the userID (#391 gap closed in WS11).
			if ev.StreamType != "user" {
				return
			}
			userID = ev.StreamID
			recheckStartTerminal = true
		default:
			return
		}
		if userID == "" {
			return
		}
		eventType := ev.EventType

		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("panic while closing terminal sessions for a revoked user", "user_id", userID, "panic", r)
				}
			}()
			bgCtx, cancel := context.WithTimeout(context.Background(), terminalRevocationCloseTimeout)
			defer cancel()

			if recheckStartTerminal {
				// A role-revoke ends terminal access only if the user no longer
				// holds StartTerminal via ANY remaining role/group. Reading the
				// projection here (post-commit) reflects the revoke already
				// applied, so a stale grant can't keep a session alive.
				userPerms, err := perms.Permissions(bgCtx, userID)
				if err != nil {
					logger.Error("terminal revocation: failed to recheck StartTerminal", "user_id", userID, "error", err)
					return
				}
				if slices.Contains(userPerms, permStartTerminal) {
					return // still has terminal access — leave live sessions running
				}
			}

			logger.Info("revoking terminal access: closing user's live sessions", "user_id", userID, "event", eventType)
			term.TerminateUserSessions(bgCtx, userID)
			logger.Info("closed terminal sessions for a revoked user", "user_id", userID, "context_error", bgCtx.Err())
		}()
	}
}
