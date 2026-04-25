package api

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/store"
)

// SyncOp is the action a system-action listener should take in response
// to a permission-shaping event. The "all-users" cases (role / group
// fan-outs, server-settings) deliberately route to a full sweep rather
// than materialising a potentially-large affected-user list in the
// classifier path — the manager's full sweep is already efficient and
// one sweep is cheaper than thousands of per-user enqueues on a big
// fleet. rc11 #77.
type SyncOp int

const (
	SyncOpNone        SyncOp = iota // event does not affect system actions
	SyncOpSyncUser                  // SyncUserSystemActions(userID)
	SyncOpCleanupUser               // CleanupDeletedUserActions(userProjection)
	SyncOpSyncAll                   // SyncAllUsersSystemActions — fan-out events
)

// AffectedFromEvent classifies an event into the system-action sync
// operation it should trigger and (for per-user ops) the user IDs
// involved.
//
// Adding a new permission-shaping event in a future handler only
// requires adding a case here. The periodic reconciler is the safety
// net for events the classifier has not yet learned about, so a missed
// case manifests as bounded drift (~one reconcile interval), not
// silent failure.
func AffectedFromEvent(e store.PersistedEvent) (SyncOp, []string) {
	switch e.EventType {
	// Direct user-scoped events — system actions for the named user
	// must be re-evaluated. The user_id source varies: for `user`
	// stream events it's the StreamID; for `user_role` it's in the
	// event Data payload.
	case "UserCreated",
		"UserDisabled",
		"UserEnabled",
		"UserLinuxUsernameChanged",
		"UserProvisioningSettingsUpdated",
		"UserSshSettingsUpdated",
		"UserProfileUpdated",
		"UserSshKeyAdded",
		"UserSshKeyRemoved",
		"UserEmailChanged":
		// stream_type=user, stream_id=user_id
		return SyncOpSyncUser, []string{e.StreamID}

	case "UserRoleAssigned", "UserRoleRevoked":
		// stream_type=user_role, stream_id=user_id:role_id; user_id
		// also lives in event.data["user_id"] for clarity. Read the
		// data payload to avoid parsing the colon-joined StreamID.
		uid := userIDFromEventData(e)
		if uid == "" {
			return SyncOpNone, nil
		}
		return SyncOpSyncUser, []string{uid}

	case "UserGroupMemberAdded", "UserGroupMemberRemoved":
		// stream_type=user_group, event.data carries user_id of the
		// added/removed member.
		uid := userIDFromEventData(e)
		if uid == "" {
			return SyncOpNone, nil
		}
		return SyncOpSyncUser, []string{uid}

	// UserDeleted is deliberately NOT handled here.
	// CleanupDeletedUserActions needs the user projection loaded
	// BEFORE the delete is applied (it reads the system_*_action_id
	// columns to find the actions to clean up), so it must run in
	// the handler that emits the event, not in a post-commit
	// listener. DeleteUser in user_handler.go and the SCIM
	// delete path each call CleanupDeletedUserActions with the
	// pre-delete projection. This is the one place the derived-
	// model invariant gets a documented exception.

	// Fan-out events — affect every holder / member / user. Route to
	// the full sweep instead of materialising the affected set.
	case "RoleUpdated",
		"RoleDeleted",
		"UserGroupRoleAssigned",
		"UserGroupRoleRevoked",
		"UserGroupDeleted",
		"UserGroupQueryUpdated",
		"ServerSettingUpdated":
		return SyncOpSyncAll, nil

	default:
		return SyncOpNone, nil
	}
}

// userIDFromEventData extracts event.data["user_id"] as a string.
// Returns "" if the field is missing or not a string — caller treats
// that as a no-op event rather than panicking.
func userIDFromEventData(e store.PersistedEvent) string {
	if len(e.Data) == 0 {
		return ""
	}
	var data map[string]any
	if err := json.Unmarshal(e.Data, &data); err != nil {
		return ""
	}
	if v, ok := data["user_id"].(string); ok {
		return v
	}
	return ""
}

// SystemActionListener is the registerable EventListener that turns
// AppendEvent post-commit hooks into system-action sync calls. Wire it
// into the store at service boot in cmd/control/main.go:
//
//	st.RegisterEventListener(api.SystemActionListener(svc.SystemActions(), st, logger))
//
// Errors from the underlying sync calls are logged and swallowed —
// listeners are post-commit, fire-and-forget; failures are caught by
// the periodic reconciler within one interval.
//
// The listener spawns a goroutine for every dispatch so AppendEvent's
// post-commit path is never blocked on system-action work. Synchronous
// invocation would have made fan-out events (RoleUpdated, RoleDeleted,
// UserGroupRoleAssigned/Revoked, UserGroupDeleted, ServerSettingUpdated)
// turn small admin RPCs into O(all-users) request-path work — review
// finding from #77's first cut. The goroutine context is detached from
// the AppendEvent ctx (which may be cancelled the moment the RPC
// returns) and uses Background so the sync survives the request.
func SystemActionListener(mgr *SystemActionManager, st *store.Store, logger *slog.Logger) store.EventListener {
	return func(_ context.Context, e store.PersistedEvent) {
		op, userIDs := AffectedFromEvent(e)
		if op == SyncOpNone {
			return
		}

		// Detached goroutine. context.Background() rather than the
		// AppendEvent ctx because the RPC that triggered the event
		// may have already returned (cancelling its ctx) by the time
		// the sync runs — we want the work to complete regardless.
		// Failures are caught by the periodic reconciler if the
		// goroutine itself dies before logging.
		go func() {
			ctx := context.Background()
			switch op {
			case SyncOpSyncUser:
				for _, uid := range userIDs {
					if err := mgr.SyncUserSystemActions(ctx, uid); err != nil {
						logger.Error("system-action listener: sync user failed",
							"user_id", uid, "event_type", e.EventType, "event_id", e.ID, "error", err)
					}
				}

			case SyncOpCleanupUser:
				// AffectedFromEvent never returns this op currently —
				// see the comment on the UserDeleted case in the
				// classifier. Kept as a tagged enum for future events
				// that don't have the load-before-emit ordering issue.
				logger.Warn("system-action listener: SyncOpCleanupUser invoked but not implemented; handler-side cleanup is canonical",
					"event_type", e.EventType, "event_id", e.ID)

			case SyncOpSyncAll:
				// Fan-out events fire SyncAllUsersSystemActions. On
				// large fleets this can take seconds; doing it on
				// the AppendEvent path would have made small admin
				// RPCs O(all-users) — review finding addressed.
				if err := mgr.SyncAllUsersSystemActions(ctx); err != nil {
					logger.Error("system-action listener: sync all users failed",
						"event_type", e.EventType, "event_id", e.ID, "error", err)
				}
			}
		}()
	}
}
