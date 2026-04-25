package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

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
		// also lives in event.data["user_id"] for clarity. Prefer the
		// data payload (cleaner contract); fall back to splitting the
		// StreamID so a future emitter that drops the data field
		// degrades to "still works" instead of "silent SyncOpNone for
		// up to one reconcile interval." The role case is the only
		// place this fallback is meaningful — group membership uses
		// the group ID as StreamID, so user_id is data-only.
		if uid := userIDFromEventData(e); uid != "" {
			return SyncOpSyncUser, []string{uid}
		}
		if uid, _, ok := strings.Cut(e.StreamID, ":"); ok && uid != "" {
			return SyncOpSyncUser, []string{uid}
		}
		return SyncOpNone, nil

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

// defaultListenerSyncTimeout is the fallback per-dispatch context
// deadline when a caller passes 0. Matches the periodic reconciler's
// default sweep timeout (5m) so a wedged DB / signer can't leak a
// goroutine on either path. Callers that want a different bound pass
// it explicitly to SystemActionListener.
const defaultListenerSyncTimeout = 5 * time.Minute

// listenerMaxConcurrentDispatches caps the number of in-flight sync
// goroutines spawned by the listener. Prevents a SCIM bulk role
// assignment that emits thousands of UserRoleAssigned events from
// saturating the pgx pool / signer. When the cap is hit the event is
// dropped (logged) — the periodic reconciler will catch up within one
// interval, so back-pressure is preferred over unbounded fan-out.
// Round-3 review of rc11 #77.
const listenerMaxConcurrentDispatches = 16

// SystemActionListener is the registerable EventListener that turns
// AppendEvent post-commit hooks into system-action sync calls. Wire it
// into the store at service boot in cmd/control/main.go:
//
//	st.RegisterEventListener(api.SystemActionListener(svc.SystemActions(), logger, cfg.SystemActionReconcileTimeout))
//
// Errors from the underlying sync calls are logged and swallowed —
// listeners are post-commit, fire-and-forget; failures are caught by
// the periodic reconciler within one interval.
//
// The listener spawns a goroutine for every dispatch so AppendEvent's
// post-commit path is never blocked on system-action work. Synchronous
// invocation would have made fan-out events (RoleUpdated, RoleDeleted,
// UserGroupRoleAssigned/Revoked, UserGroupDeleted, ServerSettingUpdated)
// turn small admin RPCs into O(all-users) request-path work.
//
// Concurrency control:
//   - syncTimeout bounds each goroutine (defaulting to
//     defaultListenerSyncTimeout when 0). Without the bound a wedged
//     DB / signer would leak goroutines indefinitely.
//   - A bounded semaphore (listenerMaxConcurrentDispatches) caps
//     in-flight syncs so a burst of per-user events can't exhaust
//     the pgx pool. Over-cap events are dropped + logged; the
//     reconciler will catch them.
//   - SyncOpSyncAll uses an atomic.Bool to coalesce: if a fan-out
//     sweep is already running, subsequent fan-out events return
//     immediately rather than stacking N concurrent O(all-users)
//     sweeps that step on each other. Same pattern the reconciler
//     uses for its tick path.
//
// Each goroutine uses context.WithoutCancel(parent) under
// context.WithTimeout: the AppendEvent ctx is detached (the RPC may
// have already returned by sync time), but request-scoped values
// like request_id are preserved so error logs correlate back to the
// triggering RPC.
func SystemActionListener(mgr *SystemActionManager, logger *slog.Logger, syncTimeout time.Duration) store.EventListener {
	if syncTimeout <= 0 {
		syncTimeout = defaultListenerSyncTimeout
	}

	sem := make(chan struct{}, listenerMaxConcurrentDispatches)
	var syncAllInFlight atomic.Bool

	return func(parent context.Context, e store.PersistedEvent) {
		op, userIDs := AffectedFromEvent(e)
		if op == SyncOpNone {
			return
		}

		// Coalesce fan-out events. If a sweep is already running it
		// will pick up state changes emitted before its commit; if
		// not, we own the flag and must clear it on goroutine exit.
		if op == SyncOpSyncAll && !syncAllInFlight.CompareAndSwap(false, true) {
			logger.Debug("system-action listener: coalescing fan-out event into in-flight sweep",
				"event_type", e.EventType, "event_id", e.ID)
			return
		}

		select {
		case sem <- struct{}{}:
		default:
			logger.Warn("system-action listener: dispatch backpressure, dropping event (reconciler will catch up)",
				"event_type", e.EventType, "event_id", e.ID, "max_concurrent", listenerMaxConcurrentDispatches)
			if op == SyncOpSyncAll {
				syncAllInFlight.Store(false)
			}
			return
		}

		go func() {
			defer func() { <-sem }()
			if op == SyncOpSyncAll {
				defer syncAllInFlight.Store(false)
			}

			ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), syncTimeout)
			defer cancel()

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
				if err := mgr.SyncAllUsersSystemActions(ctx); err != nil {
					logger.Error("system-action listener: sync all users failed",
						"event_type", e.EventType, "event_id", e.ID, "error", err)
				}
			}
		}()
	}
}
