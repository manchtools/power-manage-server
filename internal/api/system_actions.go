package api

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/store"
)

// SystemActionManager creates and maintains system-managed actions
// (user provisioning, SSH access, TTY user) for PM users. The actions
// are stored in actions_projection. Delivery to devices splits into
// two paths:
//
//   - User-account and SSH-access actions are routed through
//     assignments_projection, so the resolution engine picks them
//     up automatically for devices with assigned users.
//   - The TTY user action is the exception: it is linked to the
//     owning user via users_projection.system_tty_action_id but is
//     NOT routed through assignments_projection. Delivery is
//     permission-derived in resolution.ResolveActionsForDevice —
//     every device receives the TTY action of every user holding
//     StartTerminal, regardless of assignment. See
//     syncTtyUserAction below.
//
// Future system actions added here should follow the user-account /
// SSH pattern and ride assignments unless they share TTY's "must
// land on every device for permission holders" property.
type SystemActionManager struct {
	store   *store.Store
	signer  ca.ActionSigner
	logger  *slog.Logger
	actions *systemActionStore
}

// NewSystemActionManager creates a new system action manager.
func NewSystemActionManager(st *store.Store, signer ca.ActionSigner, logger *slog.Logger) *SystemActionManager {
	return &SystemActionManager{
		store:   st,
		signer:  signer,
		logger:  logger.With("component", "system_actions"),
		actions: newSystemActionStore(st, signer),
	}
}

// SyncAllUsersSystemActions ensures all users have correct system actions.
// Called at startup and after global settings changes. Idempotent.
func (m *SystemActionManager) SyncAllUsersSystemActions(ctx context.Context) error {
	users, err := m.store.Repos().User.ListAllNonDeleted(ctx)
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}

	var errCount int
	for _, u := range users {
		if err := m.SyncUserSystemActions(ctx, u.ID); err != nil {
			m.logger.Error("failed to sync system actions for user", "user_id", u.ID, "error", err)
			errCount++
		}
	}

	if errCount > 0 {
		m.logger.Warn("some users failed system action sync", "failed", errCount, "total", len(users))
	} else {
		// Demoted from Info to Debug in rc11 (#77): the periodic
		// reconciler runs this on a tight cadence (default 1m), so
		// success-on-every-tick at Info would flood operator logs.
		// Startup callers in cmd/control/main.go log their own Info
		// line so the one-shot startup sweep stays visible.
		m.logger.Debug("system actions synced for all users", "count", len(users))
	}

	return nil
}

// StartReconciliation launches a background goroutine that periodically
// runs SyncAllUsersSystemActions as the durability safety net for the
// event-driven listener (see system_actions_listener.go). Closes drift
// gaps if the listener fires post-commit but the process dies before
// the sync runs, plus any future event type added to the schema
// without being added to the AffectedFromEvent classifier.
//
// Guards:
//   - atomic flag prevents a slow sweep from stacking another one
//     behind it under DB pressure / large fleets;
//   - per-sweep timeout cancels a stuck invocation rather than piling
//     up missed ticks;
//   - SyncAllUsersSystemActions is already best-effort per user, so
//     one bad user cannot abort the sweep.
//
// rc11 #77.
func (m *SystemActionManager) StartReconciliation(ctx context.Context, interval, sweepTimeout time.Duration) {
	if interval <= 0 {
		m.logger.Info("system-action reconciliation disabled (interval <= 0)")
		return
	}
	// A non-positive sweepTimeout would feed an already-cancelled
	// context into SyncAllUsersSystemActions on every tick — the
	// reconciler would log an error every interval and never make
	// progress. parseFlags also clamps env input, but defend in depth
	// here so a buggy programmatic caller can't silently break the
	// safety net. Round-3 review of rc11 #77.
	if sweepTimeout <= 0 {
		m.logger.Warn("system-action reconciliation sweep timeout <= 0; falling back to interval as ceiling",
			"sweep_timeout", sweepTimeout, "interval", interval)
		sweepTimeout = interval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		var running atomic.Bool

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !running.CompareAndSwap(false, true) {
					m.logger.Warn("skipping system-action reconciliation tick — previous sweep still running")
					continue
				}
				sweepCtx, cancel := context.WithTimeout(ctx, sweepTimeout)
				if err := m.SyncAllUsersSystemActions(sweepCtx); err != nil {
					m.logger.Error("periodic system-action reconciliation failed", "error", err)
				}
				cancel()
				running.Store(false)
			}
		}
	}()
}

// SyncUserSystemActions ensures a user's system actions are up to date.
// Actions are only created when provisioning is enabled (globally or per-user).
// When provisioning is disabled, existing actions are cleaned up.
// Disabled users get a disabled flag in their USER action params.
// Idempotent and safe to call after any user mutation.
func (m *SystemActionManager) SyncUserSystemActions(ctx context.Context, userID string) error {
	user, err := m.store.Repos().User.Get(ctx, userID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	// Skip users with no linux username (shouldn't happen after migration)
	if user.LinuxUsername == "" {
		m.logger.Warn("user has no linux username, skipping system actions", "user_id", userID)
		return nil
	}

	// Read global settings from DB
	settings, err := m.store.Queries().GetServerSettings(ctx)
	if err != nil {
		return fmt.Errorf("get server settings: %w", err)
	}

	provisionNeeded := settings.UserProvisioningEnabled || user.UserProvisioningEnabled
	sshNeeded := settings.SshAccessForAll || user.SshAccessEnabled

	// Parse SSH public keys from JSONB
	sshKeys := parseSshPublicKeys(user.SshPublicKeys)

	// --- System USER action ---
	if provisionNeeded {
		if err := m.syncUserProvisionAction(ctx, user, sshKeys); err != nil {
			m.logger.Error("failed to sync user provision action", "user_id", userID, "error", err)
		}
	} else {
		if err := m.cleanupUserAction(ctx, user); err != nil {
			m.logger.Error("failed to cleanup user provision action", "user_id", userID, "error", err)
		}
	}

	// --- System SSH action ---
	if sshNeeded {
		if err := m.syncSshAccessAction(ctx, user); err != nil {
			m.logger.Error("failed to sync ssh access action", "user_id", userID, "error", err)
		}
	} else {
		if err := m.cleanupSshAction(ctx, user); err != nil {
			m.logger.Error("failed to cleanup ssh access action", "user_id", userID, "error", err)
		}
	}

	// --- System TTY user action (for remote terminal sessions) ---
	// The pm-tty-* account is created on the user's assigned devices
	// when the user holds the StartTerminal permission (directly or
	// via a user group role). When the permission is revoked, the
	// action is cleaned up so the account is removed from devices.
	//
	// If the permission query fails, we skip the TTY block entirely
	// and leave the existing state untouched — a transient DB error
	// must NOT trigger a cleanup that deletes a working TTY account.
	permissions, err := m.store.Repos().User.Permissions(ctx, userID)
	if err != nil {
		m.logger.Error("failed to resolve user permissions for tty action sync; leaving TTY state unchanged",
			"user_id", userID, "error", err)
	} else {
		ttyNeeded := false
		for _, p := range permissions {
			if p == "StartTerminal" {
				ttyNeeded = true
				break
			}
		}
		if ttyNeeded {
			if err := m.syncTtyUserAction(ctx, user); err != nil {
				m.logger.Error("failed to sync tty user action", "user_id", userID, "error", err)
			}
		} else {
			if err := m.cleanupTtyAction(ctx, user); err != nil {
				m.logger.Error("failed to cleanup tty user action", "user_id", userID, "error", err)
			}
		}
	}

	return nil
}

// CleanupDeletedUserActions removes all system actions for a deleted user.
// Must be called with the user projection loaded BEFORE the delete event.
func (m *SystemActionManager) CleanupDeletedUserActions(ctx context.Context, user store.User) error {
	if user.SystemUserActionID != "" {
		if err := m.actions.DeleteAction(ctx, user.SystemUserActionID); err != nil {
			m.logger.Error("failed to delete system user action", "action_id", user.SystemUserActionID, "error", err)
		}
		if err := m.actions.LinkAction(ctx, user.ID, "system_user_action_id", ""); err != nil {
			m.logger.Error("failed to unlink system user action", "user_id", user.ID, "error", err)
		}
	}
	if user.SystemSshActionID != "" {
		if err := m.actions.DeleteAction(ctx, user.SystemSshActionID); err != nil {
			m.logger.Error("failed to delete system ssh action", "action_id", user.SystemSshActionID, "error", err)
		}
		if err := m.actions.LinkAction(ctx, user.ID, "system_ssh_action_id", ""); err != nil {
			m.logger.Error("failed to unlink system ssh action", "user_id", user.ID, "error", err)
		}
	}
	if user.SystemTtyActionID != "" {
		if err := m.actions.DeleteAction(ctx, user.SystemTtyActionID); err != nil {
			m.logger.Error("failed to delete system tty action", "action_id", user.SystemTtyActionID, "error", err)
		}
		if err := m.actions.LinkAction(ctx, user.ID, "system_tty_action_id", ""); err != nil {
			m.logger.Error("failed to unlink system tty action", "user_id", user.ID, "error", err)
		}
	}
	return nil
}

func (m *SystemActionManager) syncUserProvisionAction(ctx context.Context, user store.User, sshKeys []string) error {
	comment := user.DisplayName
	if comment == "" {
		comment = user.Email
	}

	// Typed *pm.UserParams (not map[string]any) so the Go compiler
	// rejects any field name that doesn't exist on the proto. A past
	// bug in syncTtyUserAction used the key "system" which protojson
	// silently dropped on unmarshal — that class of typo cannot
	// recur here.
	params := &pm.UserParams{
		Username:   user.LinuxUsername,
		Uid:        user.LinuxUID,
		CreateHome: true,
		Comment:    comment,
		Disabled:   user.Disabled,
	}
	if len(sshKeys) > 0 {
		params.SshAuthorizedKeys = sshKeys
	}

	paramsJSON, err := actionparams.MarshalActionParams(params)
	if err != nil {
		return fmt.Errorf("marshal user params: %w", err)
	}

	actionName := "system:user-provision:" + user.ID

	if user.SystemUserActionID == "" {
		// Create new system action
		actionID, err := m.actions.CreateAction(ctx, actionName, int32(pm.ActionType_ACTION_TYPE_USER), int32(pm.DesiredState_DESIRED_STATE_PRESENT), paramsJSON)
		if err != nil {
			return fmt.Errorf("create user provision action: %w", err)
		}

		if err := m.actions.AssignActionToUser(ctx, actionID, user.ID); err != nil {
			return fmt.Errorf("assign user provision action: %w", err)
		}

		if err := m.actions.LinkAction(ctx, user.ID, "system_user_action_id", actionID); err != nil {
			return fmt.Errorf("link user provision action: %w", err)
		}

		if err := m.actions.SignActionByID(ctx, actionID); err != nil {
			return fmt.Errorf("sign newly created user provision action: %w", err)
		}
		m.logger.Info("created system user provision action", "user_id", user.ID, "action_id", actionID)
	} else {
		// Update existing action if params changed
		if err := m.actions.UpdateAction(ctx, user.SystemUserActionID, int32(pm.DesiredState_DESIRED_STATE_PRESENT), paramsJSON); err != nil {
			return fmt.Errorf("update user provision action: %w", err)
		}
		if err := m.actions.SignActionByID(ctx, user.SystemUserActionID); err != nil {
			return fmt.Errorf("re-sign updated user provision action: %w", err)
		}
	}

	return nil
}

func (m *SystemActionManager) syncSshAccessAction(ctx context.Context, user store.User) error {
	// Typed *pm.SshParams — same rationale as syncUserProvisionAction.
	params := &pm.SshParams{
		Users:         []string{user.LinuxUsername},
		AllowPubkey:   user.SshAllowPubkey,
		AllowPassword: user.SshAllowPassword,
	}

	paramsJSON, err := actionparams.MarshalActionParams(params)
	if err != nil {
		return fmt.Errorf("marshal ssh params: %w", err)
	}

	actionName := "system:ssh-access:" + user.ID

	if user.SystemSshActionID == "" {
		// Create new system action
		actionID, err := m.actions.CreateAction(ctx, actionName, int32(pm.ActionType_ACTION_TYPE_SSH), int32(pm.DesiredState_DESIRED_STATE_PRESENT), paramsJSON)
		if err != nil {
			return fmt.Errorf("create ssh access action: %w", err)
		}

		if err := m.actions.AssignActionToUser(ctx, actionID, user.ID); err != nil {
			return fmt.Errorf("assign ssh access action: %w", err)
		}

		if err := m.actions.LinkAction(ctx, user.ID, "system_ssh_action_id", actionID); err != nil {
			return fmt.Errorf("link ssh access action: %w", err)
		}

		if err := m.actions.SignActionByID(ctx, actionID); err != nil {
			return fmt.Errorf("sign newly created ssh access action: %w", err)
		}
		m.logger.Info("created system ssh access action", "user_id", user.ID, "action_id", actionID)
	} else {
		// Update existing action
		if err := m.actions.UpdateAction(ctx, user.SystemSshActionID, int32(pm.DesiredState_DESIRED_STATE_PRESENT), paramsJSON); err != nil {
			return fmt.Errorf("update ssh access action: %w", err)
		}
		if err := m.actions.SignActionByID(ctx, user.SystemSshActionID); err != nil {
			return fmt.Errorf("re-sign updated ssh access action: %w", err)
		}
	}

	return nil
}

func (m *SystemActionManager) cleanupUserAction(ctx context.Context, user store.User) error {
	if user.SystemUserActionID == "" {
		return nil
	}
	if err := m.actions.DeleteAction(ctx, user.SystemUserActionID); err != nil {
		m.logger.Error("failed to delete system user action", "action_id", user.SystemUserActionID, "error", err)
	}
	if err := m.actions.LinkAction(ctx, user.ID, "system_user_action_id", ""); err != nil {
		m.logger.Error("failed to unlink system user action", "user_id", user.ID, "error", err)
	}
	m.logger.Info("cleaned up system user provision action", "user_id", user.ID)
	return nil
}

func (m *SystemActionManager) cleanupSshAction(ctx context.Context, user store.User) error {
	if user.SystemSshActionID == "" {
		return nil
	}
	if err := m.actions.DeleteAction(ctx, user.SystemSshActionID); err != nil {
		m.logger.Error("failed to delete system ssh action", "action_id", user.SystemSshActionID, "error", err)
	}
	if err := m.actions.LinkAction(ctx, user.ID, "system_ssh_action_id", ""); err != nil {
		m.logger.Error("failed to unlink system ssh action", "user_id", user.ID, "error", err)
	}
	m.logger.Info("cleaned up system ssh access action", "user_id", user.ID)
	return nil
}

// syncTtyUserAction ensures a dedicated pm-tty-<linux_username>
// system User action exists for the given user. Delivery is NOT
// driven by an assignment — the action is linked to the user via
// users_projection.system_tty_action_id and surfaced to devices by
// resolution.ResolveActionsForDevice's permission-derived layer
// (every device gets the TTY action of every user holding
// StartTerminal). See the package-level comment on
// SystemActionManager for the split rationale.
// The action uses nologin as the shell (the agent temporarily
// activates it during a session), no home directory, and the
// deterministic UID from the SDK's TTYUID helper.
func (m *SystemActionManager) syncTtyUserAction(ctx context.Context, user store.User) error {
	// Typed *pm.UserParams so the Go compiler rejects field-name
	// typos. The previous map[string]any form accepted "system": true
	// as a sibling of real fields — protojson silently dropped it on
	// unmarshal and pm-tty-* accounts stayed visible on login screens.
	//
	// Field choices here:
	//   - Hidden=true: AccountsService SystemAccount=true so the
	//     account does NOT appear on graphical login screens
	//     (GDM/SDDM/LightDM). This is what the previous "system"
	//     key was trying (and failing) to express.
	//   - CreateHome=false: pm-tty-* accounts are nologin by design
	//     and should have no home directory. This used to be
	//     silently inverted to true by the agent for non-system
	//     users; agent-side fix is tracked separately but the
	//     contract on the wire is now unambiguous.
	//   - SystemUser=false (not set) deliberately: useradd --system
	//     implies UID < 1000, which conflicts with pm-tty's
	//     deterministic UID = <base>+100000. Visibility hiding uses
	//     the Hidden bit instead.
	params := systemTtyUserParams(user)

	paramsJSON, err := actionparams.MarshalActionParams(params)
	if err != nil {
		return fmt.Errorf("marshal tty user params: %w", err)
	}

	actionName := "system:tty-user:" + user.ID

	if user.SystemTtyActionID == "" {
		// Create new system action. We deliberately do NOT emit an
		// AssignmentCreated event for the TTY action — delivery is
		// driven by the permission-derived path in resolution.go,
		// which materializes the pm-tty-<username> account on every
		// device whenever the user holds the StartTerminal permission.
		// Coupling delivery to a per-user assignment was the original
		// bug: admins manage the fleet without being assigned to any
		// individual device, so their TTY accounts never landed.
		actionID, err := m.actions.CreateAction(ctx, actionName, int32(pm.ActionType_ACTION_TYPE_USER), int32(pm.DesiredState_DESIRED_STATE_PRESENT), paramsJSON)
		if err != nil {
			return fmt.Errorf("create tty user action: %w", err)
		}

		if err := m.actions.LinkAction(ctx, user.ID, "system_tty_action_id", actionID); err != nil {
			return fmt.Errorf("link tty user action: %w", err)
		}

		if err := m.actions.SignActionByID(ctx, actionID); err != nil {
			return fmt.Errorf("sign newly created tty user action: %w", err)
		}
		m.logger.Info("created system tty user action",
			"user_id", user.ID, "action_id", actionID, "tty_user", params.Username)
	} else {
		// Update existing action if params changed
		if err := m.actions.UpdateAction(ctx, user.SystemTtyActionID, int32(pm.DesiredState_DESIRED_STATE_PRESENT), paramsJSON); err != nil {
			return fmt.Errorf("update tty user action: %w", err)
		}
		if err := m.actions.SignActionByID(ctx, user.SystemTtyActionID); err != nil {
			return fmt.Errorf("re-sign updated tty user action: %w", err)
		}
	}

	return nil
}

func systemTtyUserParams(user store.User) *pm.UserParams {
	ttyUsername := "pm-tty-" + user.LinuxUsername
	ttyUID := int32(int(user.LinuxUID) + 100000) // terminal.DefaultUIDOffset

	return &pm.UserParams{
		Username:   ttyUsername,
		Uid:        ttyUID,
		Shell:      "/usr/sbin/nologin",
		CreateHome: false,
		Comment:    "Power Manage terminal user for " + user.LinuxUsername,
		Hidden:     true,
		Disabled:   user.Disabled,
	}
}

func (m *SystemActionManager) cleanupTtyAction(ctx context.Context, user store.User) error {
	if user.SystemTtyActionID == "" {
		return nil
	}
	if err := m.actions.DeleteAction(ctx, user.SystemTtyActionID); err != nil {
		m.logger.Error("failed to delete system tty action", "action_id", user.SystemTtyActionID, "error", err)
	}
	if err := m.actions.LinkAction(ctx, user.ID, "system_tty_action_id", ""); err != nil {
		m.logger.Error("failed to unlink system tty action", "user_id", user.ID, "error", err)
	}
	m.logger.Info("cleaned up system tty user action", "user_id", user.ID)
	return nil
}

// parseSshPublicKeys extracts the non-empty public_key strings from
// the typed slice the user repo now returns (Wave E.3, tracker #242).
func parseSshPublicKeys(keys []store.SshPublicKey) []string {
	result := make([]string, 0, len(keys))
	for _, k := range keys {
		if k.PublicKey != nil && *k.PublicKey != "" {
			result = append(result, *k.PublicKey)
		}
	}
	return result
}
