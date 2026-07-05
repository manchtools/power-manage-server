package api

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
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

	// Reconcile the two global TerminalAdmin actions (#70). The
	// periodic sweep + every listener-classified fan-out event runs
	// through this method, so embedding the call here means every
	// callsite gets the cohort update without having to know about
	// the new reconciler. Per-user listener events also call the
	// reconciler directly — see SystemActionListener.
	if err := m.ReconcileGlobalTerminalAdminActions(ctx); err != nil {
		m.logger.Error("failed to reconcile global TerminalAdmin actions during sync sweep", "error", err)
	}
	// Per-scope TerminalAdmin actions (#7) — same shape, keyed by
	// device-group scope.
	if err := m.ReconcileScopedTerminalAdminActions(ctx); err != nil {
		m.logger.Error("failed to reconcile scoped TerminalAdmin actions during sync sweep", "error", err)
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
	if store.IsNotFound(err) {
		// Deleted (or never-existed) user: NEVER generate or distribute a
		// system action for them (spec 19 E / AC 32 — an erased user must
		// never re-acquire a provisioning action). Graceful skip, not an
		// error, so a reconcile sweep doesn't log noise for erased users.
		return nil
	}
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	// Explicit fail-closed delete-state check at the generation choke
	// point (spec 19 AC 32). Does NOT lean on Get's incidental
	// is_deleted = FALSE filter: if a future Get is changed to return
	// soft-deleted rows, provisioning must STILL refuse an erased user.
	if user.IsDeleted {
		return nil
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

	// NoPassword=true: the pm-tty-* account is reached only via the
	// agent's setuid terminal-session opener (bypassing PAM), so the
	// agent must NOT generate a temp password and must NOT report an
	// lps.rotations row. Closes the LPS-leakage hole that the operator
	// would otherwise see if they ever held GetDeviceLpsPasswords.
	// Companion to sdk #77 + agent #94; precondition for TerminalAdmin
	// in #70. Refs #327.
	return &pm.UserParams{
		Username:   ttyUsername,
		Uid:        ttyUID,
		Shell:      "/usr/sbin/nologin",
		CreateHome: false,
		Comment:    "Power Manage terminal user for " + user.LinuxUsername,
		Hidden:     true,
		Disabled:   user.Disabled,
		NoPassword: true,
	}
}

// =============================================================================
// TerminalAdmin global system actions (manchtools/power-manage-server#70)
// =============================================================================
//
// Two globally-fanned-out AdminPolicy actions carry the LIMITED /
// FULL passwordless sudoers templates. Membership (the users[] list)
// is filled by the reconciler in ReconcileGlobalTerminalAdminActions
// (S3 — added in a subsequent slice); BootstrapGlobalTerminalAdminActions
// just makes sure the two action rows exist at server startup so the
// reconciler has something to update.
//
// Per the ADR and the user's design decisions: ONE action per access
// level, NOT one action per holder. #7 extends this to per-scope
// actions sharing the same reconciler shape.

// Global action names. The listener, audit redactor, and resolution
// layer all key on these strings — a typo here breaks the fan-out
// silently, which is why the test file (system_actions_terminal_admin_test.go)
// declares its own copies as canon to catch any drift.
const (
	GlobalTerminalAdminLimitedActionName = "system:terminal-admin-limited:global"
	GlobalTerminalAdminFullActionName    = "system:terminal-admin-full:global"
)

// BootstrapGlobalTerminalAdminActions makes sure the two global
// TerminalAdmin AdminPolicy actions exist. Idempotent — running on a
// fresh DB creates both rows; running on a DB that already has them
// is a no-op. Wired from cmd/control/main.go startup so a fresh
// deployment has these actions ready before the reconciler ticks.
//
// The bootstrap deliberately does NOT re-sign on the no-op path. The
// reconciler is the only path that mutates these actions after creation,
// and a re-sign per-server-start would invalidate every agent's cached
// copy on every restart of the server even when nothing changed.
func (m *SystemActionManager) BootstrapGlobalTerminalAdminActions(ctx context.Context) error {
	if err := m.bootstrapTerminalAdminAction(ctx,
		GlobalTerminalAdminLimitedActionName,
		pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_LIMITED); err != nil {
		return fmt.Errorf("bootstrap %s: %w", GlobalTerminalAdminLimitedActionName, err)
	}
	if err := m.bootstrapTerminalAdminAction(ctx,
		GlobalTerminalAdminFullActionName,
		pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_FULL); err != nil {
		return fmt.Errorf("bootstrap %s: %w", GlobalTerminalAdminFullActionName, err)
	}
	return nil
}

// ReconcileGlobalTerminalAdminActions recomputes users[] for both
// global TerminalAdmin actions and writes back if changed. A user
// enters the LIMITED cohort iff:
//
//   - non-deleted, non-disabled, has a linux_username, AND
//   - holds StartTerminal AND TerminalAdminLimited (directly or via
//     a user_group role).
//
// The FULL cohort is the same shape against TerminalAdminFull.
//
// Idempotency is load-bearing: the cohort is sorted deterministically
// and compared to what's already on the action. When equal, the
// reconciler returns without touching the action — no UpdateAction
// event, no SignActionByID call, no signature churn. Without that
// short-circuit, every reconcile tick (default 1 min) would invalidate
// every connected agent's cached copy of these actions even when
// nothing changed.
//
// Failure modes:
//   - A per-user permission lookup error is logged and the user is
//     SKIPPED (treated as if they hold no relevant perms). The
//     reconciler proceeds — one bad user must not prevent the rest of
//     the cohort from being materialized. This mirrors
//     SyncAllUsersSystemActions's best-effort-per-user shape.
//   - If either global action is missing, the reconciler returns an
//     error (BootstrapGlobalTerminalAdminActions must run first).
//     Silent no-op would mask a wiring bug at server startup.
func (m *SystemActionManager) ReconcileGlobalTerminalAdminActions(ctx context.Context) error {
	users, err := m.store.Repos().User.ListAllNonDeleted(ctx)
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}

	cohorts := m.computeTerminalAdminCohorts(ctx, users)

	// The global actions consume only the unscoped (Scope=="") cohorts;
	// per-scope cohorts are materialized by ReconcileScopedTerminalAdminActions.
	if err := m.reconcileOneTerminalAdmin(ctx,
		GlobalTerminalAdminLimitedActionName,
		pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_LIMITED,
		cohorts[cohortKey{Level: pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_LIMITED}]); err != nil {
		return fmt.Errorf("reconcile %s: %w", GlobalTerminalAdminLimitedActionName, err)
	}
	if err := m.reconcileOneTerminalAdmin(ctx,
		GlobalTerminalAdminFullActionName,
		pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_FULL,
		cohorts[cohortKey{Level: pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_FULL}]); err != nil {
		return fmt.Errorf("reconcile %s: %w", GlobalTerminalAdminFullActionName, err)
	}
	return nil
}

// computeTerminalAdminCohorts walks the user list and returns the two
// sorted, deduped pm-tty-* cohorts for the GLOBAL LIMITED/FULL sudo
// actions. The sort makes signature stability deterministic across runs;
// the dedup is defensive against a future permission backend that
// double-counts a user.
//
// #7 model (Model Y): the sudo cohort is driven by TerminalAdmin{Limited,
// Full} ALONE — StartTerminal is NO LONGER required (it drives the
// pm-tty account, a separate concern; the agent's sudo policy is inert
// and harmless when no account exists). This walks the user's scoped
// grants and counts only UNSCOPED (global) TerminalAdmin grants here;
// device-group-scoped grants drive the per-scope actions added in a
// follow-up and are intentionally ignored by the global cohort. A
// user_group-scoped TerminalAdmin grant has no device meaning and is
// ignored everywhere.
func (m *SystemActionManager) computeTerminalAdminCohorts(ctx context.Context, users []store.User) map[cohortKey][]string {
	sets := map[cohortKey]map[string]struct{}{}
	add := func(k cohortKey, ttyUser string) {
		if sets[k] == nil {
			sets[k] = map[string]struct{}{}
		}
		sets[k][ttyUser] = struct{}{}
	}
	for _, u := range users {
		if u.Disabled || u.LinuxUsername == "" {
			continue
		}
		grants, err := m.store.Repos().User.ScopedGrants(ctx, u.ID)
		if err != nil {
			// Skip the user this tick — the next tick will retry.
			// Aborting the whole reconcile on a single user's
			// transient DB error would block every other user from
			// landing on devices.
			m.logger.Error("scoped-grant lookup failed during terminal-admin reconcile; skipping user",
				"user_id", u.ID, "error", err)
			continue
		}
		ttyUser := "pm-tty-" + u.LinuxUsername
		for _, g := range grants {
			scope, ok := terminalAdminScopeKey(g)
			if !ok {
				continue // user_group / unknown scope — no device meaning
			}
			switch g.Permission {
			case "TerminalAdminLimited":
				add(cohortKey{Level: pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_LIMITED, Scope: scope}, ttyUser)
			case "TerminalAdminFull":
				add(cohortKey{Level: pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_FULL, Scope: scope}, ttyUser)
			}
		}
	}

	out := make(map[cohortKey][]string, len(sets))
	for k, set := range sets {
		cohort := make([]string, 0, len(set))
		for u := range set {
			cohort = append(cohort, u)
		}
		sort.Strings(cohort)
		out[k] = cohort
	}
	return out
}

func (m *SystemActionManager) reconcileOneTerminalAdmin(ctx context.Context, name string, accessLevel pm.AdminAccessLevel, desiredUsers []string) error {
	row, err := m.store.Queries().GetActionByName(ctx, name)
	if err != nil {
		// Includes the not-found case: bootstrap was skipped.
		return fmt.Errorf("lookup (run BootstrapGlobalTerminalAdminActions first): %w", err)
	}

	var current pm.AdminPolicyParams
	if err := protojson.Unmarshal(row.Params, &current); err != nil {
		return fmt.Errorf("unmarshal current params: %w", err)
	}

	// Short-circuit: same cohort → no churn.
	if slices.Equal(current.Users, desiredUsers) {
		return nil
	}

	// Emit one TerminalAdminMembershipRevoked event per user dropped
	// from the cohort. The diff is computed against the persisted
	// users[] BEFORE the update — so revocations are audited even
	// when several happen in the same reconcile tick. Additions are
	// NOT audited here; the role-grant itself is already on the audit
	// trail via the user_role stream.
	removed := diffRemoved(current.Users, desiredUsers)
	for _, ttyUser := range removed {
		m.emitTerminalAdminMembershipRevoked(ctx, ttyUser, row.ID, accessLevel)
	}

	newParams := &pm.AdminPolicyParams{
		AccessLevel: accessLevel,
		Users:       desiredUsers,
	}
	paramsJSON, err := actionparams.MarshalActionParams(newParams)
	if err != nil {
		return fmt.Errorf("marshal new params: %w", err)
	}

	if err := m.actions.UpdateAction(ctx, row.ID, row.DesiredState, paramsJSON); err != nil {
		return fmt.Errorf("update action: %w", err)
	}
	if err := m.actions.SignActionByID(ctx, row.ID); err != nil {
		return fmt.Errorf("re-sign action: %w", err)
	}
	m.logger.Info("reconciled terminal-admin action",
		"name", name, "action_id", row.ID, "users_count", len(desiredUsers))
	return nil
}

// diffRemoved returns the entries in `before` that are absent from
// `after`. Both slices are assumed to be sorted (the reconciler sorts
// the cohort and `current.Users` carries the previously-sorted set).
func diffRemoved(before, after []string) []string {
	afterSet := make(map[string]struct{}, len(after))
	for _, u := range after {
		afterSet[u] = struct{}{}
	}
	var out []string
	for _, u := range before {
		if _, ok := afterSet[u]; !ok {
			out = append(out, u)
		}
	}
	return out
}

// emitTerminalAdminMembershipRevoked writes one audit event per
// removed pm-tty-* user. Failures are logged and swallowed — the
// reconciler's primary job is to update the action's users[]; missing
// audit on a transient DB blip is recoverable (the action change is
// the canonical truth), but failing the whole reconcile would leave
// the action's users[] out of date until the next tick.
//
// stream_type is "terminal_admin_membership"; stream_id is the
// affected action_id so audit consumers can read per-action history
// via store.LoadStream.
func (m *SystemActionManager) emitTerminalAdminMembershipRevoked(ctx context.Context, ttyUsername, actionID string, accessLevel pm.AdminAccessLevel) {
	const prefix = "pm-tty-"
	linuxUsername := strings.TrimPrefix(ttyUsername, prefix)
	// userID is best-effort — the reconciler doesn't know which user
	// owned the linux_username at revocation time without a reverse
	// lookup. The lookup is cheap (one indexed query) and keeps the
	// audit row meaningful even if a linux_username is later reused.
	userID := m.lookupUserIDByLinuxUsername(ctx, linuxUsername)
	if err := m.store.AppendEvent(ctx, store.Event{
		StreamType: "terminal_admin_membership",
		StreamID:   actionID,
		EventType:  string(eventtypes.TerminalAdminMembershipRevoked),
		Data: payloads.TerminalAdminMembershipRevoked{
			UserID:        userID,
			LinuxUsername: linuxUsername,
			ActionID:      actionID,
			AccessLevel:   accessLevel.String(),
		},
		ActorType: "system",
		ActorID:   "system",
	}); err != nil {
		m.logger.Error("failed to emit TerminalAdminMembershipRevoked audit event",
			"action_id", actionID, "linux_username", linuxUsername, "error", err)
	}
}

func (m *SystemActionManager) lookupUserIDByLinuxUsername(ctx context.Context, linuxUsername string) string {
	users, err := m.store.Repos().User.ListAllNonDeleted(ctx)
	if err != nil {
		// Soft failure — audit can still attribute by linux_username
		// even if user_id is empty.
		return ""
	}
	for _, u := range users {
		if u.LinuxUsername == linuxUsername {
			return u.ID
		}
	}
	return ""
}

func (m *SystemActionManager) bootstrapTerminalAdminAction(ctx context.Context, name string, accessLevel pm.AdminAccessLevel) error {
	if _, err := m.store.Queries().GetActionByName(ctx, name); err == nil {
		// Already exists — no-op. The reconciler owns subsequent
		// mutations. NOT re-signing here is load-bearing: the agent
		// caches signed actions and a re-sign on every server start
		// would invalidate the cache without any params change.
		return nil
	} else if !store.IsNotFound(err) {
		return fmt.Errorf("lookup: %w", err)
	}

	params := &pm.AdminPolicyParams{
		AccessLevel: accessLevel,
		// users[] is intentionally empty at bootstrap. The reconciler
		// (S3) fills it on the next tick after any relevant event.
	}
	paramsJSON, err := actionparams.MarshalActionParams(params)
	if err != nil {
		return fmt.Errorf("marshal params: %w", err)
	}

	actionID, err := m.actions.CreateAction(ctx, name,
		int32(pm.ActionType_ACTION_TYPE_ADMIN_POLICY),
		int32(pm.DesiredState_DESIRED_STATE_PRESENT),
		paramsJSON)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	if err := m.actions.SignActionByID(ctx, actionID); err != nil {
		return fmt.Errorf("sign newly created action: %w", err)
	}
	m.logger.Info("created terminal-admin action",
		"name", name, "action_id", actionID, "access_level", accessLevel.String())
	return nil
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
