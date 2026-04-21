package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// SystemActionManager creates and maintains system-managed actions
// (user provisioning and SSH access) for PM users. These actions are
// stored in actions_projection and assigned to users via
// assignments_projection, so the resolution engine picks them up
// automatically for devices with assigned users.
type SystemActionManager struct {
	store  *store.Store
	signer ActionSigner
	logger *slog.Logger
}

// NewSystemActionManager creates a new system action manager.
func NewSystemActionManager(st *store.Store, signer ActionSigner, logger *slog.Logger) *SystemActionManager {
	return &SystemActionManager{
		store:  st,
		signer: signer,
		logger: logger.With("component", "system_actions"),
	}
}

// SyncAllUsersSystemActions ensures all users have correct system actions.
// Called at startup and after global settings changes. Idempotent.
func (m *SystemActionManager) SyncAllUsersSystemActions(ctx context.Context) error {
	users, err := m.store.Queries().ListAllNonDeletedUsers(ctx)
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
		m.logger.Info("system actions synced for all users", "count", len(users))
	}

	return nil
}

// SyncUserSystemActions ensures a user's system actions are up to date.
// Actions are only created when provisioning is enabled (globally or per-user).
// When provisioning is disabled, existing actions are cleaned up.
// Disabled users get a disabled flag in their USER action params.
// Idempotent and safe to call after any user mutation.
func (m *SystemActionManager) SyncUserSystemActions(ctx context.Context, userID string) error {
	user, err := m.store.Queries().GetUserByID(ctx, userID)
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
	permissions, err := m.store.Queries().GetUserPermissionsWithGroups(ctx, userID)
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
func (m *SystemActionManager) CleanupDeletedUserActions(ctx context.Context, user db.UsersProjection) error {
	if user.SystemUserActionID != "" {
		if err := m.deleteSystemAction(ctx, user.SystemUserActionID); err != nil {
			m.logger.Error("failed to delete system user action", "action_id", user.SystemUserActionID, "error", err)
		}
		if err := m.linkSystemAction(ctx, user.ID, "system_user_action_id", ""); err != nil {
			m.logger.Error("failed to unlink system user action", "user_id", user.ID, "error", err)
		}
	}
	if user.SystemSshActionID != "" {
		if err := m.deleteSystemAction(ctx, user.SystemSshActionID); err != nil {
			m.logger.Error("failed to delete system ssh action", "action_id", user.SystemSshActionID, "error", err)
		}
		if err := m.linkSystemAction(ctx, user.ID, "system_ssh_action_id", ""); err != nil {
			m.logger.Error("failed to unlink system ssh action", "user_id", user.ID, "error", err)
		}
	}
	if user.SystemTtyActionID != "" {
		if err := m.deleteSystemAction(ctx, user.SystemTtyActionID); err != nil {
			m.logger.Error("failed to delete system tty action", "action_id", user.SystemTtyActionID, "error", err)
		}
		if err := m.linkSystemAction(ctx, user.ID, "system_tty_action_id", ""); err != nil {
			m.logger.Error("failed to unlink system tty action", "user_id", user.ID, "error", err)
		}
	}
	return nil
}

func (m *SystemActionManager) syncUserProvisionAction(ctx context.Context, user db.UsersProjection, sshKeys []string) error {
	comment := user.DisplayName
	if comment == "" {
		comment = user.Email
	}

	params := map[string]any{
		"username":   user.LinuxUsername,
		"uid":        user.LinuxUid,
		"createHome": true,
		"comment":    comment,
	}
	if len(sshKeys) > 0 {
		params["sshAuthorizedKeys"] = sshKeys
	}
	if user.Disabled {
		params["disabled"] = true
	}

	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("marshal user params: %w", err)
	}

	actionName := "system:user-provision:" + user.ID

	if user.SystemUserActionID == "" {
		// Create new system action
		actionID, err := m.createSystemAction(ctx, actionName, int32(pm.ActionType_ACTION_TYPE_USER), int32(pm.DesiredState_DESIRED_STATE_PRESENT), paramsJSON)
		if err != nil {
			return fmt.Errorf("create user provision action: %w", err)
		}

		if err := m.assignActionToUser(ctx, actionID, user.ID); err != nil {
			return fmt.Errorf("assign user provision action: %w", err)
		}

		if err := m.linkSystemAction(ctx, user.ID, "system_user_action_id", actionID); err != nil {
			return fmt.Errorf("link user provision action: %w", err)
		}

		m.signActionByID(ctx, actionID)
		m.logger.Info("created system user provision action", "user_id", user.ID, "action_id", actionID)
	} else {
		// Update existing action if params changed
		if err := m.updateSystemAction(ctx, user.SystemUserActionID, int32(pm.DesiredState_DESIRED_STATE_PRESENT), paramsJSON); err != nil {
			return fmt.Errorf("update user provision action: %w", err)
		}
		m.signActionByID(ctx, user.SystemUserActionID)
	}

	return nil
}

func (m *SystemActionManager) syncSshAccessAction(ctx context.Context, user db.UsersProjection) error {
	params := map[string]any{
		"users":         []string{user.LinuxUsername},
		"allowPubkey":   user.SshAllowPubkey,
		"allowPassword": user.SshAllowPassword,
	}

	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("marshal ssh params: %w", err)
	}

	actionName := "system:ssh-access:" + user.ID

	if user.SystemSshActionID == "" {
		// Create new system action
		actionID, err := m.createSystemAction(ctx, actionName, int32(pm.ActionType_ACTION_TYPE_SSH), int32(pm.DesiredState_DESIRED_STATE_PRESENT), paramsJSON)
		if err != nil {
			return fmt.Errorf("create ssh access action: %w", err)
		}

		if err := m.assignActionToUser(ctx, actionID, user.ID); err != nil {
			return fmt.Errorf("assign ssh access action: %w", err)
		}

		if err := m.linkSystemAction(ctx, user.ID, "system_ssh_action_id", actionID); err != nil {
			return fmt.Errorf("link ssh access action: %w", err)
		}

		m.signActionByID(ctx, actionID)
		m.logger.Info("created system ssh access action", "user_id", user.ID, "action_id", actionID)
	} else {
		// Update existing action
		if err := m.updateSystemAction(ctx, user.SystemSshActionID, int32(pm.DesiredState_DESIRED_STATE_PRESENT), paramsJSON); err != nil {
			return fmt.Errorf("update ssh access action: %w", err)
		}
		m.signActionByID(ctx, user.SystemSshActionID)
	}

	return nil
}

func (m *SystemActionManager) cleanupUserAction(ctx context.Context, user db.UsersProjection) error {
	if user.SystemUserActionID == "" {
		return nil
	}
	if err := m.deleteSystemAction(ctx, user.SystemUserActionID); err != nil {
		m.logger.Error("failed to delete system user action", "action_id", user.SystemUserActionID, "error", err)
	}
	if err := m.linkSystemAction(ctx, user.ID, "system_user_action_id", ""); err != nil {
		m.logger.Error("failed to unlink system user action", "user_id", user.ID, "error", err)
	}
	m.logger.Info("cleaned up system user provision action", "user_id", user.ID)
	return nil
}

func (m *SystemActionManager) cleanupSshAction(ctx context.Context, user db.UsersProjection) error {
	if user.SystemSshActionID == "" {
		return nil
	}
	if err := m.deleteSystemAction(ctx, user.SystemSshActionID); err != nil {
		m.logger.Error("failed to delete system ssh action", "action_id", user.SystemSshActionID, "error", err)
	}
	if err := m.linkSystemAction(ctx, user.ID, "system_ssh_action_id", ""); err != nil {
		m.logger.Error("failed to unlink system ssh action", "user_id", user.ID, "error", err)
	}
	m.logger.Info("cleaned up system ssh access action", "user_id", user.ID)
	return nil
}

// syncTtyUserAction ensures a dedicated pm-tty-<linux_username>
// system User action exists for the given user so that when the
// action is resolved onto the user's assigned devices the agent
// creates the TTY account. The action uses nologin as the shell
// (the agent temporarily activates it during a session), no home
// directory, and the deterministic UID from the SDK's TTYUID helper.
func (m *SystemActionManager) syncTtyUserAction(ctx context.Context, user db.UsersProjection) error {
	ttyUsername := "pm-tty-" + user.LinuxUsername
	ttyUID := int(user.LinuxUid) + 100000 // terminal.DefaultUIDOffset

	params := map[string]any{
		"username":   ttyUsername,
		"uid":        ttyUID,
		"shell":      "/usr/sbin/nologin",
		"createHome": false,
		"comment":    "Power Manage terminal user for " + user.LinuxUsername,
		// AccountsService SystemAccount=true → hidden from login screens
		// (GDM/SDDM/LightDM). The proto field is UserParams.hidden with
		// protojson camelCase "hidden"; an earlier revision passed
		// "system": true which does not map to any proto field and so
		// was silently dropped by protojson, leaving pm-tty-* accounts
		// visible on login screens on every device they're assigned to.
		//
		// system_user is deliberately NOT set here. It would imply the
		// useradd --system flag (UID < 1000, no home by default); pm-tty
		// accounts use UID = <base>+100000 which is not a system UID and
		// the semantics would be wrong.
		"hidden": true,
	}
	if user.Disabled {
		params["disabled"] = true
	}

	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("marshal tty user params: %w", err)
	}

	actionName := "system:tty-user:" + user.ID

	if user.SystemTtyActionID == "" {
		// Create new system action
		actionID, err := m.createSystemAction(ctx, actionName, int32(pm.ActionType_ACTION_TYPE_USER), int32(pm.DesiredState_DESIRED_STATE_PRESENT), paramsJSON)
		if err != nil {
			return fmt.Errorf("create tty user action: %w", err)
		}

		if err := m.assignActionToUser(ctx, actionID, user.ID); err != nil {
			return fmt.Errorf("assign tty user action: %w", err)
		}

		if err := m.linkSystemAction(ctx, user.ID, "system_tty_action_id", actionID); err != nil {
			return fmt.Errorf("link tty user action: %w", err)
		}

		m.signActionByID(ctx, actionID)
		m.logger.Info("created system tty user action",
			"user_id", user.ID, "action_id", actionID, "tty_user", ttyUsername)
	} else {
		// Update existing action if params changed
		if err := m.updateSystemAction(ctx, user.SystemTtyActionID, int32(pm.DesiredState_DESIRED_STATE_PRESENT), paramsJSON); err != nil {
			return fmt.Errorf("update tty user action: %w", err)
		}
		m.signActionByID(ctx, user.SystemTtyActionID)
	}

	return nil
}

func (m *SystemActionManager) cleanupTtyAction(ctx context.Context, user db.UsersProjection) error {
	if user.SystemTtyActionID == "" {
		return nil
	}
	if err := m.deleteSystemAction(ctx, user.SystemTtyActionID); err != nil {
		m.logger.Error("failed to delete system tty action", "action_id", user.SystemTtyActionID, "error", err)
	}
	if err := m.linkSystemAction(ctx, user.ID, "system_tty_action_id", ""); err != nil {
		m.logger.Error("failed to unlink system tty action", "user_id", user.ID, "error", err)
	}
	m.logger.Info("cleaned up system tty user action", "user_id", user.ID)
	return nil
}

// createSystemAction emits an ActionCreated event with is_system=true.
func (m *SystemActionManager) createSystemAction(ctx context.Context, name string, actionType, desiredState int32, paramsJSON []byte) (string, error) {
	id := newULID()

	var params map[string]any
	if err := json.Unmarshal(paramsJSON, &params); err != nil {
		return "", fmt.Errorf("unmarshal params: %w", err)
	}

	if err := m.store.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   id,
		EventType:  "ActionCreated",
		Data: map[string]any{
			"name":            name,
			"description":     "System-managed action",
			"action_type":     actionType,
			"desired_state":   desiredState,
			"params":          params,
			"timeout_seconds": 300,
			"is_system":       true,
		},
		ActorType: "system",
		ActorID:   "system",
	}); err != nil {
		return "", fmt.Errorf("append ActionCreated: %w", err)
	}

	return id, nil
}

// assignActionToUser emits an AssignmentCreated event.
func (m *SystemActionManager) assignActionToUser(ctx context.Context, actionID, userID string) error {
	assignmentID := newULID()

	return m.store.AppendEvent(ctx, store.Event{
		StreamType: "assignment",
		StreamID:   assignmentID,
		EventType:  "AssignmentCreated",
		Data: map[string]any{
			"source_type": "action",
			"source_id":   actionID,
			"target_type": "user",
			"target_id":   userID,
			"mode":        0, // REQUIRED
			"sort_order":  0,
		},
		ActorType: "system",
		ActorID:   "system",
	})
}

// updateSystemAction emits an ActionParamsUpdated event.
func (m *SystemActionManager) updateSystemAction(ctx context.Context, actionID string, desiredState int32, paramsJSON []byte) error {
	var params map[string]any
	if err := json.Unmarshal(paramsJSON, &params); err != nil {
		return fmt.Errorf("unmarshal params: %w", err)
	}

	return m.store.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   actionID,
		EventType:  "ActionParamsUpdated",
		Data: map[string]any{
			"params":        params,
			"desired_state": desiredState,
		},
		ActorType: "system",
		ActorID:   "system",
	})
}

// deleteSystemAction emits an ActionDeleted event.
func (m *SystemActionManager) deleteSystemAction(ctx context.Context, actionID string) error {
	return m.store.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   actionID,
		EventType:  "ActionDeleted",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "system",
	})
}

// linkSystemAction emits a UserSystemActionLinked event to record the
// system action ID on the user projection.
func (m *SystemActionManager) linkSystemAction(ctx context.Context, userID, field, actionID string) error {
	return m.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  "UserSystemActionLinked",
		Data: map[string]any{
			"field":     field,
			"action_id": actionID,
		},
		ActorType: "system",
		ActorID:   "system",
	})
}

// signActionByID loads an action from the DB and signs it.
func (m *SystemActionManager) signActionByID(ctx context.Context, actionID string) {
	if m.signer == nil {
		return
	}

	action, err := m.store.Queries().GetActionByID(ctx, actionID)
	if err != nil {
		m.logger.Error("failed to load action for signing", "action_id", actionID, "error", err)
		return
	}

	paramsJSON := action.Params
	if paramsJSON == nil {
		paramsJSON = []byte("{}")
	}

	sig, err := m.signer.Sign(action.ID, action.ActionType, paramsJSON)
	if err != nil {
		m.logger.Error("failed to sign system action", "action_id", actionID, "error", err)
		return
	}

	if err := m.store.Queries().UpdateActionSignature(ctx, db.UpdateActionSignatureParams{
		ID:              action.ID,
		Signature:       sig,
		ParamsCanonical: paramsJSON,
	}); err != nil {
		m.logger.Error("failed to store system action signature", "action_id", actionID, "error", err)
	}
}

// parseSshPublicKeys extracts the public_key strings from the JSONB array.
func parseSshPublicKeys(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}

	var keys []struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil
	}

	result := make([]string, 0, len(keys))
	for _, k := range keys {
		if k.PublicKey != "" {
			result = append(result, k.PublicKey)
		}
	}
	return result
}
