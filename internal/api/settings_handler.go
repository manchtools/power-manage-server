package api

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/store"
)

// SettingsHandler handles server settings RPCs.
type SettingsHandler struct {
	store         *store.Store
	logger        *slog.Logger
	systemActions *SystemActionManager
}

// NewSettingsHandler creates a new settings handler.
func NewSettingsHandler(st *store.Store, logger *slog.Logger, systemActions *SystemActionManager) *SettingsHandler {
	return &SettingsHandler{
		store:         st,
		logger:        logger.With("component", "settings_handler"),
		systemActions: systemActions,
	}
}

// GetServerSettings returns the current server settings.
func (h *SettingsHandler) GetServerSettings(ctx context.Context, req *connect.Request[pm.GetServerSettingsRequest]) (*connect.Response[pm.GetServerSettingsResponse], error) {
	settings, err := h.store.Queries().GetServerSettings(ctx)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get server settings")
	}

	return connect.NewResponse(&pm.GetServerSettingsResponse{
		Settings: &pm.ServerSettings{
			UserProvisioningEnabled: settings.UserProvisioningEnabled,
			SshAccessForAll:         settings.SshAccessForAll,
			AutoUpdateAgents:        settings.AutoUpdateAgents,
		},
	}), nil
}

// UpdateServerSettings updates global server settings and triggers a full resync.
func (h *SettingsHandler) UpdateServerSettings(ctx context.Context, req *connect.Request[pm.UpdateServerSettingsRequest]) (*connect.Response[pm.UpdateServerSettingsResponse], error) {
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "server_settings",
		StreamID:   "global",
		EventType:  "ServerSettingUpdated",
		Data: map[string]any{
			"user_provisioning_enabled": req.Msg.UserProvisioningEnabled,
			"ssh_access_for_all":        req.Msg.SshAccessForAll,
			"auto_update_agents":        req.Msg.AutoUpdateAgents,
		},
		ActorType: "system",
		ActorID:   "system",
	}); err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update server settings")
	}

	// Read back from projection
	settings, err := h.store.Queries().GetServerSettings(ctx)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to read server settings")
	}

	// Propagate global flags to individual users when enabled.
	// This makes the global toggle a "batch enable" — once set per user,
	// turning off the global flag won't remove provisioning for existing users.
	go func() {
		bgCtx := context.Background()
		if req.Msg.UserProvisioningEnabled {
			if err := h.enableProvisioningForAllUsers(bgCtx); err != nil {
				h.logger.Error("failed to propagate provisioning to users", "error", err)
			}
		}
		if req.Msg.SshAccessForAll {
			if err := h.enableSshAccessForAllUsers(bgCtx); err != nil {
				h.logger.Error("failed to propagate SSH access to users", "error", err)
			}
		}
		if err := h.systemActions.SyncAllUsersSystemActions(bgCtx); err != nil {
			h.logger.Error("failed to sync system actions after settings update", "error", err)
		}
	}()

	return connect.NewResponse(&pm.UpdateServerSettingsResponse{
		Settings: &pm.ServerSettings{
			UserProvisioningEnabled: settings.UserProvisioningEnabled,
			SshAccessForAll:         settings.SshAccessForAll,
			AutoUpdateAgents:        settings.AutoUpdateAgents,
		},
	}), nil
}

// enableProvisioningForAllUsers sets user_provisioning_enabled=true on every user
// that doesn't already have it enabled.
func (h *SettingsHandler) enableProvisioningForAllUsers(ctx context.Context) error {
	users, err := h.store.Queries().ListAllNonDeletedUsers(ctx)
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}
	var errCount int
	for _, u := range users {
		if u.UserProvisioningEnabled {
			continue
		}
		if err := h.store.AppendEvent(ctx, store.Event{
			StreamType: "user",
			StreamID:   u.ID,
			EventType:  "UserProvisioningSettingsUpdated",
			Data:       map[string]any{"user_provisioning_enabled": true},
			ActorType:  "system",
			ActorID:    "system",
		}); err != nil {
			h.logger.Error("failed to enable provisioning for user", "user_id", u.ID, "error", err)
			errCount++
		}
	}
	if errCount > 0 {
		return fmt.Errorf("failed to enable provisioning for %d users", errCount)
	}
	h.logger.Info("enabled provisioning for all users", "count", len(users))
	return nil
}

// enableSshAccessForAllUsers sets ssh_access_enabled=true on every user
// that doesn't already have it enabled.
func (h *SettingsHandler) enableSshAccessForAllUsers(ctx context.Context) error {
	users, err := h.store.Queries().ListAllNonDeletedUsers(ctx)
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}
	var errCount int
	for _, u := range users {
		if u.SshAccessEnabled {
			continue
		}
		if err := h.store.AppendEvent(ctx, store.Event{
			StreamType: "user",
			StreamID:   u.ID,
			EventType:  "UserSshSettingsUpdated",
			Data: map[string]any{
				"ssh_access_enabled": true,
				"ssh_allow_pubkey":   u.SshAllowPubkey,
				"ssh_allow_password": u.SshAllowPassword,
			},
			ActorType: "system",
			ActorID:   "system",
		}); err != nil {
			h.logger.Error("failed to enable SSH access for user", "user_id", u.ID, "error", err)
			errCount++
		}
	}
	if errCount > 0 {
		return fmt.Errorf("failed to enable SSH access for %d users", errCount)
	}
	h.logger.Info("enabled SSH access for all users", "count", len(users))
	return nil
}
