package api

import (
	"context"
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
		return nil, apiError(ErrInternal, connect.CodeInternal, "failed to get server settings")
	}

	return connect.NewResponse(&pm.GetServerSettingsResponse{
		Settings: &pm.ServerSettings{
			UserProvisioningEnabled: settings.UserProvisioningEnabled,
			SshAccessForAll:         settings.SshAccessForAll,
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
		},
		ActorType: "system",
		ActorID:   "system",
	}); err != nil {
		return nil, apiError(ErrInternal, connect.CodeInternal, "failed to update server settings")
	}

	// Read back from projection
	settings, err := h.store.Queries().GetServerSettings(ctx)
	if err != nil {
		return nil, apiError(ErrInternal, connect.CodeInternal, "failed to read server settings")
	}

	// Trigger full system actions resync in background
	go func() {
		if err := h.systemActions.SyncAllUsersSystemActions(context.Background()); err != nil {
			h.logger.Error("failed to sync system actions after settings update", "error", err)
		}
	}()

	return connect.NewResponse(&pm.UpdateServerSettingsResponse{
		Settings: &pm.ServerSettings{
			UserProvisioningEnabled: settings.UserProvisioningEnabled,
			SshAccessForAll:         settings.SshAccessForAll,
		},
	}), nil
}
