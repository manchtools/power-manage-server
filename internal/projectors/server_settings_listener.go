package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/store"
)

// ServerSettingsListener returns a store.EventListener that applies
// ServerSettingUpdated events to the singleton
// server_settings_projection row. Replaces the deleted PL/pgSQL
// project_server_settings_event function.
//
// Single event type, single UPDATE — no transaction wrap needed.
// COALESCE preserves columns the payload omitted; the
// `WHERE projection_version < $N` guard protects against stale
// reconciler replays.
//
// Wired in projectors.WireAll. Refs #100, tracker #107.
func ServerSettingsListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "server_settings" {
			return
		}
		if e.EventType != "ServerSettingUpdated" {
			return
		}

		payload, err := ServerSettingsUpdatedFromEvent(e)
		if err != nil {
			if errors.Is(err, ErrIgnoredEvent) {
				return
			}
			logger.Warn("server_settings projector: invalid ServerSettingUpdated payload",
				"event_id", e.ID, "error", err)
			return
		}

		if err := ApplyServerSettingsUpdate(ctx, st, ServerSettingsUpdate{
			UserProvisioningEnabled: payload.UserProvisioningEnabled,
			SshAccessForAll:         payload.SshAccessForAll,
			OccurredAt:              e.OccurredAt,
			ProjectionVersion:       deref(e.SequenceNum),
		}); err != nil {
			logger.Warn("server_settings projector: failed to apply ServerSettingUpdated",
				"event_id", e.ID, "error", err)
		}
	}
}
