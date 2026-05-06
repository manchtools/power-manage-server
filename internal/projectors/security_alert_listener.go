package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/store"
)

// SecurityAlertListener returns a store.EventListener that applies
// SecurityAlert / SecurityAlertAcknowledged events to the
// security_alerts_projection.
//
// Wired into the store at boot in cmd/control/main.go:
//
//	st.RegisterEventListener(projectors.SecurityAlertListener(st, logger))
//
// Replaces the (now-deleted) PL/pgSQL `project_security_alert_event`
// function and its sidecar `project_security_alert_trigger`. The
// trigger ran inside the AppendEvent transaction, so projection
// writes were synchronous with the event commit. This listener is
// post-commit, so the projection write is async — but no consumer
// of security_alerts_projection relies on read-your-writes after a
// SecurityAlert append. The original emitter (control InboxWorker
// processing an Asynq task) doesn't return data to a synchronous
// caller, and no API handler reads back the row immediately after
// emitting the event.
//
// Errors are logged and swallowed (post-commit notification
// contract). The 1h periodic indexer reconciler is the safety net
// for any write that drops on the floor — bounded drift, not silent
// data loss. The InsertSecurityAlertProjection query is idempotent
// via ON CONFLICT (event_id) DO NOTHING, so a re-fire on crash
// recovery is safe.
//
// Refs #96, tracker #107.
func SecurityAlertListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		// Match the SearchListener factory contract: never return
		// nil — handlers should not have to nil-guard registration.
		return func(context.Context, store.PersistedEvent) {}
	}

	return func(ctx context.Context, e store.PersistedEvent) {
		// Filter at the top so we don't pay the projector function
		// call cost for every event flowing through the store.
		if e.StreamType != "device" {
			return
		}
		switch e.EventType {
		case "SecurityAlert":
			params, err := SecurityAlertProjectionFromEvent(e)
			if err != nil {
				if errors.Is(err, ErrIgnoredEvent) {
					return
				}
				logger.Warn("security_alert projector: failed to derive insert params",
					"event_id", e.ID, "error", err)
				return
			}
			if err := st.Queries().InsertSecurityAlertProjection(ctx, params); err != nil {
				logger.Warn("security_alert projector: failed to insert projection row",
					"event_id", e.ID, "device_id", e.StreamID, "error", err)
			}

		case "SecurityAlertAcknowledged":
			params, err := SecurityAlertAckParamsFromEvent(e)
			if err != nil {
				if errors.Is(err, ErrIgnoredEvent) {
					return
				}
				// Malformed alert_id — log and skip. The deleted
				// PL/pgSQL projector raised an EXCEPTION in this
				// case so a sidecar trigger could catch it and
				// write to plpgsql_projection_errors. Post-commit
				// listener equivalent: log to stderr via slog.Warn
				// so the operator sees it and can correlate with
				// the event.
				logger.Warn("security_alert projector: invalid SecurityAlertAcknowledged payload",
					"event_id", e.ID, "error", err)
				return
			}
			rows, err := st.Queries().AcknowledgeSecurityAlertProjection(ctx, params)
			if err != nil {
				logger.Warn("security_alert projector: failed to acknowledge alert",
					"event_id", e.ID, "alert_id", params.Column1, "error", err)
				return
			}
			if rows == 0 {
				// Out-of-order replay (ack arrived before the
				// alert insert reached the projection) or an alert
				// that's been purged. Same warning the deleted
				// PL/pgSQL projector raised.
				logger.Warn("security_alert projector: SecurityAlertAcknowledged references unknown alert_id",
					"event_id", e.ID, "alert_id", params.Column1)
			}
		}
	}
}
