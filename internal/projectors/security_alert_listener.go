package projectors

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
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
// Live dispatch wraps ApplySecurityAlert and logs-and-swallows; the
// rebuild path (#497) registers ApplySecurityAlert via
// RegisterRebuildApply so RebuildAll re-derives the projection from the
// event store.
//
// Refs #96, tracker #107, #497.
func SecurityAlertListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		// Match the SearchListener factory contract: never return
		// nil — handlers should not have to nil-guard registration.
		return func(context.Context, store.PersistedEvent) {}
	}

	return func(ctx context.Context, e store.PersistedEvent) {
		if err := ApplySecurityAlert(ctx, st.Queries(), e); err != nil {
			logger.Warn("security_alert projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "error", err)
		}
	}
}

// ApplySecurityAlert is the transactional core of the security_alert
// projector: it writes through the supplied Queries (the rebuild tx or
// the live autocommit handle) and RETURNS errors instead of
// logging-and-swallowing, so a rebuild fails loudly rather than
// producing a partial projection.
//
// The stream guard filters on "device" (security alerts ride the device
// stream), not "security_alert".
func ApplySecurityAlert(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	// Filter at the top so we don't pay the projector function
	// call cost for every event flowing through the store.
	if e.StreamType != "device" {
		return nil
	}
	switch e.EventType {
	case string(eventtypes.SecurityAlert):
		params, err := SecurityAlertProjectionFromEvent(e)
		if err != nil {
			if errors.Is(err, ErrIgnoredEvent) {
				return nil
			}
			return err
		}
		return q.InsertSecurityAlertProjection(ctx, params)

	case string(eventtypes.SecurityAlertAcknowledged):
		params, err := SecurityAlertAckParamsFromEvent(e)
		if err != nil {
			if errors.Is(err, ErrIgnoredEvent) {
				return nil
			}
			// Malformed alert_id — the deleted PL/pgSQL projector
			// raised an EXCEPTION here; the live listener logged and
			// skipped. Report it as skippable: the live listener
			// logs-and-swallows (restoring the lost log line), and
			// RebuildAll skips-and-continues instead of aborting on one
			// bad historical row.
			return fmt.Errorf("security_alert projector: malformed SecurityAlertAcknowledged %s: %w: %w",
				e.ID, err, store.ErrSkipEvent)
		}
		rows, err := q.AcknowledgeSecurityAlertProjection(ctx, params)
		if err != nil {
			return err
		}
		if rows == 0 {
			// Out-of-order replay (ack arrived before the alert
			// insert reached the projection) or an alert that's been
			// purged. Non-fatal — nothing to acknowledge, so nothing
			// to do. The live listener logged a warning here; during
			// rebuild the ordering is stable so this is a benign
			// no-op.
			return nil
		}
		return nil
	}
	return nil
}
