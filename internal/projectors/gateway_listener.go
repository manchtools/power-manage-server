package projectors

import (
	"context"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/store"
)

// GatewayListener returns a store.EventListener that projects the gateway
// stream (spec 31). Every gateway event is a single guarded statement, so it
// runs on the autocommit pool. Post-commit errors are logged-and-swallowed,
// matching the other Go projectors; the periodic rebuild re-converges.
func GatewayListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "gateway" {
			return
		}
		if err := ApplyGateway(ctx, st.Queries(), e); err != nil {
			logger.Warn("gateway projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "gateway_id", e.StreamID, "error", err)
		}
	}
}
