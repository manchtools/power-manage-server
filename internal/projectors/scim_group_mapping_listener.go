package projectors

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// SCIMGroupMappingListener returns a store.EventListener that applies
// every scim_group_mapping stream event the deleted PL/pgSQL
// project_scim_group_mapping_event handled. Three event types, all
// single-statement:
//
//   - SCIMGroupMapped: UPSERT (replay-safe via ON CONFLICT)
//   - SCIMGroupUnmapped: DELETE WHERE (provider_id, scim_group_id)
//   - SCIMGroupMappingUpdated: UPDATE display_name with NULLIF/COALESCE
//
// Wired in projectors.WireAll. Refs #105, tracker #107.
//
// Listener body delegates to ApplySCIMGroupMapping so the rebuild
// path (RebuildAll) and the post-commit listener path share one
// codepath. Any new event type only needs to be added in one place.
func SCIMGroupMappingListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "scim_group_mapping" {
			return
		}
		if err := ApplySCIMGroupMapping(ctx, st.Queries(), e); err != nil {
			if errors.Is(err, ErrIgnoredEvent) {
				return
			}
			logger.Warn("scim_group_mapping projector: apply failed",
				"event_id", e.ID, "event_type", e.EventType, "error", err)
		}
	}
}

// ApplySCIMGroupMapping is the rebuild-applier-shape entry point.
// Dispatches to the per-event-type helpers (each a single SQL
// statement). RebuildAll registers this via
// projectors.WireAll → Store.RegisterRebuildApply("scim_group_mappings", ApplySCIMGroupMapping)
// so the new "scim_group_mappings" rebuild target replays the
// stream after the user_groups target has restored the FK references.
// See manchtools/power-manage-server#175.
func ApplySCIMGroupMapping(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "scim_group_mapping" {
		return nil
	}
	switch e.EventType {
	case string(eventtypes.SCIMGroupMapped):
		return applySCIMGroupMapped(ctx, q, e)
	case string(eventtypes.SCIMGroupUnmapped):
		return applySCIMGroupUnmapped(ctx, q, e)
	case string(eventtypes.SCIMGroupMappingUpdated):
		return applySCIMGroupMappingUpdated(ctx, q, e)
	}
	return nil
}

func applySCIMGroupMapped(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := SCIMGroupMappedFromEvent(e)
	if err != nil {
		return err
	}
	if err := q.UpsertSCIMGroupMapping(ctx, db.UpsertSCIMGroupMappingParams{
		ID:                payload.ID,
		ProviderID:        payload.ProviderID,
		ScimGroupID:       payload.SCIMGroupID,
		ScimDisplayName:   payload.SCIMDisplayName,
		UserGroupID:       payload.UserGroupID,
		CreatedAt:         e.OccurredAt,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		return fmt.Errorf("upsert scim_group_mapping (mapping_id %s): %w", payload.ID, err)
	}
	return nil
}

func applySCIMGroupUnmapped(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := SCIMGroupUnmappedFromEvent(e)
	if err != nil {
		return err
	}
	if err := q.DeleteSCIMGroupMappingByCompositeKey(ctx, db.DeleteSCIMGroupMappingByCompositeKeyParams{
		ProviderID:  payload.ProviderID,
		ScimGroupID: payload.SCIMGroupID,
	}); err != nil {
		return fmt.Errorf("delete scim_group_mapping (provider_id %s, scim_group_id %s): %w",
			payload.ProviderID, payload.SCIMGroupID, err)
	}
	return nil
}

func applySCIMGroupMappingUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := SCIMGroupMappingUpdatedFromEvent(e)
	if err != nil {
		return err
	}
	if err := q.UpdateSCIMGroupMappingDisplayName(ctx, db.UpdateSCIMGroupMappingDisplayNameParams{
		ProviderID:        payload.ProviderID,
		ScimGroupID:       payload.SCIMGroupID,
		ScimDisplayName:   payload.SCIMDisplayName,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		return fmt.Errorf("update scim_group_mapping display_name (provider_id %s, scim_group_id %s): %w",
			payload.ProviderID, payload.SCIMGroupID, err)
	}
	return nil
}
