package projectors

import (
	"context"
	"errors"
	"log/slog"

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
func SCIMGroupMappingListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "scim_group_mapping" {
			return
		}
		switch e.EventType {
		case "SCIMGroupMapped":
			applySCIMGroupMapped(ctx, st, logger, e)
		case "SCIMGroupUnmapped":
			applySCIMGroupUnmapped(ctx, st, logger, e)
		case "SCIMGroupMappingUpdated":
			applySCIMGroupMappingUpdated(ctx, st, logger, e)
		}
	}
}

func applySCIMGroupMapped(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	payload, err := SCIMGroupMappedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return
		}
		logger.Warn("scim_group_mapping projector: invalid SCIMGroupMapped payload",
			"event_id", e.ID, "error", err)
		return
	}
	if err := st.Queries().UpsertSCIMGroupMapping(ctx, db.UpsertSCIMGroupMappingParams{
		ID:                payload.ID,
		ProviderID:        payload.ProviderID,
		ScimGroupID:       payload.SCIMGroupID,
		ScimDisplayName:   payload.SCIMDisplayName,
		UserGroupID:       payload.UserGroupID,
		CreatedAt:         e.OccurredAt,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		logger.Warn("scim_group_mapping projector: failed to upsert SCIMGroupMapped",
			"event_id", e.ID, "mapping_id", payload.ID, "error", err)
	}
}

func applySCIMGroupUnmapped(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	payload, err := SCIMGroupUnmappedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return
		}
		logger.Warn("scim_group_mapping projector: invalid SCIMGroupUnmapped payload",
			"event_id", e.ID, "error", err)
		return
	}
	if err := st.Queries().DeleteSCIMGroupMappingByCompositeKey(ctx, db.DeleteSCIMGroupMappingByCompositeKeyParams{
		ProviderID:  payload.ProviderID,
		ScimGroupID: payload.SCIMGroupID,
	}); err != nil {
		logger.Warn("scim_group_mapping projector: failed to delete SCIMGroupUnmapped",
			"event_id", e.ID,
			"provider_id", payload.ProviderID,
			"scim_group_id", payload.SCIMGroupID,
			"error", err)
	}
}

func applySCIMGroupMappingUpdated(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	payload, err := SCIMGroupMappingUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return
		}
		logger.Warn("scim_group_mapping projector: invalid SCIMGroupMappingUpdated payload",
			"event_id", e.ID, "error", err)
		return
	}
	if err := st.Queries().UpdateSCIMGroupMappingDisplayName(ctx, db.UpdateSCIMGroupMappingDisplayNameParams{
		ProviderID:        payload.ProviderID,
		ScimGroupID:       payload.SCIMGroupID,
		ScimDisplayName:   payload.SCIMDisplayName,
		ProjectionVersion: deref(e.SequenceNum),
	}); err != nil {
		logger.Warn("scim_group_mapping projector: failed to apply SCIMGroupMappingUpdated",
			"event_id", e.ID,
			"provider_id", payload.ProviderID,
			"scim_group_id", payload.SCIMGroupID,
			"error", err)
	}
}
