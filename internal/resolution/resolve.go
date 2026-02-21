package resolution

import (
	"context"

	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// Querier defines the queries needed for action resolution.
type Querier interface {
	ListResolvedActionsForDevice(ctx context.Context, targetID string) ([]db.ListResolvedActionsForDeviceRow, error)
	ListDeviceLayerExcludedActionIDs(ctx context.Context, targetID string) ([]string, error)
	ListUserLayerResolvedActionsForDevice(ctx context.Context, id string) ([]db.ListUserLayerResolvedActionsForDeviceRow, error)
}

// ResolveActionsForDevice queries both device-layer and user-layer assignments,
// merges them with cross-layer exclusion rules, and returns the final action list.
//
// Cross-layer exclusion rules:
//   - Device EXCLUDED → blocks action entirely (not returned from either layer)
//   - User EXCLUDED → only removes from user layer, device layer unaffected
//   - Same action in both layers → device layer wins (no duplicates)
func ResolveActionsForDevice(ctx context.Context, q Querier, deviceID string) ([]db.ListResolvedActionsForDeviceRow, error) {
	// 1. Get device-layer resolved actions (existing query, unchanged)
	deviceActions, err := q.ListResolvedActionsForDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	// 2. Get user-layer resolved actions (returns empty if device has no owner)
	userActions, err := q.ListUserLayerResolvedActionsForDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	// If no user-layer actions, return device layer only (fast path)
	if len(userActions) == 0 {
		return deviceActions, nil
	}

	// 3. Get device-layer excluded action IDs
	excludedIDs, err := q.ListDeviceLayerExcludedActionIDs(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	// Build lookup sets
	excludedSet := make(map[string]bool, len(excludedIDs))
	for _, id := range excludedIDs {
		excludedSet[id] = true
	}

	deviceActionSet := make(map[string]bool, len(deviceActions))
	for _, a := range deviceActions {
		deviceActionSet[a.ID] = true
	}

	// 4. Merge: add user-layer actions that aren't device-excluded or duplicates
	for _, ua := range userActions {
		if excludedSet[ua.ID] || deviceActionSet[ua.ID] {
			continue
		}
		deviceActions = append(deviceActions, db.ListResolvedActionsForDeviceRow{
			ID:                ua.ID,
			Name:              ua.Name,
			Description:       ua.Description,
			ActionType:        ua.ActionType,
			DesiredState:      ua.DesiredState,
			Params:            ua.Params,
			TimeoutSeconds:    ua.TimeoutSeconds,
			CreatedAt:         ua.CreatedAt,
			CreatedBy:         ua.CreatedBy,
			IsDeleted:         ua.IsDeleted,
			ProjectionVersion: ua.ProjectionVersion,
			Signature:         ua.Signature,
			ParamsCanonical:   ua.ParamsCanonical,
		})
		deviceActionSet[ua.ID] = true
	}

	return deviceActions, nil
}
