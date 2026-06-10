package api

import (
	"context"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
)

// storeScopeResolver implements auth.ScopeResolver over the device-group
// and user-group membership projections. The auth package stays
// store-independent (it only knows the interface); the concrete resolver
// lives here and is handed to the Enforce* helpers by the handlers (#7).
type storeScopeResolver struct {
	store *store.Store
}

// newScopeResolver builds the projection-backed scope resolver.
func newScopeResolver(st *store.Store) auth.ScopeResolver {
	return storeScopeResolver{store: st}
}

// DeviceGroupsForDevice returns the ids of every device group the device
// belongs to (static + dynamic-materialized).
func (r storeScopeResolver) DeviceGroupsForDevice(ctx context.Context, deviceID string) ([]string, error) {
	groups, err := r.store.Repos().DeviceGroup.ListForDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(groups))
	for i, g := range groups {
		ids[i] = g.ID
	}
	return ids, nil
}

// UserGroupsForUser returns the ids of every user group the user belongs to.
func (r storeScopeResolver) UserGroupsForUser(ctx context.Context, userID string) ([]string, error) {
	groups, err := r.store.Repos().UserGroup.ListForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(groups))
	for i, g := range groups {
		ids[i] = g.ID
	}
	return ids, nil
}
