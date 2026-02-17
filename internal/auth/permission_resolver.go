package auth

import (
	"context"
	"sync"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// PermissionQuerier is the interface needed by PermissionResolver.
type PermissionQuerier interface {
	GetUserPermissions(ctx context.Context, userID string) ([]string, error)
}

// PermissionResolver loads and caches user permissions from their assigned roles.
type PermissionResolver struct {
	querier PermissionQuerier
	mu      sync.RWMutex
	cache   map[string]*cachedPerms
}

type cachedPerms struct {
	permissions map[string]bool
	version     int32
}

// NewPermissionResolver creates a new resolver.
func NewPermissionResolver(querier PermissionQuerier) *PermissionResolver {
	return &PermissionResolver{
		querier: querier,
		cache:   make(map[string]*cachedPerms),
	}
}

// UserPermissions returns the user's effective permissions.
// It uses a version-based cache: if sessionVersion matches the cached version, return cached result.
// Otherwise reload from the database.
func (r *PermissionResolver) UserPermissions(ctx context.Context, userID string, sessionVersion int32) ([]string, error) {
	r.mu.RLock()
	if cached, ok := r.cache[userID]; ok && cached.version == sessionVersion {
		perms := make([]string, 0, len(cached.permissions))
		for p := range cached.permissions {
			perms = append(perms, p)
		}
		r.mu.RUnlock()
		return perms, nil
	}
	r.mu.RUnlock()

	// Cache miss or version mismatch — reload from DB
	permList, err := r.querier.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, err
	}

	permSet := make(map[string]bool, len(permList))
	for _, p := range permList {
		permSet[p] = true
	}

	r.mu.Lock()
	r.cache[userID] = &cachedPerms{
		permissions: permSet,
		version:     sessionVersion,
	}
	r.mu.Unlock()

	return permList, nil
}

// InvalidateUser removes a user's cached permissions.
func (r *PermissionResolver) InvalidateUser(userID string) {
	r.mu.Lock()
	delete(r.cache, userID)
	r.mu.Unlock()
}

// queriesAdapter adapts generated.Queries to PermissionQuerier.
type queriesAdapter struct {
	q *generated.Queries
}

// NewQueriesAdapter creates a PermissionQuerier from sqlc-generated Queries.
func NewQueriesAdapter(q *generated.Queries) PermissionQuerier {
	return &queriesAdapter{q: q}
}

func (a *queriesAdapter) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	return a.q.GetUserPermissions(ctx, userID)
}
