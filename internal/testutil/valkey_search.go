package testutil

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
)

// SetupValkeySearch starts a valkey-bundle container (the valkey-search module
// auto-loads), builds a *search.Index over st, and creates the FT indexes. It
// returns the Index for a handler's SetSearchIndex + behavioral scope tests
// against a REAL search backend.
//
// This is the load-bearing infra for spec 29 S1 / spec 30: FT.SEARCH scope
// filtering (@scope_group_ids) can only be verified BEHAVIORALLY against a real
// index — the in-memory api.SearchIndex fake and the clause-string unit tests
// prove construction, not confinement (the presence-not-behavior gap that let
// ListActions leak). Seed objects + assignments in Postgres, call
// idx.Rebuild(ctx) to backfill, then drive the real handler with a
// scope-restricted caller and assert the out-of-scope object is absent.
//
// The container is torn down on test cleanup. Skipped in -short mode. Mirrors
// the search package's own setupRedis (image + wait strategy kept identical so a
// clean run validates the same cutover, #319).
func SetupValkeySearch(t *testing.T, st *store.Store) *search.Index {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping valkey-search integration test in short mode")
	}
	ctx := context.Background()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "valkey/valkey-bundle:9.1.0",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err, "start valkey-bundle container")
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "6379")
	require.NoError(t, err)

	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", host, port.Port()),
		Protocol: 2,
	})
	t.Cleanup(func() { _ = rdb.Close() })

	idx := search.New(rdb, st, nil, slog.Default())
	require.NoError(t, idx.EnsureIndexes(ctx), "create FT indexes")
	return idx
}
