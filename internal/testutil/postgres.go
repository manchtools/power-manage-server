package testutil

// Postgres testcontainer setup. Production-parity bits (image tag,
// wait strategy, cleanup hooks) live here exactly once so the two
// public helpers cannot drift — e.g. an image bump applies uniformly.
//
// SetupPostgres also wires the same Go-side projector listeners that
// production boot wires in cmd/control/main.go. Tests that read
// projection state after AppendEvent need this; SetupPostgresWithoutProjectors
// exists only for the narrow case of testing rebuild-applier guards
// that depend on the listener pipeline being unwired.

import (
	"context"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	pgrepo "github.com/manchtools/power-manage/server/internal/store/postgres"
)

// setupPostgresContainer is the shared bootstrap used by both public
// helpers. Returns the connected Store; callers decide whether to
// wire projectors.
func setupPostgresContainer(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:17-alpine",
		postgres.WithDatabase("power_manage_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() {
		// Bound the teardown so a wedged Docker daemon cannot hang
		// the cleanup goroutine indefinitely and stall the rest of
		// the suite.
		termCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := container.Terminate(termCtx); err != nil {
			// Log without failing the test — the test result is
			// already finalized at cleanup time. Surfacing the error
			// gives operators a chance to spot leaked containers or
			// flaky Docker teardown.
			t.Logf("testutil: terminate postgres container: %v", err)
		}
	})

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("get connection string: %v", err)
	}

	st, err := store.New(ctx, connStr)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	st.SetRepos(pgrepo.NewRepos(st.Queries()))
	return st
}

// SetupPostgres starts a PostgreSQL testcontainer and returns a connected Store.
// The container is stopped when the test completes.
func SetupPostgres(t *testing.T) *store.Store {
	t.Helper()
	st := setupPostgresContainer(t)

	// Wire the same Go-side projector listeners that production
	// boot wires in cmd/control/main.go. Without this, handlers
	// emit events but the projection writes never fire (the
	// PL/pgSQL projectors that the migrations have replaced with
	// no-op stubs no longer do anything either), so any test that
	// reads back projection state after AppendEvent silently sees
	// stale data.
	projectors.WireAll(st, nil)

	return st
}

// SetupPostgresWithoutProjectors is identical to SetupPostgres but
// skips projectors.WireAll. Used only to exercise failure modes
// that depend on the projector pipeline being unwired — e.g. the
// RebuildAll guard that fires when neither a Go applier nor a
// PL/pgSQL Function is set for a target.
//
// Production code paths must always call WireAll; never use this
// helper for tests that read projection state.
func SetupPostgresWithoutProjectors(t *testing.T) *store.Store {
	t.Helper()
	return setupPostgresContainer(t)
}
