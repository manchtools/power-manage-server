package testutil

// Postgres testcontainer setup. Production-parity bits (image tag,
// wait strategy) live here exactly once so the two public helpers cannot
// drift — e.g. an image bump applies uniformly.
//
// Container reuse (#338): historically every SetupPostgres call started its
// own Postgres container. With ~75 callers (one per integration test) that
// meant ~75 container boots per package, which pushed the suite toward the
// CI timeout AND exhausted the Ryuk reaper's tracked-resource budget when a
// package ran serially. Instead we now start ONE container per package test
// binary (lazy, via sync.Once) and hand each test its own freshly-cloned
// database, so isolation is identical (every test sees a pristine schema with
// no other test's data) while the expensive boot + migrate happens once.
//
// The mechanism is Postgres template databases: the shared container's
// default DB is migrated once and used as a CREATE DATABASE ... TEMPLATE
// source; each test clones it (a fast catalog copy, no migration re-run) into
// a uniquely-named database it owns and drops on cleanup.
//
// SetupPostgres also wires the same Go-side projector listeners that
// production boot wires in cmd/control/main.go. Tests that read projection
// state after AppendEvent need this; SetupPostgresWithoutProjectors exists
// only for the narrow case of testing rebuild-applier guards that depend on
// the listener pipeline being unwired.

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver for the maintenance conn
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	pgrepo "github.com/manchtools/power-manage/server/internal/store/postgres"
)

const (
	// templateDatabase is the container's default DB. It is migrated exactly
	// once and then used only as a CREATE DATABASE ... TEMPLATE source — no
	// test ever connects to it, which is what lets it stay clonable (Postgres
	// refuses to clone a template that has live connections).
	templateDatabase = "power_manage_test"
	// maintenanceDatabase is where CREATE/DROP DATABASE statements run from
	// (you cannot drop the database your own session is connected to).
	maintenanceDatabase = "postgres"
)

// sharedPG holds the per-package container state, initialised once.
type sharedPG struct {
	baseURL *url.URL // connection URL to the container; path (db name) is swapped per test
	admin   *sql.DB  // maintenance connection on maintenanceDatabase for CREATE/DROP DATABASE
}

var (
	sharedOnce sync.Once
	shared     *sharedPG
	sharedErr  error
	dbSeq      atomic.Uint64
	// createMu serialises CREATE/DROP DATABASE on the single shared admin
	// connection. Integration tests run serially today (no t.Parallel), so
	// this is defensive rather than load-bearing.
	createMu sync.Mutex
)

// initShared boots the one shared container, migrates the template database,
// and opens the maintenance connection. Runs exactly once per test binary.
func initShared() {
	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:17-alpine",
		postgres.WithDatabase(templateDatabase),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		sharedErr = fmt.Errorf("start shared postgres container: %w", err)
		return
	}
	// Intentionally NO container.Terminate hook: the container is shared for
	// the whole package test binary and reaped by the testcontainers Ryuk
	// sidecar when the test process exits. This is the core of the #338 fix —
	// one container (and one Ryuk-tracked resource) per package instead of one
	// per test.

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		sharedErr = fmt.Errorf("shared postgres connection string: %w", err)
		return
	}
	base, err := url.Parse(connStr)
	if err != nil {
		sharedErr = fmt.Errorf("parse shared postgres url: %w", err)
		return
	}

	// Migrate the template database exactly once, then close — CREATE DATABASE
	// ... TEMPLATE requires the source have no active connections.
	tmpl, err := store.New(ctx, connStr)
	if err != nil {
		sharedErr = fmt.Errorf("migrate template database: %w", err)
		return
	}
	tmpl.Close()

	admin, err := sql.Open("pgx", databaseURL(base, maintenanceDatabase))
	if err != nil {
		sharedErr = fmt.Errorf("open maintenance connection: %w", err)
		return
	}
	// One connection is enough and keeps CREATE/DROP DATABASE serialised at
	// the driver level too.
	admin.SetMaxOpenConns(1)
	if err := admin.PingContext(ctx); err != nil {
		sharedErr = fmt.Errorf("ping maintenance connection: %w", err)
		return
	}

	shared = &sharedPG{baseURL: base, admin: admin}
}

// databaseURL returns the shared container's connection string pointed at a
// specific database name.
func databaseURL(base *url.URL, dbName string) string {
	u := *base
	u.Path = "/" + dbName
	return u.String()
}

// setupTestStore is the shared bootstrap used by both public helpers. It
// clones the migrated template into a fresh per-test database and returns a
// connected Store; callers decide whether to wire projectors.
func setupTestStore(t *testing.T) *store.Store {
	t.Helper()
	sharedOnce.Do(initShared)
	if sharedErr != nil {
		t.Fatalf("testutil: shared postgres init: %v", sharedErr)
	}

	ctx := context.Background()
	dbName := fmt.Sprintf("pm_test_%d", dbSeq.Add(1))

	createMu.Lock()
	// %q on a Postgres identifier here is safe: dbName is a fixed-format
	// internal string (pm_test_<n>), never caller input.
	_, err := shared.admin.ExecContext(ctx,
		fmt.Sprintf(`CREATE DATABASE %q TEMPLATE %q`, dbName, templateDatabase))
	createMu.Unlock()
	if err != nil {
		t.Fatalf("testutil: create test database %s: %v", dbName, err)
	}

	// Registered BEFORE the Store close below so that, by t.Cleanup's LIFO
	// order, the Store (and its pool) is closed FIRST and the DROP sees no
	// lingering backends. WITH (FORCE) is belt-and-braces for the same reason.
	t.Cleanup(func() {
		createMu.Lock()
		defer createMu.Unlock()
		dropCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := shared.admin.ExecContext(dropCtx,
			fmt.Sprintf(`DROP DATABASE IF EXISTS %q WITH (FORCE)`, dbName)); err != nil {
			// Don't fail the test — it is already finalised at cleanup time.
			// Surfacing the error helps spot leaked databases; the shared
			// container is reaped by Ryuk regardless.
			t.Logf("testutil: drop test database %s: %v", dbName, err)
		}
	})

	// Schema is already present (cloned from the migrated template), so skip
	// migrations — re-running goose here would be redundant work on every test.
	st, err := store.NewWithoutMigrations(ctx, databaseURL(shared.baseURL, dbName))
	if err != nil {
		t.Fatalf("testutil: connect test database %s: %v", dbName, err)
	}
	t.Cleanup(func() { st.Close() })
	st.SetRepos(pgrepo.NewRepos(st.Queries()))
	return st
}

// SetupPostgres returns a connected Store backed by a fresh per-test database
// on the shared package container. The database is dropped when the test
// completes.
func SetupPostgres(t *testing.T) *store.Store {
	t.Helper()
	st := setupTestStore(t)

	// Wire the same Go-side projector listeners that production boot wires in
	// cmd/control/main.go. Without this, handlers emit events but the
	// projection writes never fire (the PL/pgSQL projectors that the
	// migrations have replaced with no-op stubs no longer do anything either),
	// so any test that reads back projection state after AppendEvent silently
	// sees stale data.
	projectors.WireAll(st, nil)

	return st
}

// SetupPostgresWithoutProjectors is identical to SetupPostgres but skips
// projectors.WireAll. Used only to exercise failure modes that depend on the
// projector pipeline being unwired — e.g. the RebuildAll guard that fires when
// neither a Go applier nor a PL/pgSQL function is set for a target.
//
// Production code paths must always call WireAll; never use this helper for
// tests that read projection state.
func SetupPostgresWithoutProjectors(t *testing.T) *store.Store {
	t.Helper()
	return setupTestStore(t)
}
