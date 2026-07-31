package store_test

// Real-PostgreSQL fixture for the store package.
//
// One container per test binary, started lazily. Its default database
// is migrated once and then used only as a CREATE DATABASE ... TEMPLATE
// source; each test clones it into a database it owns and drops on
// cleanup. Isolation is identical to a container per test — every test
// sees a pristine schema with nobody else's rows — while the expensive
// boot and migrate happen once.
//
// The template must have no live connections to be clonable, which is
// why the migrating store is closed immediately and no test ever
// connects to it.

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // "pgx" database/sql driver for the maintenance connection
	"github.com/oklog/ulid/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	templateDatabase    = "power_manage_test"
	maintenanceDatabase = "postgres"
)

type sharedPG struct {
	baseURL *url.URL
	admin   *sql.DB
}

var (
	sharedOnce sync.Once
	shared     *sharedPG
	sharedErr  error
	dbSeq      atomic.Uint64
	// createMu serialises CREATE/DROP DATABASE on the single admin
	// connection.
	createMu sync.Mutex
)

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
	// No Terminate hook: the container is shared for the whole test
	// binary and reaped by the testcontainers sidecar when the process
	// exits.

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
	admin.SetMaxOpenConns(1)
	if err := admin.PingContext(ctx); err != nil {
		sharedErr = fmt.Errorf("ping maintenance connection: %w", err)
		return
	}

	shared = &sharedPG{baseURL: base, admin: admin}
}

func databaseURL(base *url.URL, dbName string) string {
	u := *base
	u.Path = "/" + dbName
	return u.String()
}

// setupPostgresPool clones the migrated template into a fresh per-test
// database and returns a connected Store plus a pool the TEST owns.
//
// The second pool exists because the Store deliberately exposes no raw
// database access: a test that needs to introspect the catalog, drive
// the append-only triggers directly or simulate a hostile edit opens
// its own connection rather than the production type growing an
// escape hatch for it.
//
// maxConns caps the store's pgx pool (0 = pgx default); a small cap
// exercises pool-pressure paths.
func setupPostgresPool(t *testing.T, maxConns int) (*store.Store, *pgxpool.Pool) {
	t.Helper()
	sharedOnce.Do(initShared)
	if sharedErr != nil {
		t.Fatalf("store test fixture: shared postgres init: %v", sharedErr)
	}

	ctx := context.Background()
	dbName := fmt.Sprintf("pm_test_%d", dbSeq.Add(1))

	createMu.Lock()
	// %q on the identifier is safe: dbName is a fixed internal format,
	// never caller input.
	_, err := shared.admin.ExecContext(ctx,
		fmt.Sprintf(`CREATE DATABASE %q TEMPLATE %q`, dbName, templateDatabase))
	createMu.Unlock()
	if err != nil {
		t.Fatalf("store test fixture: create test database %s: %v", dbName, err)
	}

	// Registered BEFORE the store's own cleanup so t.Cleanup's LIFO
	// order closes the pool first and the DROP sees no live backend.
	t.Cleanup(func() {
		createMu.Lock()
		defer createMu.Unlock()
		dropCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := shared.admin.ExecContext(dropCtx,
			fmt.Sprintf(`DROP DATABASE IF EXISTS %q WITH (FORCE)`, dbName)); err != nil {
			t.Logf("store test fixture: drop test database %s: %v", dbName, err)
		}
	})

	connStr := databaseURL(shared.baseURL, dbName)
	if maxConns > 0 {
		sep := "?"
		if strings.Contains(connStr, "?") {
			sep = "&"
		}
		connStr += sep + fmt.Sprintf("pool_max_conns=%d", maxConns)
	}
	// The schema arrived with the clone, so migrations are skipped.
	st, err := store.NewWithoutMigrations(ctx, connStr)
	if err != nil {
		t.Fatalf("store test fixture: connect test database %s: %v", dbName, err)
	}
	t.Cleanup(st.Close)

	raw, err := pgxpool.New(ctx, databaseURL(shared.baseURL, dbName))
	if err != nil {
		t.Fatalf("store test fixture: open raw pool on %s: %v", dbName, err)
	}
	t.Cleanup(raw.Close)

	return st, raw
}

func setupPostgres(t *testing.T) (*store.Store, *pgxpool.Pool) {
	t.Helper()
	return setupPostgresPool(t, 0)
}

// newID mints a ULID, the only identifier form this schema accepts.
func newID() string { return ulid.Make().String() }
