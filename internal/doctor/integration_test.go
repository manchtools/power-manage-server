package doctor

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/manchtools/power-manage/server/internal/search"
)

// waitReachable retries ping until it succeeds, smoothing over the brief window
// between a container's readiness log and it actually accepting connections.
func waitReachable(t *testing.T, ping func() error) {
	t.Helper()
	var err error
	for i := 0; i < 40; i++ {
		if err = ping(); err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	require.NoError(t, err, "never became reachable")
}

// TestValkeyProbe_Integration exercises the real RediSearch/Asynq probe against a
// live valkey-search container (the unit tests use fakes; this verifies the
// actual FT.INFO / fingerprint / queue commands).
func TestValkeyProbe_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "valkey/valkey-bundle:9.1.0",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	host, err := c.Host(ctx)
	require.NoError(t, err)
	port, err := c.MappedPort(ctx, "6379")
	require.NoError(t, err)
	addr := fmt.Sprintf("%s:%s", host, port.Port())

	probe, err := NewValkeyProbe(addr, "", "", 0, nil)
	require.NoError(t, err)
	t.Cleanup(probe.Close)

	waitReachable(t, func() error { return probe.Ping(ctx) })

	// Before any indexer run: every expected index is missing.
	missing, err := probe.MissingIndexes(ctx, expectedIndexNames())
	require.NoError(t, err)
	assert.ElementsMatch(t, expectedIndexNames(), missing, "no indexes created yet")

	// Schema is not current until a fingerprint is stamped.
	current, err := probe.SchemaCurrent(ctx)
	require.NoError(t, err)
	assert.False(t, current)

	// Create the indexes the way the indexer does, then re-check.
	rdb := redis.NewClient(&redis.Options{Addr: addr, Protocol: 2})
	t.Cleanup(func() { _ = rdb.Close() })
	idx := search.New(rdb, nil, nil, slog.Default())
	require.NoError(t, idx.EnsureIndexes(ctx))
	require.NoError(t, rdb.Set(ctx, search.SchemaFingerprintKey, search.SchemaFingerprint(), 0).Err())

	missing, err = probe.MissingIndexes(ctx, expectedIndexNames())
	require.NoError(t, err)
	assert.Empty(t, missing, "all indexes present after EnsureIndexes")

	current, err = probe.SchemaCurrent(ctx)
	require.NoError(t, err)
	assert.True(t, current, "fingerprint matches the running schema")

	// Before any reconcile: the heartbeat is absent.
	_, present, err := probe.LastReconcile(ctx)
	require.NoError(t, err)
	assert.False(t, present, "no heartbeat before a reconcile")

	// The indexer stamps the heartbeat; the probe round-trips the real RFC3339 key.
	require.NoError(t, idx.StampReconciled(ctx))
	ts, present, err := probe.LastReconcile(ctx)
	require.NoError(t, err)
	require.True(t, present, "heartbeat present after StampReconciled")
	assert.WithinDuration(t, time.Now(), ts, time.Minute, "heartbeat is recent")

	// No queues created yet → empty, no error (queue-not-found is not a failure).
	archived, err := probe.ArchivedByQueue(ctx)
	require.NoError(t, err)
	assert.Empty(t, archived)

	// And the high-level check passes against the live cache (fresh heartbeat).
	env := testEnv(nil)
	env.Cache = probe
	env.Now = time.Now // real clock so the fresh heartbeat reads as fresh
	assert.Equal(t, SeverityOK, worst(run1(t, SearchCheck{}, env)))
}

// TestPGProbe_Integration exercises the real Postgres probe (Ping + the
// admin-exists query) against a live Postgres container.
func TestPGProbe_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ctx := context.Background()
	pg, err := postgres.Run(ctx, "postgres:17-alpine",
		postgres.WithDatabase("doctor"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(60*time.Second)),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pg.Terminate(context.Background()) })
	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	probe, err := NewPGProbe(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(probe.Close)
	waitReachable(t, func() error { return probe.Ping(ctx) })

	// Seed a minimal users_projection with a default-email admin (DB is ready now).
	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, `CREATE TABLE users_projection (
		email text NOT NULL, role text NOT NULL DEFAULT 'user',
		disabled boolean NOT NULL DEFAULT false, is_deleted boolean NOT NULL DEFAULT false)`)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, `INSERT INTO users_projection (email, role) VALUES ($1, 'admin')`, defaultAdminEmail)
	require.NoError(t, err)
	require.NoError(t, conn.Close(ctx))

	exists, err := probe.AdminUserExists(ctx, defaultAdminEmail)
	require.NoError(t, err)
	assert.True(t, exists, "the default-email admin is detected")

	exists, err = probe.AdminUserExists(ctx, "nobody@corp.example")
	require.NoError(t, err)
	assert.False(t, exists)

	// The admin check flags the default-email admin against the live DB.
	env := testEnv(nil)
	env.DB = probe
	assert.Equal(t, SeverityWarning, worst(run1(t, AdminCheck{}, env)))
}
