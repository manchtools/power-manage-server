package search_test

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// setupRedis starts a Redis Stack container with RediSearch module and returns
// a connected go-redis client. The container is stopped when the test completes.
func setupRedis(t *testing.T) *redis.Client {
	t.Helper()
	ctx := context.Background()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "redis/redis-stack-server:latest",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { container.Terminate(context.Background()) })

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "6379")
	require.NoError(t, err)

	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", host, port.Port()),
		Protocol: 2,
	})
	t.Cleanup(func() { rdb.Close() })

	return rdb
}

func testLogger() *slog.Logger {
	return slog.Default()
}

func TestEnsureIndexes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	rdb := setupRedis(t)
	ctx := context.Background()

	idx := search.New(rdb, nil, nil, testLogger())

	err := idx.EnsureIndexes(ctx)
	require.NoError(t, err)

	// Verify all 6 indexes exist
	for _, idxName := range []string{
		"idx:actions", "idx:action_sets", "idx:definitions",
		"idx:compliance_policies", "idx:executions", "idx:audit_events",
	} {
		info := rdb.Do(ctx, "FT.INFO", idxName)
		require.NoError(t, info.Err(), "index %s should exist", idxName)
	}

	// Calling again should be idempotent
	err = idx.EnsureIndexes(ctx)
	require.NoError(t, err)
}

func TestWarmActions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	st := testutil.SetupPostgres(t)
	rdb := setupRedis(t)
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, "admin@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, userID, "Install Nginx", 100)

	idx := search.New(rdb, st, nil, testLogger())
	require.NoError(t, idx.EnsureIndexes(ctx))
	require.NoError(t, idx.Warm(ctx))

	// Verify action hash exists with correct fields
	fields, err := rdb.HGetAll(ctx, "search:action:"+actionID).Result()
	require.NoError(t, err)
	assert.Equal(t, "Install Nginx", fields["name"])
	assert.Equal(t, "100", fields["type"])

	// Verify FT.SEARCH returns the action
	result, err := rdb.Do(ctx, "FT.SEARCH", "idx:actions", "Nginx*", "LIMIT", 0, 10).Result()
	require.NoError(t, err)
	arr, ok := result.([]any)
	require.True(t, ok)
	count, _ := arr[0].(int64)
	assert.Equal(t, int64(1), count)
}

func TestWarmExecutions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	st := testutil.SetupPostgres(t)
	rdb := setupRedis(t)
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, "admin@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "web-server-01")
	actionID := testutil.CreateTestAction(t, st, userID, "Install Docker", 100)

	execID := testutil.NewID()
	err := st.AppendEvent(ctx, store.Event{
		StreamType: "execution",
		StreamID:   execID,
		EventType:  "ExecutionCreated",
		Data: map[string]any{
			"device_id":       deviceID,
			"action_id":       actionID,
			"action_type":     100,
			"desired_state":   1,
			"params":          map[string]any{},
			"timeout_seconds": 300,
		},
		ActorType: "user",
		ActorID:   userID,
	})
	require.NoError(t, err)

	idx := search.New(rdb, st, nil, testLogger())
	require.NoError(t, idx.EnsureIndexes(ctx))
	require.NoError(t, idx.Warm(ctx))

	// Verify execution hash exists with correct fields
	fields, err := rdb.HGetAll(ctx, "search:execution:"+execID).Result()
	require.NoError(t, err)
	assert.Equal(t, "Install Docker", fields["action_name"])
	assert.Equal(t, "web-server-01", fields["device_hostname"])
	assert.Equal(t, "pending", fields["status"])
	assert.Equal(t, "100", fields["action_type"])
	assert.Equal(t, deviceID, fields["device_id"])

	// Verify FT.SEARCH by action name
	result, err := rdb.Do(ctx, "FT.SEARCH", "idx:executions", "Docker*", "LIMIT", 0, 10).Result()
	require.NoError(t, err)
	arr, ok := result.([]any)
	require.True(t, ok)
	count, _ := arr[0].(int64)
	assert.Equal(t, int64(1), count)

	// Verify FT.SEARCH by hostname
	result, err = rdb.Do(ctx, "FT.SEARCH", "idx:executions", "web\\-server*", "LIMIT", 0, 10).Result()
	require.NoError(t, err)
	arr, ok = result.([]any)
	require.True(t, ok)
	count, _ = arr[0].(int64)
	assert.Equal(t, int64(1), count)
}

func TestWarmAuditEvents(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	st := testutil.SetupPostgres(t)
	rdb := setupRedis(t)
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, "admin@test.com", "pass", "admin")
	testutil.CreateTestDevice(t, st, "my-device")
	testutil.CreateTestAction(t, st, userID, "My Action", 100)

	idx := search.New(rdb, st, nil, testLogger())
	require.NoError(t, idx.EnsureIndexes(ctx))
	require.NoError(t, idx.Warm(ctx))

	// Verify FT.SEARCH finds UserCreated events
	result, err := rdb.Do(ctx, "FT.SEARCH", "idx:audit_events", "UserCreated*", "LIMIT", 0, 10).Result()
	require.NoError(t, err)
	arr, ok := result.([]any)
	require.True(t, ok)
	count, _ := arr[0].(int64)
	assert.GreaterOrEqual(t, count, int64(1))

	// Search by stream_type TAG
	result, err = rdb.Do(ctx, "FT.SEARCH", "idx:audit_events", "@stream_type:{device}", "LIMIT", 0, 10).Result()
	require.NoError(t, err)
	arr, ok = result.([]any)
	require.True(t, ok)
	count, _ = arr[0].(int64)
	assert.GreaterOrEqual(t, count, int64(1))
}

func TestFlushAndRebuild(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	st := testutil.SetupPostgres(t)
	rdb := setupRedis(t)
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, "admin@test.com", "pass", "admin")
	testutil.CreateTestAction(t, st, userID, "Flush Test Action", 100)

	idx := search.New(rdb, st, nil, testLogger())

	// Build
	require.NoError(t, idx.Rebuild(ctx))

	// Verify data exists
	result, err := rdb.Do(ctx, "FT.SEARCH", "idx:actions", "Flush*", "LIMIT", 0, 10).Result()
	require.NoError(t, err)
	arr, _ := result.([]any)
	count, _ := arr[0].(int64)
	assert.Equal(t, int64(1), count)

	// Flush
	require.NoError(t, idx.FlushSearchData(ctx))

	// Indexes no longer exist — FT.SEARCH should error
	_, err = rdb.Do(ctx, "FT.SEARCH", "idx:actions", "Flush*").Result()
	assert.Error(t, err)

	// Rebuild should restore
	require.NoError(t, idx.Rebuild(ctx))

	result, err = rdb.Do(ctx, "FT.SEARCH", "idx:actions", "Flush*", "LIMIT", 0, 10).Result()
	require.NoError(t, err)
	arr, _ = result.([]any)
	count, _ = arr[0].(int64)
	assert.Equal(t, int64(1), count)
}

func TestSearchExecutionsByTag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	st := testutil.SetupPostgres(t)
	rdb := setupRedis(t)
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, "admin@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "tag-test-host")
	actionID := testutil.CreateTestAction(t, st, userID, "Tag Test Action", 200)

	execID := testutil.NewID()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "execution",
		StreamID:   execID,
		EventType:  "ExecutionCreated",
		Data: map[string]any{
			"device_id":       deviceID,
			"action_id":       actionID,
			"action_type":     200,
			"desired_state":   1,
			"params":          map[string]any{},
			"timeout_seconds": 300,
		},
		ActorType: "user",
		ActorID:   userID,
	}))

	idx := search.New(rdb, st, nil, testLogger())
	require.NoError(t, idx.Rebuild(ctx))

	// Search by action_type TAG
	result, err := rdb.Do(ctx, "FT.SEARCH", "idx:executions", "@action_type:{200}", "LIMIT", 0, 10).Result()
	require.NoError(t, err)
	arr, ok := result.([]any)
	require.True(t, ok)
	count, _ := arr[0].(int64)
	assert.Equal(t, int64(1), count)

	// Search by status TAG
	result, err = rdb.Do(ctx, "FT.SEARCH", "idx:executions", "@status:{pending}", "LIMIT", 0, 10).Result()
	require.NoError(t, err)
	arr, ok = result.([]any)
	require.True(t, ok)
	count, _ = arr[0].(int64)
	assert.GreaterOrEqual(t, count, int64(1))
}

func TestSearchAuditEventsByTag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	st := testutil.SetupPostgres(t)
	rdb := setupRedis(t)
	ctx := context.Background()

	testutil.CreateTestUser(t, st, "admin@test.com", "pass", "admin")

	idx := search.New(rdb, st, nil, testLogger())
	require.NoError(t, idx.Rebuild(ctx))

	// Search by actor_type TAG
	result, err := rdb.Do(ctx, "FT.SEARCH", "idx:audit_events", "@actor_type:{system}", "LIMIT", 0, 10).Result()
	require.NoError(t, err)
	arr, ok := result.([]any)
	require.True(t, ok)
	count, _ := arr[0].(int64)
	assert.GreaterOrEqual(t, count, int64(1))
}

func TestCompliancePolicySearch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	st := testutil.SetupPostgres(t)
	rdb := setupRedis(t)
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, "admin@test.com", "pass", "admin")

	// Create a compliance policy
	policyID := testutil.NewID()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy",
		StreamID:   policyID,
		EventType:  "CompliancePolicyCreated",
		Data: map[string]any{
			"name":        "Security Baseline",
			"description": "Ensures all servers have basic security packages",
		},
		ActorType: "user",
		ActorID:   userID,
	}))

	idx := search.New(rdb, st, nil, testLogger())
	require.NoError(t, idx.Rebuild(ctx))

	// Search by name
	result, err := rdb.Do(ctx, "FT.SEARCH", "idx:compliance_policies", "Security*", "LIMIT", 0, 10).Result()
	require.NoError(t, err)
	arr, ok := result.([]any)
	require.True(t, ok)
	count, _ := arr[0].(int64)
	assert.Equal(t, int64(1), count)
}
