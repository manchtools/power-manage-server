package search_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/search"
)

// ftCount extracts the hit count from a raw FT.SEARCH reply.
func ftCount(t *testing.T, result any) int64 {
	t.Helper()
	arr, ok := result.([]any)
	require.True(t, ok, "FT.SEARCH reply must be an array, got %T", result)
	count, ok := arr[0].(int64)
	require.True(t, ok, "FT.SEARCH count must be int64, got %T", arr[0])
	return count
}

// onlineQuery mirrors the search handler's deviceStatusClause "online"
// window: last_seen_at strictly newer than now-5m.
func onlineQuery() string {
	cutoff := time.Now().Add(-5 * time.Minute).Unix()
	return fmt.Sprintf("@last_seen_at:[(%d +inf]", cutoff)
}

// TestTouchDeviceLastSeen_DeviceGoesOnline is the #499 regression: a
// device whose indexed last_seen_at is stale shows offline in search
// even while it heartbeats. The O(1) touch must advance the NUMERIC
// field so the online status filter matches again — without a full
// row reload.
func TestTouchDeviceLastSeen_DeviceGoesOnline(t *testing.T) {
	rdb := setupRedis(t)
	idx := search.New(rdb, nil, nil, testLogger())
	ctx := context.Background()
	require.NoError(t, idx.EnsureIndexes(ctx))

	// Seed an indexed device row with a 2-hour-stale last_seen_at, the
	// way the indexer worker writes it (HSET on the search:device: prefix).
	stale := time.Now().Add(-2 * time.Hour).Unix()
	key := "search:device:DEVTOUCH1"
	require.NoError(t, rdb.HSet(ctx, key, map[string]any{
		"hostname":     "touch-host",
		"last_seen_at": strconv.FormatInt(stale, 10),
	}).Err())

	result, err := rdb.Do(ctx, "FT.SEARCH", "idx:devices", onlineQuery(), "LIMIT", 0, 10).Result()
	require.NoError(t, err)
	require.Equal(t, int64(0), ftCount(t, result), "stale device must start offline")

	now := time.Now().Unix()
	require.NoError(t, idx.TouchDeviceLastSeen(ctx, "DEVTOUCH1", now))

	// The FT NUMERIC attribute updates with the hash field: the device
	// is online again for the same window query.
	result, err = rdb.Do(ctx, "FT.SEARCH", "idx:devices", onlineQuery(), "LIMIT", 0, 10).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), ftCount(t, result), "touched device must match the online window")

	val, err := rdb.HGet(ctx, key, "last_seen_at").Result()
	require.NoError(t, err)
	assert.Equal(t, strconv.FormatInt(now, 10), val)
}

// TestTouchDeviceLastSeen_NoPartialRowForUnindexedDevice pins the
// guard: touching a device that has no search row (not yet indexed,
// or already removed) must NOT create a partial hash — a hash holding
// only last_seen_at would enter the FT index and surface as a
// hostname-less ghost row in device search results.
func TestTouchDeviceLastSeen_NoPartialRowForUnindexedDevice(t *testing.T) {
	rdb := setupRedis(t)
	idx := search.New(rdb, nil, nil, testLogger())
	ctx := context.Background()
	require.NoError(t, idx.EnsureIndexes(ctx))

	require.NoError(t, idx.TouchDeviceLastSeen(ctx, "DEVGHOST1", time.Now().Unix()))

	exists, err := rdb.Exists(ctx, "search:device:DEVGHOST1").Result()
	require.NoError(t, err)
	assert.Equal(t, int64(0), exists, "touch must not create a hash for an unindexed device")

	result, err := rdb.Do(ctx, "FT.SEARCH", "idx:devices", onlineQuery(), "LIMIT", 0, 10).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(0), ftCount(t, result), "no ghost row may enter the device index")
}
