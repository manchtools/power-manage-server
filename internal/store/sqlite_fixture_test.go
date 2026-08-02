package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testdb"
)

// setupSQLitePool creates one isolated, real SQLite file per test. maxConns is
// retained at the call boundary for the lock-pressure cases; SQLite writer
// serialization belongs to Store rather than a test-configurable pool.
func setupSQLitePool(t *testing.T, _ int) (*store.Store, *testdb.DB) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "power-manage.db")
	st, err := store.New(ctx, path)
	if err != nil {
		t.Fatalf("store test fixture: initialize SQLite: %v", err)
	}
	t.Cleanup(st.Close)
	raw, err := testdb.Open(ctx, path)
	if err != nil {
		t.Fatalf("store test fixture: open raw SQLite handle: %v", err)
	}
	t.Cleanup(raw.Close)
	return st, raw
}

func setupSQLite(t *testing.T) (*store.Store, *testdb.DB) {
	t.Helper()
	return setupSQLitePool(t, 0)
}

func seedDelivery(t *testing.T, raw *testdb.DB, deviceID string, now time.Time) string {
	t.Helper()
	deliveryID := newID()
	if _, err := raw.Exec(context.Background(), `
		INSERT INTO deliveries
			(delivery_id, device_id, manifest_id, manifest, state, created_at, available_at)
		VALUES ($1, $2, $3, '{}', 'PENDING', $4, $4)`,
		deliveryID, deviceID, newID(), now); err != nil {
		t.Fatalf("seed delivery: %v", err)
	}
	return deliveryID
}

func newID() string { return ulid.Make().String() }
