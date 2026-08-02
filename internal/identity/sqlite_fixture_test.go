package identity_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testdb"
)

func setupSQLite(t *testing.T) (*store.Store, *testdb.DB) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "power-manage.db")
	st, err := store.New(ctx, path)
	if err != nil {
		t.Fatalf("identity test fixture: initialize SQLite: %v", err)
	}
	t.Cleanup(st.Close)
	raw, err := testdb.Open(ctx, path)
	if err != nil {
		t.Fatalf("identity test fixture: open raw SQLite handle: %v", err)
	}
	t.Cleanup(raw.Close)
	return st, raw
}
