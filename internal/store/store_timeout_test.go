package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestNew_SetsStatementTimeout pins WS13 #10: the pool applies a non-zero
// application statement_timeout on its connections, and the timeout actually
// cancels an over-long query (verified quickly via a per-transaction override
// rather than waiting out the production bound).
func TestNew_SetsStatementTimeout(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	// The pool set a non-zero statement_timeout on its connections.
	var timeoutStr string
	require.NoError(t, st.TestingPool().QueryRow(ctx, "SHOW statement_timeout").Scan(&timeoutStr))
	assert.NotEqual(t, "0", timeoutStr, "statement_timeout must be set to a non-zero bound on pooled connections")

	// The mechanism cancels an over-long query (fast: a tiny per-tx override).
	tx, err := st.TestingPool().Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, "SET LOCAL statement_timeout = '100ms'")
	require.NoError(t, err)
	_, err = tx.Exec(ctx, "SELECT pg_sleep(1)")
	require.Error(t, err, "a query exceeding statement_timeout must be cancelled, not hang")
	assert.Contains(t, err.Error(), "statement timeout", "the error must be the statement-timeout cancellation")
}
