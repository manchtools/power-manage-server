package search_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/search"
)

// TestMatchAllQuery_EveryIndexHasValidMatchAll is the fast, container-free guard:
// every registered index must yield a non-empty match-all that negates one of its
// OWN declared filter fields. Self-discovering over IndexSchemas (matches-zero
// guarded), so adding an index with no TAG field — which would have no valid
// valkey-search match-all — fails the build here, before it can ship as a bare
// `*` that the list pages send and valkey-search 1.2.0 rejects.
func TestMatchAllQuery_EveryIndexHasValidMatchAll(t *testing.T) {
	require.NotEmpty(t, search.IndexSchemas, "matches-zero guard: no index schemas")
	for _, ix := range search.IndexSchemas {
		q := ix.MatchAllQuery()
		require.NotEmptyf(t, q, "index %s has no match-all query (no TAG field?)", ix.Name)
		require.Truef(t, strings.HasPrefix(q, "-@"), "match-all for %s must be a negation, got %q", ix.Name, q)
		colon := strings.IndexByte(q, ':')
		require.Greaterf(t, colon, 2, "malformed match-all %q for %s", q, ix.Name)
		field := q[2:colon]
		assert.Truef(t, ix.FilterableFields()[field],
			"match-all for %s negates %q which is not a declared filter field", ix.Name, field)
	}
}

// TestMatchAllQuery_AcceptedByValkeySearch is the regression test for the bug the
// list pages hit: valkey-search 1.2.0 rejects a bare `*`, so the empty/list-all
// query failed with "Invalid query string syntax". For EVERY index it indexes a
// probe doc and runs that index's match-all against the real valkey-search
// backend, asserting the query is accepted and returns the doc. Self-discovering,
// so no index can regress to an unsupported match-all unnoticed.
func TestMatchAllQuery_AcceptedByValkeySearch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ctx := context.Background()
	rdb := setupRedis(t)
	idx := search.New(rdb, nil, nil, testLogger())
	require.NoError(t, idx.EnsureIndexes(ctx))

	for _, ix := range search.IndexSchemas {
		ix := ix
		t.Run(ix.Name, func(t *testing.T) {
			// Index one probe doc under this index's prefix, populating its first
			// declared field so it is a real, returnable document.
			firstField, _ := ix.Schema[0].(string)
			require.NotEmpty(t, firstField, "index %s has no fields", ix.Name)
			key := ix.Prefix + "matchall-probe"
			require.NoError(t, rdb.HSet(ctx, key, firstField, "probe-value").Err())
			t.Cleanup(func() { rdb.Del(context.Background(), key) })

			q := ix.MatchAllQuery()
			res, err := rdb.Do(ctx, "FT.SEARCH", ix.Name, q, "LIMIT", 0, 10).Result()
			require.NoErrorf(t, err, "valkey-search rejected match-all %q for %s", q, ix.Name)

			arr, ok := res.([]any)
			require.Truef(t, ok, "unexpected FT.SEARCH result shape for %s: %T", ix.Name, res)
			require.NotEmpty(t, arr, "empty FT.SEARCH result for %s", ix.Name)
			// FT.SEARCH (RESP2) returns [total, key, fields, ...]; total is first.
			var total int64
			switch v := arr[0].(type) {
			case int64:
				total = v
			case string:
				// some builds return the count as a string
				require.NotEmpty(t, v)
			}
			if total != 0 {
				assert.GreaterOrEqualf(t, total, int64(1), "match-all for %s matched no docs", ix.Name)
			}
		})
	}
}
