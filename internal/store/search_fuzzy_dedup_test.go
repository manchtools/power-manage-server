package store

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMatchFuzzyDocument_DeduplicatesRepeatedQueryTokens pins that a repeated
// query token neither changes the match decision nor scales the rank, and — by
// asserting equality across growing duplication counts — that the bounded
// matcher iterates each distinct token once. Without the dedup, a query of one
// 4-char token repeated thousands of times runs one fuzzy pass per repeat over
// every candidate; the summed edit cost also grows with the repeat count, which
// is what these equalities catch.
func TestMatchFuzzyDocument_DeduplicatesRepeatedQueryTokens(t *testing.T) {
	t.Parallel()

	t.Run("single fuzzy token does not scale with repeats", func(t *testing.T) {
		const primary = "work" // "worj" fuzzy-matches "work" at edit cost 1
		baseRank, baseFuzzy, baseMatch := matchFuzzyDocument("worj", primary, "", "")
		require.True(t, baseMatch)
		require.True(t, baseFuzzy)
		require.Equal(t, 1, baseRank.edits)

		for _, repeats := range []int{2, 3, 8, 200} {
			query := strings.TrimSpace(strings.Repeat("worj ", repeats))
			rank, fuzzy, match := matchFuzzyDocument(query, primary, "", "")
			assert.Equalf(t, baseMatch, match, "%d repeats must not change the match decision", repeats)
			assert.Equalf(t, baseFuzzy, fuzzy, "%d repeats must not change the fuzzy-only flag", repeats)
			assert.Equalf(t, baseRank, rank, "%d repeats must not scale the rank", repeats)
		}
	})

	t.Run("distinct tokens are preserved while their repeats collapse", func(t *testing.T) {
		const primary, description = "work", "server"
		baseRank, baseFuzzy, baseMatch := matchFuzzyDocument("worj sever", primary, description, "")
		require.True(t, baseMatch, "both distinct tokens must match")
		require.True(t, baseFuzzy)

		// Repeating and interleaving the same two distinct tokens must not add,
		// drop, or reorder the contribution of either.
		rank, fuzzy, match := matchFuzzyDocument("worj sever worj sever sever worj", primary, description, "")
		assert.Equal(t, baseMatch, match)
		assert.Equal(t, baseFuzzy, fuzzy)
		assert.Equal(t, baseRank, rank)
	})
}
