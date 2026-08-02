package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBoundedDamerauLevenshtein_MatchesReferenceForShortStrings(t *testing.T) {
	t.Parallel()

	values := []string{""}
	for length := 1; length <= 4; length++ {
		values = append(values, stringsOfLength("abc", length)...)
	}
	for _, a := range values {
		for _, b := range values {
			want := referenceDamerauLevenshtein(a, b)
			for limit := 0; limit <= 2; limit++ {
				got, ok := boundedDamerauLevenshtein(a, b, limit)
				assert.Equalf(t, want <= limit, ok, "%q → %q at limit %d", a, b, limit)
				if ok {
					assert.Equalf(t, want, got, "%q → %q at limit %d", a, b, limit)
				}
			}
		}
	}
}

func TestMatchFuzzyDocument_ApprovedEditContract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, query, primary, description, related string
		wantMatch, wantFuzzy                       bool
		wantEdits, wantFieldCost                   int
	}{
		{name: "one deletion", query: "server", primary: "sever", wantMatch: true, wantFuzzy: true, wantEdits: 1},
		{name: "adjacent transposition", query: "workstation", primary: "workstaiton", wantMatch: true, wantFuzzy: true, wantEdits: 1},
		{name: "two edits for eight characters", query: "abcdefgh", primary: "abcxefyh", wantMatch: true, wantFuzzy: true, wantEdits: 2},
		{name: "too many edits for seven characters", query: "servers", primary: "savors", wantMatch: false},
		{name: "short token is not fuzzy", query: "abc", primary: "acb", wantMatch: false},
		{name: "prefix is not fuzzy only", query: "work", primary: "workstation", wantMatch: true, wantFuzzy: false},
		{name: "every query token must match", query: "server secure", primary: "sever baseline", wantMatch: false},
		{name: "description follows primary", query: "server", description: "sever", wantMatch: true, wantFuzzy: true, wantEdits: 1, wantFieldCost: 1},
		{name: "related follows description", query: "server", related: "sever", wantMatch: true, wantFuzzy: true, wantEdits: 1, wantFieldCost: 2},
		{name: "unicode deletion", query: "münchen", primary: "münchn", wantMatch: true, wantFuzzy: true, wantEdits: 1},
		{name: "short sharp-s spelling stays distinct", query: "straße", primary: "strasse", wantMatch: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rank, fuzzy, ok := matchFuzzyDocument(tc.query, tc.primary, tc.description, tc.related)
			assert.Equal(t, tc.wantMatch, ok)
			if !ok {
				return
			}
			assert.Equal(t, tc.wantFuzzy, fuzzy)
			assert.Equal(t, tc.wantEdits, rank.edits)
			assert.Equal(t, tc.wantFieldCost, rank.fieldCost)
		})
	}
}

func TestFuzzyResultHeap_KeepsOnlyBestRequestedPrefix(t *testing.T) {
	t.Parallel()

	h := newFuzzyResultHeap(2)
	h.add(fuzzySearchResult{row: SearchRow{ID: "03"}, rank: fuzzyRank{edits: 2}})
	h.add(fuzzySearchResult{row: SearchRow{ID: "02"}, rank: fuzzyRank{edits: 1, fieldCost: 1}})
	h.add(fuzzySearchResult{row: SearchRow{ID: "01"}, rank: fuzzyRank{edits: 1}})

	got := h.sorted()
	require.Len(t, got, 2)
	assert.Equal(t, []string{"01", "02"}, []string{got[0].row.ID, got[1].row.ID})
}

func stringsOfLength(alphabet string, length int) []string {
	if length == 0 {
		return []string{""}
	}
	shorter := stringsOfLength(alphabet, length-1)
	result := make([]string, 0, len(shorter)*len(alphabet))
	for _, prefix := range shorter {
		for _, r := range alphabet {
			result = append(result, prefix+string(r))
		}
	}
	return result
}

func referenceDamerauLevenshtein(a, b string) int {
	ar, br := []rune(a), []rune(b)
	distance := make([][]int, len(ar)+1)
	for i := range distance {
		distance[i] = make([]int, len(br)+1)
		distance[i][0] = i
	}
	for j := range distance[0] {
		distance[0][j] = j
	}
	for i := 1; i <= len(ar); i++ {
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			distance[i][j] = min(distance[i-1][j]+1, distance[i][j-1]+1, distance[i-1][j-1]+cost)
			if i > 1 && j > 1 && ar[i-1] == br[j-2] && ar[i-2] == br[j-1] {
				distance[i][j] = min(distance[i][j], distance[i-2][j-2]+1)
			}
		}
	}
	return distance[len(ar)][len(br)]
}
