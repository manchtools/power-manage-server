package store

import (
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/jackc/pgx/v5"
)

const fuzzyCandidateSimilarity = 0.1

type fuzzyRank struct {
	edits, fieldCost int
}

type fuzzySearchResult struct {
	row  SearchRow
	rank fuzzyRank
}

// matchFuzzyDocument owns the engine-independent fuzzy contract. Primary is
// the entity ID and display name, description is the explicit description,
// and related is the remaining facet document assembled by PostgreSQL.
func matchFuzzyDocument(query, primary, description, related string) (fuzzyRank, bool, bool) {
	queryTokens := tokenizeSearchText(query)
	if len(queryTokens) == 0 {
		return fuzzyRank{}, false, false
	}

	type documentToken struct {
		value string
		field int
	}
	document := make([]documentToken, 0)
	for field, text := range []string{primary, description, related} {
		for _, token := range tokenizeSearchText(text) {
			document = append(document, documentToken{value: token, field: field})
		}
	}

	var rank fuzzyRank
	fuzzyOnly := false
	for _, queryToken := range queryTokens {
		bestEdits, bestField := -1, -1
		maxEdits := fuzzyEditLimit(queryToken)
		for _, candidate := range document {
			edits := -1
			if strings.HasPrefix(candidate.value, queryToken) {
				edits = 0
			} else if maxEdits > 0 {
				if distance, ok := boundedDamerauLevenshtein(queryToken, candidate.value, maxEdits); ok {
					edits = distance
				}
			}
			if edits < 0 || (bestEdits >= 0 && (edits > bestEdits || (edits == bestEdits && candidate.field >= bestField))) {
				continue
			}
			bestEdits, bestField = edits, candidate.field
		}
		if bestEdits < 0 {
			return fuzzyRank{}, false, false
		}
		rank.edits += bestEdits
		rank.fieldCost += bestField
		fuzzyOnly = fuzzyOnly || bestEdits > 0
	}
	return rank, fuzzyOnly, true
}

func tokenizeSearchText(value string) []string {
	var tokens []string
	var token []rune
	flush := func() {
		if len(token) == 0 {
			return
		}
		tokens = append(tokens, string(token))
		token = token[:0]
	}
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsMark(r) {
			token = append(token, unicode.ToLower(r))
			continue
		}
		flush()
	}
	flush()
	return tokens
}

func fuzzyEditLimit(token string) int {
	switch n := len([]rune(token)); {
	case n < 4:
		return 0
	case n < 8:
		return 1
	default:
		return 2
	}
}

// boundedDamerauLevenshtein computes optimal-string-alignment distance in a
// narrow band. Adjacent transposition costs one; values outside max are
// rejected without allocating an unbounded matrix.
func boundedDamerauLevenshtein(a, b string, maxDistance int) (int, bool) {
	ar, br := []rune(a), []rune(b)
	if abs(len(ar)-len(br)) > maxDistance {
		return 0, false
	}
	if len(ar) == 0 {
		return len(br), true
	}
	if len(br) == 0 {
		return len(ar), true
	}
	tooFar := maxDistance + 1
	previousPrevious := make([]int, len(br)+1)
	previous := make([]int, len(br)+1)
	current := make([]int, len(br)+1)
	for j := range previous {
		previous[j] = j
		previousPrevious[j] = tooFar
	}

	for i := 1; i <= len(ar); i++ {
		for j := range current {
			current[j] = tooFar
		}
		if i <= maxDistance {
			current[0] = i
		}
		start, end := max(1, i-maxDistance), min(len(br), i+maxDistance)
		rowBest := tooFar
		for j := start; j <= end; j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			current[j] = min(previous[j]+1, current[j-1]+1, previous[j-1]+cost)
			if i > 1 && j > 1 && ar[i-1] == br[j-2] && ar[i-2] == br[j-1] {
				current[j] = min(current[j], previousPrevious[j-2]+1)
			}
			rowBest = min(rowBest, current[j])
		}
		if rowBest > maxDistance {
			return 0, false
		}
		previousPrevious, previous, current = previous, current, previousPrevious
	}
	if previous[len(br)] > maxDistance {
		return 0, false
	}
	return previous[len(br)], true
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func fuzzyEligibleQueryTokens(query string) []string {
	tokens := tokenizeSearchText(query)
	eligible := tokens[:0]
	seen := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		if fuzzyEditLimit(token) == 0 {
			continue
		}
		if _, exists := seen[token]; exists {
			continue
		}
		seen[token] = struct{}{}
		eligible = append(eligible, token)
	}
	return eligible
}

func (f searchFacet) fuzzyRelatedSQL() string {
	if f.fuzzyRelated == "" {
		return "''::text"
	}
	return f.fuzzyRelated
}

// searchFuzzy streams PostgreSQL's trigram candidates through the bounded
// application matcher. It counts every accepted row but retains only the best
// prefix needed to serve the requested page.
func (s *Store) searchFuzzy(
	ctx context.Context,
	p SearchParams,
	facet searchFacet,
	args pgx.NamedArgs,
	baseConditions []string,
	keep int,
) ([]fuzzySearchResult, int64, error) {
	tokens := fuzzyEligibleQueryTokens(p.Query)
	if len(tokens) == 0 {
		return nil, 0, nil
	}
	args["fuzzy_tokens"] = tokens
	args["fuzzy_candidate_similarity"] = fuzzyCandidateSimilarity

	query := fmt.Sprintf(`WITH %s,
prefix_query AS (
    SELECT to_tsquery('simple'::regconfig,
        string_agg(quote_literal(term) || ':*', ' & ' ORDER BY term)) AS value
    FROM unnest(tsvector_to_array(to_tsvector('simple'::regconfig, @query::text))) AS term
), eligible AS (
    SELECT %s AS id, %s AS name, %s AS description, %s AS member_count,
           %s AS fields, %s AS fuzzy_related
    FROM %s CROSS JOIN prefix_query pq
    WHERE %s AND NOT (pq.value IS NOT NULL AND (%s))
), candidates AS (
    SELECT * FROM eligible
    WHERE NOT EXISTS (
        SELECT 1 FROM unnest(@fuzzy_tokens::text[]) AS q(token)
        WHERE strict_word_similarity(q.token,
            lower(concat_ws(' ', eligible.id, eligible.name, eligible.description,
                eligible.fields::text, eligible.fuzzy_related)))
            < @fuzzy_candidate_similarity
    )
)
SELECT id, name, description, member_count, fields, fuzzy_related FROM candidates`,
		assignmentGroupsCTE, facet.id, facet.name, facet.description, facet.memberCount,
		facet.fields, facet.fuzzyRelatedSQL(), facet.from,
		strings.Join(baseConditions, " AND "), facet.textMatch)

	rows, err := s.pool.Query(ctx, query, args)
	if err != nil {
		return nil, 0, fmt.Errorf("search %s fuzzy candidates: %w", p.Scope, err)
	}
	defer rows.Close()

	best := newFuzzyResultHeap(keep)
	var total int64
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		var row SearchRow
		var name, description, related *string
		var fields []byte
		if err := rows.Scan(&row.ID, &name, &description, &row.MemberCount, &fields, &related); err != nil {
			return nil, 0, fmt.Errorf("search %s fuzzy scan: %w", p.Scope, err)
		}
		if name != nil {
			row.Name = *name
		}
		if description != nil {
			row.Description = *description
		}
		row.Fields = make(map[string]string)
		if err := json.Unmarshal(fields, &row.Fields); err != nil {
			return nil, 0, fmt.Errorf("search %s fuzzy fields: %w", p.Scope, err)
		}
		relatedText := ""
		if related != nil {
			relatedText = *related
		}
		rank, fuzzyOnly, matches := matchFuzzyDocument(p.Query, row.ID+" "+row.Name, row.Description, relatedText)
		if !matches || !fuzzyOnly {
			continue
		}
		total++
		best.add(fuzzySearchResult{row: row, rank: rank})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("search %s fuzzy rows: %w", p.Scope, err)
	}
	return best.sorted(), total, nil
}

type fuzzyResultHeap struct {
	capacity int
	items    fuzzyMaxHeap
}

func newFuzzyResultHeap(capacity int) *fuzzyResultHeap {
	return &fuzzyResultHeap{capacity: max(0, capacity)}
}

func (h *fuzzyResultHeap) add(result fuzzySearchResult) {
	if h.capacity == 0 {
		return
	}
	if len(h.items) < h.capacity {
		heap.Push(&h.items, result)
		return
	}
	if fuzzyResultBetter(result, h.items[0]) {
		h.items[0] = result
		heap.Fix(&h.items, 0)
	}
}

func (h *fuzzyResultHeap) sorted() []fuzzySearchResult {
	result := append([]fuzzySearchResult(nil), h.items...)
	sort.Slice(result, func(i, j int) bool { return fuzzyResultBetter(result[i], result[j]) })
	return result
}

func fuzzyResultBetter(a, b fuzzySearchResult) bool {
	if a.rank.edits != b.rank.edits {
		return a.rank.edits < b.rank.edits
	}
	if a.rank.fieldCost != b.rank.fieldCost {
		return a.rank.fieldCost < b.rank.fieldCost
	}
	return a.row.ID < b.row.ID
}

type fuzzyMaxHeap []fuzzySearchResult

func (h fuzzyMaxHeap) Len() int { return len(h) }
func (h fuzzyMaxHeap) Less(i, j int) bool {
	return fuzzyResultBetter(h[j], h[i])
}
func (h fuzzyMaxHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *fuzzyMaxHeap) Push(value any) {
	*h = append(*h, value.(fuzzySearchResult))
}
func (h *fuzzyMaxHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}
