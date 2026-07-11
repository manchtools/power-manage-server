package api

import (
	"context"
	"strings"

	"github.com/manchtools/power-manage/server/internal/search"
)

// scopedObjectIDs returns the page of in-scope object IDs (ordered created_at
// DESC, matching the Postgres List* ordering) plus the total in-scope count, for
// a scope-restricted caller, resolved from the search index.
//
// The object projections carry no scope column — the effective scope of an
// object (its assignment groups + container walk) is materialized only in the
// search index's @scope_group_ids TAG (the same materialization Search uses).
// So a scoped List* filters there, then hydrates full rows from Postgres by ID.
//
// FAILS CLOSED (ADR 0024 / spec 29 S1): a restricted caller whose index is
// unconfigured or not yet built sees NOTHING — never the unscoped catalog. Only
// call this when auth.ObjectScopeListFilter reported restricted; scopeGroupClause
// returns "" for an unrestricted caller, which also yields an empty (fail-closed)
// result here as a defensive backstop.
func scopedObjectIDs(ctx context.Context, idx *search.Index, scope string, offset, pageSize int32) (ids []string, total int32, err error) {
	if idx == nil {
		return nil, 0, nil
	}
	clause := scopeGroupClause(ctx, scope)
	if clause == "" {
		return nil, 0, nil
	}
	args := []any{"FT.SEARCH", "idx:" + scope, clause, "SORTBY", "created_at", "DESC", "LIMIT", offset, pageSize}
	raw, err := idx.RDB().Do(ctx, args...).Result()
	if err != nil {
		// An index that doesn't exist yet (control started before the first
		// Rebuild) fails CLOSED to an empty page, never the unscoped list.
		msg := err.Error()
		if strings.Contains(msg, "Unknown index") || strings.Contains(msg, "Unknown Index") || strings.Contains(msg, "not found") {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	parsed, count := parseFTSearchResult(raw, scope)
	ids = make([]string, len(parsed))
	for i, r := range parsed {
		ids[i] = r.Id
	}
	return ids, count, nil
}
