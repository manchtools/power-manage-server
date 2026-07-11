package api

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/manchtools/power-manage/server/internal/search"
)

// scopedObjectIDs returns the page of in-scope object IDs (ordered created_at
// DESC, matching the Postgres List* ordering) plus the total in-scope count, for
// a scope-restricted caller, resolved from the search index. extraClauses are
// additional RediSearch clauses ANDed onto the scope filter (e.g. an @type TAG so
// a scoped caller's typeFilter still applies and pagination stays accurate).
//
// The object projections carry no scope column — the effective scope of an
// object (its assignment groups + container walk) is materialized only in the
// search index's @scope_group_ids TAG (the same materialization Search uses). So
// a scoped List* filters there, then hydrates full rows from Postgres by ID.
//
// FAILS CLOSED (ADR 0024 / spec 29 S1): a restricted caller whose index is not
// yet built sees NOTHING — never the unscoped catalog — and the fail-closed path
// is logged so a missing index reads as an operational problem, not "zero
// results". Only call this when auth.ObjectScopeListFilter reported restricted;
// scopeGroupClause returns "" for an unrestricted caller, which also yields an
// empty (fail-closed) result here as a defensive backstop.
func scopedObjectIDs(ctx context.Context, idx *search.Index, logger *slog.Logger, scope string, offset, pageSize int32, extraClauses ...string) (ids []string, total int32, err error) {
	if idx == nil {
		return nil, 0, nil
	}
	clause := scopeGroupClause(ctx, scope)
	if clause == "" {
		return nil, 0, nil
	}
	q := clause
	for _, c := range extraClauses {
		if c != "" {
			q += " " + c
		}
	}
	args := []any{"FT.SEARCH", "idx:" + scope, q, "SORTBY", "created_at", "DESC", "LIMIT", offset, pageSize}
	raw, err := idx.RDB().Do(ctx, args...).Result()
	if err != nil {
		// A missing index (control started before the first Rebuild) is the ONLY
		// error we fail closed on — matched specifically on RediSearch's
		// "Unknown index" so an unrelated backend failure surfaces as an error,
		// not a silent empty page. Fail-closed is logged; the caller sees zero
		// results, never the unscoped list.
		if strings.Contains(strings.ToLower(err.Error()), "unknown index name") {
			if logger != nil {
				logger.Warn("scopedObjectIDs: search index not built, failing closed to empty page",
					"scope", scope, "error", err)
			}
			return nil, 0, nil
		}
		return nil, 0, fmt.Errorf("scopedObjectIDs: FT.SEARCH idx:%s: %w", scope, err)
	}
	parsed, count := parseFTSearchResult(raw, scope)
	ids = make([]string, len(parsed))
	for i, r := range parsed {
		ids[i] = r.Id
	}
	return ids, count, nil
}
