package api

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// SearchHandler handles search and search index management RPCs.
type SearchHandler struct {
	searchIndexHolder
	logger *slog.Logger
}

// NewSearchHandler creates a new search handler.
func NewSearchHandler(logger *slog.Logger) *SearchHandler {
	return &SearchHandler{
		logger: logger,
	}
}

// scopeSortField returns the default sort field for a scope, or empty if none.
func scopeSortField(scope string) string {
	switch scope {
	case "actions", "action_sets", "definitions", "device_groups", "user_groups":
		return "created_at"
	case "devices":
		return "last_seen_at"
	case "users":
		return "created_at"
	case "executions":
		return "created_at"
	case "audit_events":
		return "occurred_at"
	}
	return ""
}

// searchScopeToString converts the wire enum to the lowercase string
// form used by the RediSearch index names (idx:<scope>) and the
// document key prefixes (search:<scope>:<id>). Returns the empty
// string for UNSPECIFIED so the caller can treat it as the legacy
// "all scopes" sentinel.
func searchScopeToString(s pm.SearchScope) string {
	switch s {
	case pm.SearchScope_SEARCH_SCOPE_ACTIONS:
		return "actions"
	case pm.SearchScope_SEARCH_SCOPE_ACTION_SETS:
		return "action_sets"
	case pm.SearchScope_SEARCH_SCOPE_DEFINITIONS:
		return "definitions"
	case pm.SearchScope_SEARCH_SCOPE_COMPLIANCE_POLICIES:
		return "compliance_policies"
	case pm.SearchScope_SEARCH_SCOPE_DEVICES:
		return "devices"
	case pm.SearchScope_SEARCH_SCOPE_USERS:
		return "users"
	case pm.SearchScope_SEARCH_SCOPE_DEVICE_GROUPS:
		return "device_groups"
	case pm.SearchScope_SEARCH_SCOPE_USER_GROUPS:
		return "user_groups"
	case pm.SearchScope_SEARCH_SCOPE_EXECUTIONS:
		return "executions"
	case pm.SearchScope_SEARCH_SCOPE_AUDIT_EVENTS:
		return "audit_events"
	default:
		return ""
	}
}

// searchScopeFromString is the inverse: it maps the lowercase string
// (as embedded in RediSearch keys) back to the wire enum. Unknown /
// empty values map to UNSPECIFIED so a stale or unknown index entry
// never crashes the response — the caller surfaces UNSPECIFIED and
// the client treats it as "unknown scope".
func searchScopeFromString(s string) pm.SearchScope {
	switch s {
	case "actions":
		return pm.SearchScope_SEARCH_SCOPE_ACTIONS
	case "action_sets":
		return pm.SearchScope_SEARCH_SCOPE_ACTION_SETS
	case "definitions":
		return pm.SearchScope_SEARCH_SCOPE_DEFINITIONS
	case "compliance_policies":
		return pm.SearchScope_SEARCH_SCOPE_COMPLIANCE_POLICIES
	case "devices":
		return pm.SearchScope_SEARCH_SCOPE_DEVICES
	case "users":
		return pm.SearchScope_SEARCH_SCOPE_USERS
	case "device_groups":
		return pm.SearchScope_SEARCH_SCOPE_DEVICE_GROUPS
	case "user_groups":
		return pm.SearchScope_SEARCH_SCOPE_USER_GROUPS
	case "executions":
		return pm.SearchScope_SEARCH_SCOPE_EXECUTIONS
	case "audit_events":
		return pm.SearchScope_SEARCH_SCOPE_AUDIT_EVENTS
	default:
		return pm.SearchScope_SEARCH_SCOPE_UNSPECIFIED
	}
}

func (h *SearchHandler) Search(ctx context.Context, req *connect.Request[pm.SearchRequest]) (*connect.Response[pm.SearchResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if h.searchIdx == nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeUnavailable, "search index is not configured on this control instance")
	}

	query := strings.TrimSpace(req.Msg.Query)
	hasFilters := len(req.Msg.DateFilters) > 0 || len(req.Msg.TagFilters) > 0
	scopeStr := searchScopeToString(req.Msg.Scope)

	// Allow empty query when filters or a specific scope are provided.
	// scopeStr == "" matches the legacy "all scopes" sentinel.
	if query == "" && !hasFilters && scopeStr == "" {
		return connect.NewResponse(&pm.SearchResponse{}), nil
	}

	pageSize := int(req.Msg.PageSize)
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}

	// Parse page token as offset. Cap the offset to prevent an
	// attacker or misbehaving client from walking arbitrarily deep
	// into results (Atoi alone has no ceiling).
	const maxSearchOffset = 100_000
	offset := 0
	if req.Msg.PageToken != "" {
		v, err := strconv.Atoi(req.Msg.PageToken)
		if err != nil || v < 0 || v > maxSearchOffset {
			return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "invalid page token")
		}
		offset = v
	}

	// Determine which scopes to search.
	scopes := []string{scopeStr}
	if scopeStr == "" {
		scopes = []string{"actions", "action_sets", "definitions", "compliance_policies", "devices", "users", "device_groups", "user_groups"}
	}

	// Reject filter fields that aren't supported by every scope in the
	// query plan. Without this check, an unscoped `@status:{pending}`
	// would propagate to e.g. idx:action_sets, which RediSearch rejects
	// with a SYNTAX error surfaced as opaque CodeInternal. See #158.
	if err := validateFiltersForScopes(ctx, scopes, req.Msg.DateFilters, req.Msg.TagFilters); err != nil {
		return nil, err
	}

	scopeToIndex := map[string]string{
		"actions":             "idx:actions",
		"action_sets":         "idx:action_sets",
		"definitions":         "idx:definitions",
		"compliance_policies": "idx:compliance_policies",
		"devices":             "idx:devices",
		"users":               "idx:users",
		"device_groups":       "idx:device_groups",
		"user_groups":         "idx:user_groups",
		"executions":          "idx:executions",
		"audit_events":        "idx:audit_events",
	}

	// Build the FT.SEARCH query from text query + filters.
	ftQuery := buildFTQuery(query, req.Msg.DateFilters, req.Msg.TagFilters)

	var results []*pm.SearchResult
	var totalCount int32

	for _, scope := range scopes {
		idxName, ok := scopeToIndex[scope]
		if !ok {
			continue
		}

		args := []any{"FT.SEARCH", idxName, ftQuery}

		// Add SORTBY for scopes that have a timestamp field.
		if sortField := scopeSortField(scope); sortField != "" {
			args = append(args, "SORTBY", sortField, "DESC")
		}

		args = append(args, "LIMIT", offset, pageSize)

		raw, err := h.searchIdx.RDB().Do(ctx, args...).Result()
		if err != nil {
			errMsg := err.Error()
			if strings.Contains(errMsg, "Unknown index") || strings.Contains(errMsg, "Unknown Index") || strings.Contains(errMsg, "not found") {
				continue
			}
			h.logger.Error("search index query failed", "scope", scope, "error", err)
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "search index query failed")
		}

		parsed, count := parseFTSearchResult(raw, scope)
		results = append(results, parsed...)
		totalCount += count
	}

	// Build next page token.
	var nextPageToken string
	if offset+pageSize < int(totalCount) {
		nextPageToken = strconv.Itoa(offset + pageSize)
	}

	return connect.NewResponse(&pm.SearchResponse{
		Results:       results,
		TotalCount:    totalCount,
		NextPageToken: nextPageToken,
	}), nil
}

func (h *SearchHandler) RebuildSearchIndex(ctx context.Context, req *connect.Request[pm.RebuildSearchIndexRequest]) (*connect.Response[pm.RebuildSearchIndexResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if h.searchIdx == nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeUnavailable, "search index is not configured on this control instance")
	}

	if err := h.searchIdx.Rebuild(ctx); err != nil {
		h.logger.Error("search index rebuild failed", "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "search index rebuild failed")
	}

	return connect.NewResponse(&pm.RebuildSearchIndexResponse{}), nil
}

// scopeFilterFields enumerates the indexed filter fields per scope.
// Mirrors the FT.CREATE schemas in internal/search/index.go: a field
// only appears here if its scope's RediSearch schema declares a NUMERIC
// or TAG attribute for it. Sending @status:{pending} to an index that
// doesn't declare a `status` attribute makes RediSearch reject the
// query with a SYNTAX error — see manchtools/power-manage-server#158.
//
// The map drives two checks:
//
//  1. Up-front validation in Search: if the request's filters
//     reference a field that isn't supported by every scope in the
//     query plan, return InvalidArgument naming the scopes that DO
//     support the field. Operators learn quickly; broken queries no
//     longer surface as opaque CodeInternal.
//
//  2. The derived allowedSearchFields set below feeds buildFTQuery's
//     defensive silent-drop check (defence in depth — the up-front
//     validator already rejects unknown fields).
var scopeFilterFields = map[string]map[string]bool{
	"actions":             {"type": true, "is_compliance": true, "created_at": true, "updated_at": true},
	"action_sets":         {"member_count": true, "created_at": true, "updated_at": true},
	"definitions":         {"member_count": true, "created_at": true, "updated_at": true},
	"compliance_policies": {},
	"devices":             {"agent_version": true, "os_arch": true, "compliance_status": true, "registered_at": true, "last_seen_at": true},
	"users":               {"disabled": true, "created_at": true},
	"device_groups":       {"is_dynamic": true, "member_count": true, "created_at": true},
	"user_groups":         {"is_dynamic": true, "member_count": true, "created_at": true},
	"executions":          {"status": true, "action_type": true, "device_id": true, "created_at": true},
	"audit_events":        {"stream_type": true, "actor_type": true, "actor_id": true, "occurred_at": true},
}

// allowedSearchFields is the union of every per-scope filter field.
// Derived from scopeFilterFields so the two never drift. Used by
// buildFTQuery as a final injection-prevention sieve; the up-front
// validateFiltersForScopes call is the operator-facing check.
var allowedSearchFields = func() map[string]bool {
	out := map[string]bool{}
	for _, fields := range scopeFilterFields {
		for f := range fields {
			out[f] = true
		}
	}
	return out
}()

// validateFiltersForScopes returns InvalidArgument when the request's
// filter fields reference attributes that aren't declared by every
// index in the query plan. The error message names the scopes that
// DO accept the field so the operator can re-issue with an explicit
// scope.
//
// Same-name attributes across scopes (e.g. created_at on actions +
// devices) pass when the query plan stays inside scopes that all
// declare them.
func validateFiltersForScopes(ctx context.Context, scopes []string, dateFilters []*pm.SearchDateFilter, tagFilters map[string]string) error {
	used := map[string]bool{}
	for _, df := range dateFilters {
		if df.Field != "" {
			used[df.Field] = true
		}
	}
	for f, v := range tagFilters {
		if f != "" && v != "" {
			used[f] = true
		}
	}
	for field := range used {
		acceptedByAll := true
		for _, sc := range scopes {
			if !scopeFilterFields[sc][field] {
				acceptedByAll = false
				break
			}
		}
		if acceptedByAll {
			continue
		}
		var supportedBy []string
		for sc, fields := range scopeFilterFields {
			if fields[field] {
				supportedBy = append(supportedBy, sc)
			}
		}
		sort.Strings(supportedBy)
		if len(supportedBy) == 0 {
			return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, fmt.Sprintf("filter field %q is not supported by any search scope", field))
		}
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, fmt.Sprintf("filter field %q is only valid for scope=%s", field, strings.Join(supportedBy, ",")))
	}
	return nil
}

// buildFTQuery constructs a RediSearch query string from text, date filters, and tag filters.
func buildFTQuery(textQuery string, dateFilters []*pm.SearchDateFilter, tagFilters map[string]string) string {
	var parts []string

	// Text query (prefix search).
	if textQuery != "" {
		escaped := escapeRediSearchQuery(textQuery)
		parts = append(parts, escaped+"*")
	}

	// Date range filters: @field:[start end]
	for _, df := range dateFilters {
		if df.Field == "" || !allowedSearchFields[df.Field] {
			continue
		}
		start := "-inf"
		end := "+inf"
		if df.Start > 0 {
			start = strconv.FormatInt(df.Start, 10)
		}
		if df.End > 0 {
			end = strconv.FormatInt(df.End, 10)
		}
		if start == "-inf" && end == "+inf" {
			continue // no actual filter
		}
		parts = append(parts, fmt.Sprintf("@%s:[%s %s]", df.Field, start, end))
	}

	// Tag filters: @field:{val1|val2}
	for field, value := range tagFilters {
		if field == "" || value == "" || !allowedSearchFields[field] {
			continue
		}
		// Values may be pipe-separated for OR. Escape each value.
		vals := strings.Split(value, "|")
		var escaped []string
		for _, v := range vals {
			escaped = append(escaped, escapeRediSearchTagValue(v))
		}
		parts = append(parts, fmt.Sprintf("@%s:{%s}", field, strings.Join(escaped, "|")))
	}

	if len(parts) == 0 {
		return "*"
	}
	return strings.Join(parts, " ")
}

// parseFTSearchResult parses the raw FT.SEARCH result into SearchResult protos.
// FT.SEARCH returns: [total_count, doc_key, [field, value, ...], doc_key, ...]
func parseFTSearchResult(raw any, scope string) ([]*pm.SearchResult, int32) {
	arr, ok := raw.([]any)
	if !ok || len(arr) < 1 {
		return nil, 0
	}

	total, _ := arr[0].(int64)

	var results []*pm.SearchResult
	// Each document is: key, [field, value, field, value, ...]
	for i := 1; i+1 < len(arr); i += 2 {
		key, ok := arr[i].(string)
		if !ok {
			continue
		}

		fields, ok := arr[i+1].([]any)
		if !ok {
			continue
		}

		// Extract ID from key (e.g., "search:action:ABC123" → "ABC123").
		id := key
		if idx := strings.LastIndex(key, ":"); idx >= 0 {
			id = key[idx+1:]
		}

		result := &pm.SearchResult{
			Id:     id,
			Scope:  searchScopeFromString(scope),
			Fields: make(map[string]string),
		}

		// Parse ALL field/value pairs into the fields map and populate top-level fields.
		for j := 0; j+1 < len(fields); j += 2 {
			fieldName, _ := fields[j].(string)
			fieldVal, _ := fields[j+1].(string)

			result.Fields[fieldName] = fieldVal

			switch fieldName {
			case "name":
				result.Name = fieldVal
			case "description":
				result.Description = fieldVal
			case "member_count":
				if v, err := strconv.Atoi(fieldVal); err == nil {
					result.MemberCount = int32(v)
				}
			case "hostname":
				if scope == "devices" {
					result.Name = fieldVal
				}
			case "email":
				if scope == "users" {
					result.Name = fieldVal
				}
			}
		}

		results = append(results, result)
	}

	return results, int32(total)
}

// rediSearchSpecialChars is the full set of characters RediSearch treats
// specially in query / TAG syntax. Backslash is NOT in this list — it is
// escaped separately and FIRST in escapeRediSearch.
var rediSearchSpecialChars = []string{
	",", ".", "<", ">", "{", "}", "[", "]", "\"", "'", ":", ";", "!", "@",
	"#", "$", "%", "^", "&", "*", "(", ")", "-", "+", "=", "~", "|", "/",
}

// escapeRediSearch escapes every character RediSearch treats specially so a
// user-supplied string is matched literally rather than parsed as query syntax.
//
// Backslash is escaped FIRST. Otherwise escaping another metacharacter (which
// inserts a backslash) is re-interpreted and leaves a LIVE operator: the prior
// code turned `\|` into `\\|` — a literal backslash followed by a live OR — and
// omitted `% * "` entirely, so a Search-permission holder could manipulate the
// query scope / build an error oracle. Whitespace is intentionally left alone:
// in the query path the result is a prefix term (`escaped*`) where spaces are
// the token separators a multi-word search relies on.
func escapeRediSearch(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	for _, ch := range rediSearchSpecialChars {
		s = strings.ReplaceAll(s, ch, "\\"+ch)
	}
	return s
}

// escapeRediSearchQuery escapes a free-text query before it is embedded in a
// RediSearch query string.
func escapeRediSearchQuery(query string) string { return escapeRediSearch(query) }

// escapeRediSearchTagValue escapes a RediSearch TAG field value.
func escapeRediSearchTagValue(val string) string { return escapeRediSearch(val) }
