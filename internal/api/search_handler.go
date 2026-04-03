package api

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/search"
)

// SearchHandler handles search and search index management RPCs.
type SearchHandler struct {
	logger    *slog.Logger
	searchIdx *search.Index
}

// NewSearchHandler creates a new search handler.
func NewSearchHandler(logger *slog.Logger) *SearchHandler {
	return &SearchHandler{
		logger: logger,
	}
}

// SetSearchIndex sets the search index used by the handler.
func (h *SearchHandler) SetSearchIndex(idx *search.Index) {
	h.searchIdx = idx
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

func (h *SearchHandler) Search(ctx context.Context, req *connect.Request[pm.SearchRequest]) (*connect.Response[pm.SearchResponse], error) {
	if h.searchIdx == nil {
		return nil, connect.NewError(connect.CodeUnavailable, nil)
	}

	query := strings.TrimSpace(req.Msg.Query)
	hasFilters := len(req.Msg.DateFilters) > 0 || len(req.Msg.TagFilters) > 0

	// Allow empty query when filters or scope are provided.
	if query == "" && !hasFilters && req.Msg.Scope == "" {
		return connect.NewResponse(&pm.SearchResponse{}), nil
	}

	pageSize := int(req.Msg.PageSize)
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}

	// Parse page token as offset.
	offset := 0
	if req.Msg.PageToken != "" {
		if v, err := strconv.Atoi(req.Msg.PageToken); err == nil {
			offset = v
		}
	}

	// Determine which scopes to search.
	scopes := []string{req.Msg.Scope}
	if req.Msg.Scope == "" {
		scopes = []string{"actions", "action_sets", "definitions", "compliance_policies", "devices", "users", "device_groups", "user_groups"}
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
			return nil, connect.NewError(connect.CodeInternal, err)
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
	if h.searchIdx == nil {
		return nil, connect.NewError(connect.CodeUnavailable, nil)
	}

	if err := h.searchIdx.Rebuild(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&pm.RebuildSearchIndexResponse{}), nil
}

// allowedSearchFields is the set of field names that can be used in search
// date and tag filters. This prevents query injection via crafted field names.
var allowedSearchFields = map[string]bool{
	// NUMERIC fields (date filters)
	"created_at":  true,
	"updated_at":  true,
	"occurred_at": true,
	// TAG fields (tag filters)
	"type":          true,
	"is_compliance": true,
	"status":        true,
	"action_type":   true,
	"device_id":     true,
	"stream_type":   true,
	"actor_type":    true,
	"actor_id":          true,
	"disabled":          true,
	"compliance_status": true,
	"agent_version":     true,
	"os_arch":           true,
	"registered_at":     true,
	"last_seen_at":      true,
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
			Scope:  scope,
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

// escapeRediSearchQuery escapes special characters that have meaning in RediSearch query syntax.
func escapeRediSearchQuery(query string) string {
	special := []string{
		"@", "!", "{", "}", "(", ")", "|", "-", "=", ">", "[", "]", ":", ";", "~",
	}
	result := query
	for _, ch := range special {
		result = strings.ReplaceAll(result, ch, "\\"+ch)
	}
	return result
}

// escapeRediSearchTagValue escapes special characters in a RediSearch TAG value.
func escapeRediSearchTagValue(val string) string {
	special := []string{
		",", ".", "<", ">", "{", "}", "[", "]", "\"", "'", ":", ";", "!", "@", "#",
		"$", "%", "^", "&", "*", "(", ")", "-", "+", "=", "~",
	}
	result := val
	for _, ch := range special {
		result = strings.ReplaceAll(result, ch, "\\"+ch)
	}
	return result
}
