package api

import (
	"context"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/search"
)

// SearchHandler handles search and search index management RPCs.
type SearchHandler struct {
	searchIdx *search.Index
}

// NewSearchHandler creates a new search handler.
func NewSearchHandler() *SearchHandler {
	return &SearchHandler{}
}

// SetSearchIndex sets the search index used by the handler.
func (h *SearchHandler) SetSearchIndex(idx *search.Index) {
	h.searchIdx = idx
}

func (h *SearchHandler) Search(ctx context.Context, req *connect.Request[pm.SearchRequest]) (*connect.Response[pm.SearchResponse], error) {
	if h.searchIdx == nil {
		return nil, connect.NewError(connect.CodeUnavailable, nil)
	}

	query := strings.TrimSpace(req.Msg.Query)
	if query == "" {
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
		scopes = []string{"actions", "action_sets", "definitions", "compliance_policies"}
	}

	scopeToIndex := map[string]string{
		"actions":             "idx:actions",
		"action_sets":         "idx:action_sets",
		"definitions":         "idx:definitions",
		"compliance_policies": "idx:compliance_policies",
	}

	// Escape special RediSearch characters in query.
	escaped := escapeRediSearchQuery(query)
	ftQuery := escaped + "*"

	var results []*pm.SearchResult
	var totalCount int32

	for _, scope := range scopes {
		idxName, ok := scopeToIndex[scope]
		if !ok {
			continue
		}

		args := []any{"FT.SEARCH", idxName, ftQuery, "LIMIT", offset, pageSize}
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
			Id:    id,
			Scope: scope,
		}

		// Parse field/value pairs.
		for j := 0; j+1 < len(fields); j += 2 {
			fieldName, _ := fields[j].(string)
			fieldVal, _ := fields[j+1].(string)
			switch fieldName {
			case "name":
				result.Name = fieldVal
			case "description":
				result.Description = fieldVal
			case "member_count":
				if v, err := strconv.Atoi(fieldVal); err == nil {
					result.MemberCount = int32(v)
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
