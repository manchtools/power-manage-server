package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

func TestBuildFTQuery_TextOnly(t *testing.T) {
	q := buildFTQuery("hello", nil, nil)
	assert.Equal(t, "hello*", q)
}

func TestBuildFTQuery_EmptyReturnsWildcard(t *testing.T) {
	q := buildFTQuery("", nil, nil)
	assert.Equal(t, "*", q)
}

func TestBuildFTQuery_TextWithSpecialChars(t *testing.T) {
	q := buildFTQuery("user@example.com", nil, nil)
	// The query escaper escapes @ but NOT dots (dots are only in the tag value escaper)
	assert.Contains(t, q, "user\\@example.com")
}

func TestBuildFTQuery_DateFilterOnly(t *testing.T) {
	filters := []*pm.SearchDateFilter{
		{Field: "created_at", Start: 1000, End: 2000},
	}
	q := buildFTQuery("", filters, nil)
	assert.Equal(t, "@created_at:[1000 2000]", q)
}

func TestBuildFTQuery_DateFilterStartOnly(t *testing.T) {
	filters := []*pm.SearchDateFilter{
		{Field: "created_at", Start: 1000},
	}
	q := buildFTQuery("", filters, nil)
	assert.Equal(t, "@created_at:[1000 +inf]", q)
}

func TestBuildFTQuery_DateFilterEndOnly(t *testing.T) {
	filters := []*pm.SearchDateFilter{
		{Field: "created_at", End: 2000},
	}
	q := buildFTQuery("", filters, nil)
	assert.Equal(t, "@created_at:[-inf 2000]", q)
}

func TestBuildFTQuery_DateFilterNoRange(t *testing.T) {
	// Both start and end are 0 => no actual filter, should return "*"
	filters := []*pm.SearchDateFilter{
		{Field: "created_at", Start: 0, End: 0},
	}
	q := buildFTQuery("", filters, nil)
	assert.Equal(t, "*", q)
}

func TestBuildFTQuery_DateFilterDisallowedField(t *testing.T) {
	filters := []*pm.SearchDateFilter{
		{Field: "injected_field", Start: 1000, End: 2000},
	}
	q := buildFTQuery("", filters, nil)
	assert.Equal(t, "*", q, "disallowed field should be skipped")
}

func TestBuildFTQuery_TagFilterOnly(t *testing.T) {
	tags := map[string]string{
		"type": "shell",
	}
	q := buildFTQuery("", nil, tags)
	assert.Equal(t, "@type:{shell}", q)
}

func TestBuildFTQuery_TagFilterMultipleValues(t *testing.T) {
	tags := map[string]string{
		"type": "shell|package",
	}
	q := buildFTQuery("", nil, tags)
	assert.Equal(t, "@type:{shell|package}", q)
}

func TestBuildFTQuery_TagFilterDisallowedField(t *testing.T) {
	tags := map[string]string{
		"injected": "value",
	}
	q := buildFTQuery("", nil, tags)
	assert.Equal(t, "*", q)
}

func TestBuildFTQuery_TagFilterEmptyValue(t *testing.T) {
	tags := map[string]string{
		"type": "",
	}
	q := buildFTQuery("", nil, tags)
	assert.Equal(t, "*", q, "empty tag value should be skipped")
}

func TestBuildFTQuery_Combined(t *testing.T) {
	dateFilters := []*pm.SearchDateFilter{
		{Field: "created_at", Start: 1000, End: 2000},
	}
	tagFilters := map[string]string{
		"type": "shell",
	}
	q := buildFTQuery("hello", dateFilters, tagFilters)
	assert.Contains(t, q, "hello*")
	assert.Contains(t, q, "@created_at:[1000 2000]")
	assert.Contains(t, q, "@type:{shell}")
}

func TestEscapeRediSearchQuery(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{"user@example", "user\\@example"},
		{"test!", "test\\!"},
		{"a{b}c", "a\\{b\\}c"},
		{"(x|y)", "\\(x\\|y\\)"},
		{"a-b", "a\\-b"},
		{"a=b", "a\\=b"},
		{"a>b", "a\\>b"},
		{"[a]", "\\[a\\]"},
		{"a:b", "a\\:b"},
		{"a;b", "a\\;b"},
		{"a~b", "a\\~b"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, escapeRediSearchQuery(tt.input))
		})
	}
}

func TestEscapeRediSearchTagValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{"a,b", "a\\,b"},
		{"a.b", "a\\.b"},
		{"a<b>c", "a\\<b\\>c"},
		{"a{b}c", "a\\{b\\}c"},
		{"a\"b", "a\\\"b"},
		{"a'b", "a\\'b"},
		{"a:b", "a\\:b"},
		{"a;b", "a\\;b"},
		{"a!b", "a\\!b"},
		{"a@b", "a\\@b"},
		{"a#b", "a\\#b"},
		{"a$b", "a\\$b"},
		{"a%b", "a\\%b"},
		{"a^b", "a\\^b"},
		{"a&b", "a\\&b"},
		{"a*b", "a\\*b"},
		{"a(b)c", "a\\(b\\)c"},
		{"a-b", "a\\-b"},
		{"a+b", "a\\+b"},
		{"a=b", "a\\=b"},
		{"a~b", "a\\~b"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, escapeRediSearchTagValue(tt.input))
		})
	}
}

func TestScopeSortField(t *testing.T) {
	tests := []struct {
		scope    string
		expected string
	}{
		{"actions", "created_at"},
		{"action_sets", "created_at"},
		{"definitions", "created_at"},
		{"devices", "last_seen_at"},
		{"users", "created_at"},
		{"device_groups", "created_at"},
		{"user_groups", "created_at"},
		{"executions", "created_at"},
		{"audit_events", "occurred_at"},
		{"unknown_scope", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			assert.Equal(t, tt.expected, scopeSortField(tt.scope))
		})
	}
}

func TestParseFTSearchResult_Empty(t *testing.T) {
	results, count := parseFTSearchResult(nil, "actions")
	assert.Nil(t, results)
	assert.Equal(t, int32(0), count)
}

func TestParseFTSearchResult_NotArray(t *testing.T) {
	results, count := parseFTSearchResult("not an array", "actions")
	assert.Nil(t, results)
	assert.Equal(t, int32(0), count)
}

func TestParseFTSearchResult_EmptyArray(t *testing.T) {
	results, count := parseFTSearchResult([]any{}, "actions")
	assert.Nil(t, results)
	assert.Equal(t, int32(0), count)
}

func TestParseFTSearchResult_ZeroResults(t *testing.T) {
	// FT.SEARCH returns [0] when there are no results
	results, count := parseFTSearchResult([]any{int64(0)}, "actions")
	assert.Empty(t, results)
	assert.Equal(t, int32(0), count)
}

func TestParseFTSearchResult_SingleResult(t *testing.T) {
	raw := []any{
		int64(1),
		"search:action:ABC123",
		[]any{"name", "My Action", "description", "A test action"},
	}

	results, count := parseFTSearchResult(raw, "actions")
	require.Len(t, results, 1)
	assert.Equal(t, int32(1), count)
	assert.Equal(t, "ABC123", results[0].Id)
	assert.Equal(t, "actions", results[0].Scope)
	assert.Equal(t, "My Action", results[0].Name)
	assert.Equal(t, "A test action", results[0].Description)
	assert.Equal(t, "My Action", results[0].Fields["name"])
	assert.Equal(t, "A test action", results[0].Fields["description"])
}

func TestParseFTSearchResult_MultipleResults(t *testing.T) {
	raw := []any{
		int64(2),
		"search:action:ID1",
		[]any{"name", "Action One"},
		"search:action:ID2",
		[]any{"name", "Action Two"},
	}

	results, count := parseFTSearchResult(raw, "actions")
	require.Len(t, results, 2)
	assert.Equal(t, int32(2), count)
	assert.Equal(t, "ID1", results[0].Id)
	assert.Equal(t, "ID2", results[1].Id)
}

func TestParseFTSearchResult_DeviceScope(t *testing.T) {
	// Fields are processed in order; "name" sets Name, then "hostname" overrides it for devices scope.
	raw := []any{
		int64(1),
		"search:device:DEV1",
		[]any{"hostname", "web-server-01"},
	}

	results, count := parseFTSearchResult(raw, "devices")
	require.Len(t, results, 1)
	assert.Equal(t, int32(1), count)
	// For devices scope, hostname sets the Name field
	assert.Equal(t, "web-server-01", results[0].Name)
}

func TestParseFTSearchResult_UserScope(t *testing.T) {
	raw := []any{
		int64(1),
		"search:user:USR1",
		[]any{"email", "user@example.com"},
	}

	results, count := parseFTSearchResult(raw, "users")
	require.Len(t, results, 1)
	assert.Equal(t, int32(1), count)
	// For users scope, email sets the Name field
	assert.Equal(t, "user@example.com", results[0].Name)
}

func TestParseFTSearchResult_MemberCount(t *testing.T) {
	raw := []any{
		int64(1),
		"search:action_set:SET1",
		[]any{"name", "My Set", "member_count", "5"},
	}

	results, count := parseFTSearchResult(raw, "action_sets")
	require.Len(t, results, 1)
	assert.Equal(t, int32(1), count)
	assert.Equal(t, int32(5), results[0].MemberCount)
}

func TestParseFTSearchResult_InvalidMemberCount(t *testing.T) {
	raw := []any{
		int64(1),
		"search:action_set:SET1",
		[]any{"name", "My Set", "member_count", "not-a-number"},
	}

	results, _ := parseFTSearchResult(raw, "action_sets")
	require.Len(t, results, 1)
	assert.Equal(t, int32(0), results[0].MemberCount)
}

func TestParseFTSearchResult_KeyWithoutColon(t *testing.T) {
	raw := []any{
		int64(1),
		"simplekey",
		[]any{"name", "Test"},
	}

	results, _ := parseFTSearchResult(raw, "actions")
	require.Len(t, results, 1)
	// LastIndex of ":" is -1, so id = key[0:] = full key
	assert.Equal(t, "simplekey", results[0].Id)
}

func TestParseFTSearchResult_InvalidDocPair(t *testing.T) {
	// key is not a string
	raw := []any{
		int64(1),
		42, // not a string key
		[]any{"name", "Test"},
	}

	results, count := parseFTSearchResult(raw, "actions")
	assert.Empty(t, results)
	assert.Equal(t, int32(1), count)
}
