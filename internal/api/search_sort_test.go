package api

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/search"
)

// TestScopeSortableFields_MirrorIndexSchemas is a self-discovering guard that
// scopeSortableFields stays in lockstep with the SORTABLE attributes in
// search.IndexSchemas. A SORTBY on a field the index didn't declare SORTABLE is
// rejected by RediSearch; a SORTABLE field missing here is silently unsortable.
// Both sides derive from their sources, so the test fails on any drift.
func TestScopeSortableFields_MirrorIndexSchemas(t *testing.T) {
	require.NotEmpty(t, search.IndexSchemas, "no index schemas discovered — parity check would vacuously pass")

	sawSortable := false
	for _, ix := range search.IndexSchemas {
		scope := ix.Scope()
		want := ix.SortableFields()
		got := scopeSortableFields[scope] // may be nil if the scope has no sortable fields

		for field := range want {
			sawSortable = true
			assert.Truef(t, got[field],
				"scope %q: index %q declares SORTABLE field %q but scopeSortableFields omits it", scope, ix.Name, field)
		}
		for field := range got {
			assert.Truef(t, want[field],
				"scope %q: scopeSortableFields lists %q but index %q does not declare it SORTABLE", scope, field, ix.Name)
		}
	}
	require.True(t, sawSortable, "no SORTABLE fields discovered across any index — detector is dead")

	indexed := map[string]bool{}
	for _, ix := range search.IndexSchemas {
		indexed[ix.Scope()] = true
	}
	for scope := range scopeSortableFields {
		assert.Truef(t, indexed[scope], "scopeSortableFields advertises scope %q with no matching index", scope)
	}
}

func TestResolveSort_UnspecifiedFallsBackToScopeDefault(t *testing.T) {
	field, dir, err := resolveSort(context.Background(), "devices",
		pm.SortField_SORT_FIELD_UNSPECIFIED, pm.SortDirection_SORT_DIRECTION_UNSPECIFIED)
	require.NoError(t, err)
	assert.Equal(t, "last_seen_at", field, "devices default sort is last_seen_at")
	assert.Equal(t, "DESC", dir)
}

func TestResolveSort_ValidFieldAndDirection(t *testing.T) {
	field, dir, err := resolveSort(context.Background(), "actions",
		pm.SortField_SORT_FIELD_NAME, pm.SortDirection_SORT_DIRECTION_ASC)
	require.NoError(t, err)
	assert.Equal(t, "name", field)
	assert.Equal(t, "ASC", dir)
}

func TestResolveSort_FieldNotSortableOnScope_InvalidArgument(t *testing.T) {
	// hostname is sortable on devices, NOT on actions.
	_, _, err := resolveSort(context.Background(), "actions",
		pm.SortField_SORT_FIELD_HOSTNAME, pm.SortDirection_SORT_DIRECTION_DESC)
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestResolveSort_RuleCountSortableOnCompliance(t *testing.T) {
	// rule_count is now a populated SORTABLE field on compliance_policies (#325 PR B).
	field, dir, err := resolveSort(context.Background(), "compliance_policies",
		pm.SortField_SORT_FIELD_RULE_COUNT, pm.SortDirection_SORT_DIRECTION_DESC)
	require.NoError(t, err)
	assert.Equal(t, "rule_count", field)
	assert.Equal(t, "DESC", dir)
}
