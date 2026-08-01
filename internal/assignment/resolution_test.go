package assignment

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/store"
)

func TestResolveSourcesAppliesModePrecedence(t *testing.T) {
	path := func(sourceID string, mode pmv1.AssignmentMode, selected bool) store.ResolvedAssignmentSource {
		return store.ResolvedAssignmentSource{
			SourceType: "action", SourceID: sourceID, Mode: int32(mode), Selected: selected,
		}
	}
	paths := []store.ResolvedAssignmentSource{
		path("excluded", pmv1.AssignmentMode_ASSIGNMENT_MODE_REQUIRED, false),
		path("excluded", pmv1.AssignmentMode_ASSIGNMENT_MODE_EXCLUDED, false),
		path("uninstall", pmv1.AssignmentMode_ASSIGNMENT_MODE_REQUIRED, false),
		path("uninstall", pmv1.AssignmentMode_ASSIGNMENT_MODE_UNINSTALL, false),
		path("unselected", pmv1.AssignmentMode_ASSIGNMENT_MODE_AVAILABLE, false),
		path("selected", pmv1.AssignmentMode_ASSIGNMENT_MODE_AVAILABLE, true),
	}

	resolved, err := ResolveSources(paths)
	require.NoError(t, err)
	require.Len(t, resolved, 4)
	assert.Equal(t, "excluded", resolved[0].Row.SourceID)
	assert.False(t, resolved[0].Active)
	assert.True(t, resolved[0].Excluded)
	assert.False(t, resolved[0].ForceAbsent)
	assert.Equal(t, "uninstall", resolved[1].Row.SourceID)
	assert.True(t, resolved[1].Active)
	assert.True(t, resolved[1].ForceAbsent)
	assert.Equal(t, "unselected", resolved[2].Row.SourceID)
	assert.False(t, resolved[2].Active)
	assert.Equal(t, "selected", resolved[3].Row.SourceID)
	assert.True(t, resolved[3].Active)

	effective, err := EffectiveSources(paths)
	require.NoError(t, err)
	require.Len(t, effective, 2)
	assert.Equal(t, []string{"uninstall", "selected"},
		[]string{effective[0].Row.SourceID, effective[1].Row.SourceID})
}
