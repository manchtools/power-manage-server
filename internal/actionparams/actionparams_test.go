package actionparams_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
)

// TestPopulateAction_MalformedParamsReturnsError pins the #368 fix: a protojson
// parse failure surfaces as an error and leaves the oneof unset, rather than
// being swallowed (which let the gateway dispatch an action with empty params).
func TestPopulateAction_MalformedParamsReturnsError(t *testing.T) {
	action := &pm.Action{}
	err := actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_SHELL), []byte("{not valid json"))
	require.Error(t, err)
	assert.Nil(t, action.Params, "params must not be set on a parse error")
}

// TestPopulateAction_UnknownTypeWithParamsReturnsError pins that an action type
// the switch doesn't handle (a new enum value, here a synthetic one) errors
// instead of silently falling through with nil params.
func TestPopulateAction_UnknownTypeWithParamsReturnsError(t *testing.T) {
	action := &pm.Action{}
	err := actionparams.PopulateAction(action, 999999, []byte(`{"x":1}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unhandled action type")
	assert.Nil(t, action.Params)
}

// TestPopulateAction_NoParamsTypesReturnNil pins that the param-less action
// types (REBOOT/SYNC) and the zero value are NOT treated as errors.
func TestPopulateAction_NoParamsTypesReturnNil(t *testing.T) {
	for _, at := range []pm.ActionType{
		pm.ActionType_ACTION_TYPE_UNSPECIFIED,
		pm.ActionType_ACTION_TYPE_REBOOT,
		pm.ActionType_ACTION_TYPE_SYNC,
	} {
		action := &pm.Action{}
		require.NoErrorf(t, actionparams.PopulateAction(action, int32(at), []byte("{}")), "type %s", at)
		assert.Nil(t, action.Params)
	}
}

// TestPopulateAction_EveryActionTypeHandled is self-discovering against the
// generated ActionType enum: every value must either be wired into the switch
// (an empty `{}` parses cleanly for any params message) or classified as
// param-less. A new action type added without a case fails here rather than
// silently dispatching with nil params (#368).
func TestPopulateAction_EveryActionTypeHandled(t *testing.T) {
	require.NotEmpty(t, pm.ActionType_name)
	for v, name := range pm.ActionType_name {
		t.Run(name, func(t *testing.T) {
			action := &pm.Action{}
			require.NoErrorf(t, actionparams.PopulateAction(action, v, []byte("{}")),
				"PopulateAction does not handle %s (%d) — add a case or classify it param-less (#368)", name, v)

			managed := &pm.ManagedAction{}
			require.NoErrorf(t, actionparams.PopulateManagedAction(managed, pm.ActionType(v), []byte("{}")),
				"PopulateManagedAction does not handle %s (%d) — add a case or classify it param-less (#368)", name, v)
		})
	}
}

// TestPopulateManagedAction_MalformedParamsReturnsError mirrors the wire-format
// guard for the API-format path.
func TestPopulateManagedAction_MalformedParamsReturnsError(t *testing.T) {
	action := &pm.ManagedAction{}
	err := actionparams.PopulateManagedAction(action, pm.ActionType_ACTION_TYPE_FILE, []byte("{bad"))
	require.Error(t, err)
	assert.Nil(t, action.Params)
}
