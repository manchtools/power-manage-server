package actionparams_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
)

func TestPopulateAction_RejectsMalformedParams(t *testing.T) {
	action := &pm.Action{}
	err := actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_SHELL), []byte("{not valid json"))
	require.Error(t, err)
	assert.Nil(t, action.Params)
}

func TestPopulateAction_RejectsUnknownParams(t *testing.T) {
	action := &pm.Action{}
	err := actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_SHELL), []byte(`{"unexpected":true}`))
	require.Error(t, err)
	assert.Nil(t, action.Params)
}

func TestPopulateAction_RejectsUnknownType(t *testing.T) {
	action := &pm.Action{}
	err := actionparams.PopulateAction(action, 999999, []byte(`{"x":1}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unhandled action type")
	assert.Nil(t, action.Params)
}

func TestPopulateAction_NoParamsTypesRemainEmpty(t *testing.T) {
	for _, actionType := range []pm.ActionType{
		pm.ActionType_ACTION_TYPE_UNSPECIFIED,
		pm.ActionType_ACTION_TYPE_REBOOT,
		pm.ActionType_ACTION_TYPE_SYNC,
	} {
		action := &pm.Action{}
		require.NoError(t, actionparams.PopulateAction(action, int32(actionType), []byte(`{}`)))
		assert.Nil(t, action.Params)
	}
}

func TestPopulateAction_EveryContractTypeIsClassified(t *testing.T) {
	require.NotEmpty(t, pm.ActionType_name)
	for value, name := range pm.ActionType_name {
		t.Run(name, func(t *testing.T) {
			action := &pm.Action{}
			require.NoErrorf(t, actionparams.PopulateAction(action, value, []byte(`{}`)),
				"classify new action type %s", name)
			managed := &pm.ManagedAction{}
			require.NoErrorf(t, actionparams.PopulateManagedAction(managed, pm.ActionType(value), []byte(`{}`)),
				"classify new managed action type %s", name)
		})
	}
}

func TestPopulateManagedAction_RejectsMalformedParams(t *testing.T) {
	action := &pm.ManagedAction{}
	err := actionparams.PopulateManagedAction(action, pm.ActionType_ACTION_TYPE_FILE, []byte("{bad"))
	require.Error(t, err)
	assert.Nil(t, action.Params)
}
