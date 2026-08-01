package actionparams

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pm "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
)

func TestEveryActionTypeUsesOneParamsRegistry(t *testing.T) {
	require.NotEmpty(t, pm.ActionType_name)
	ok, detail := registryFieldsAreValid(
		&pm.Action{}, &pm.ManagedAction{}, &pm.CreateActionRequest{}, &pm.UpdateActionParamsRequest{},
	)
	require.Truef(t, ok, "registry inconsistent with the contract: %s", detail)

	for value, name := range pm.ActionType_name {
		actionType := pm.ActionType(value)
		t.Run(name, func(t *testing.T) {
			action := &pm.Action{}
			require.NoError(t, PopulateAction(action, value, []byte(`{}`)))
			managed := &pm.ManagedAction{}
			require.NoError(t, PopulateManagedAction(managed, actionType, []byte(`{}`)))

			_, registered := paramsFieldByActionType[actionType]
			if isNoParamsActionType(actionType) {
				assert.False(t, registered)
				assert.Nil(t, action.Params)
				assert.Nil(t, managed.Params)
				assert.Nil(t, ExtractParamsMsg(action))
				assert.False(t, ParamsMatchType(action, actionType))
				return
			}
			require.Truef(t, registered, "classify new action type %s", name)
			actionParams := ExtractParamsMsg(action)
			managedParams := ExtractParamsMsg(managed)
			require.NotNil(t, actionParams)
			require.NotNil(t, managedParams)
			assert.Equal(t, proto.MessageName(actionParams), proto.MessageName(managedParams))
			assert.True(t, ParamsMatchType(action, actionType))
		})
	}
}

func TestParamsMatchType_RejectsMismatchedOneof(t *testing.T) {
	mismatch := &pm.Action{}
	require.NoError(t, PopulateAction(mismatch, int32(pm.ActionType_ACTION_TYPE_SSH), []byte(`{}`)))
	assert.False(t, ParamsMatchType(mismatch, pm.ActionType_ACTION_TYPE_USER))
	assert.True(t, ParamsMatchType(mismatch, pm.ActionType_ACTION_TYPE_SSH))

	empty := &pm.Action{}
	assert.True(t, ParamsMatchType(empty, pm.ActionType_ACTION_TYPE_UPDATE))
	assert.False(t, ParamsMatchType(empty, pm.ActionType_ACTION_TYPE_PACKAGE))
}
