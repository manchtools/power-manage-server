package actionparams

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// TestEveryActionTypeHandledInEveryParamsSwitch is the fitness function that
// guards the proto-reflection collapse (#401 / WS1b#1): the single registry
// paramsFieldByActionType replaced six hand-maintained ActionType→params-message
// switch tables. It pins, self-discovering against the generated enum, that:
//
//   - every params-carrying ActionType has a registry entry (and param-less
//     types do NOT) — a new ACTION_TYPE_* fails here until wired;
//   - the registry's field names are valid against the live proto descriptors
//     of all five params-bearing messages (a proto rename / typo is caught);
//   - populating Action, SignedActionEnvelope, and ManagedAction from the same
//     ActionType lands the SAME params message type in each (no cross-message
//     drift — the exact bug the collapse removes);
//   - ExtractParamsMsg (the inverse walk) and ParamsMatchType agree with the
//     populated oneof.
//
// require.NotEmpty(ActionType_name) is the matches-zero guard so the check can
// never pass vacuously.
func TestEveryActionTypeHandledInEveryParamsSwitch(t *testing.T) {
	require.NotEmpty(t, pm.ActionType_name, "enum enumeration is empty — the self-discovering check would pass vacuously")

	// The registry field names must exist, be message fields, and live in the
	// `params` oneof of every params-bearing message. Catches a proto rename or
	// a registry typo structurally rather than via a silent mis-route.
	ok, detail := registryFieldsAreValid(
		&pm.Action{}, &pm.SignedActionEnvelope{}, &pm.ManagedAction{},
		&pm.CreateActionRequest{}, &pm.UpdateActionParamsRequest{},
	)
	require.Truef(t, ok, "registry inconsistent with proto descriptors: %s", detail)

	for v, name := range pm.ActionType_name {
		at := pm.ActionType(v)
		t.Run(name, func(t *testing.T) {
			// Every type populates all three target messages from `{}` cleanly
			// (or is fail-closed param-less) — no per-message switch can miss one.
			action := &pm.Action{}
			require.NoErrorf(t, PopulateAction(action, v, []byte("{}")),
				"PopulateAction missing %s — add a registry entry or classify it param-less", name)
			env := &pm.SignedActionEnvelope{}
			require.NoErrorf(t, PopulateEnvelope(env, v, []byte("{}")),
				"PopulateEnvelope missing %s", name)
			managed := &pm.ManagedAction{}
			require.NoErrorf(t, PopulateManagedAction(managed, at, []byte("{}")),
				"PopulateManagedAction missing %s", name)

			_, inRegistry := paramsFieldByActionType[at]

			if isNoParamsActionType(at) {
				assert.False(t, inRegistry, "param-less type %s must NOT be in the params registry", name)
				assert.Nil(t, action.Params, "param-less type %s must leave the Action oneof unset", name)
				assert.Nil(t, env.Params, "param-less type %s must leave the Envelope oneof unset", name)
				assert.Nil(t, managed.Params, "param-less type %s must leave the ManagedAction oneof unset", name)
				assert.Nil(t, ExtractParamsMsg(action), "param-less type %s must extract nil", name)
				assert.False(t, ParamsMatchType(action, at), "param-less type %s must not match a populated oneof", name)
				return
			}

			require.Truef(t, inRegistry,
				"params-carrying type %s is absent from the registry — add an entry or classify it param-less", name)

			// The populated oneof is set on all three messages...
			am := ExtractParamsMsg(action)
			em := ExtractParamsMsg(env)
			mm := ExtractParamsMsg(managed)
			require.NotNilf(t, am, "Action params oneof unset for %s", name)
			require.NotNilf(t, em, "SignedActionEnvelope params oneof unset for %s", name)
			require.NotNilf(t, mm, "ManagedAction params oneof unset for %s", name)

			// ...and resolves to the SAME params message type in each — the
			// cross-message drift the collapse exists to make impossible.
			assert.Equalf(t, proto.MessageName(am), proto.MessageName(em),
				"%s: Action vs SignedActionEnvelope params type drift", name)
			assert.Equalf(t, proto.MessageName(am), proto.MessageName(mm),
				"%s: Action vs ManagedAction params type drift", name)

			// The type-match guard agrees the populated oneof matches the type.
			assert.Truef(t, ParamsMatchType(action, at), "ParamsMatchType disagrees for %s", name)
		})
	}
}

// TestParamsMatchType_RejectsMismatchAndUpdateNil pins the two non-obvious arms
// of the reflection-based type guard that the old switch encoded by hand:
//   - a populated oneof that does NOT match the declared type is rejected
//     (the Type=USER-carrying-Ssh-oneof corruption the guard exists to stop);
//   - ACTION_TYPE_UPDATE uniquely matches an UNSET oneof (an update with no
//     params is legitimate), while every other type does not.
func TestParamsMatchType_RejectsMismatchAndUpdateNil(t *testing.T) {
	// present-but-WRONG: USER type declared, Ssh oneof populated → reject.
	mismatch := &pm.Action{}
	require.NoError(t, PopulateAction(mismatch, int32(pm.ActionType_ACTION_TYPE_SSH), []byte("{}")))
	assert.False(t, ParamsMatchType(mismatch, pm.ActionType_ACTION_TYPE_USER),
		"a USER action carrying an Ssh oneof must not match")
	assert.True(t, ParamsMatchType(mismatch, pm.ActionType_ACTION_TYPE_SSH),
		"an Ssh action carrying an Ssh oneof must match")

	// UPDATE matches an unset oneof; PACKAGE (a params type) does not.
	empty := &pm.Action{}
	assert.True(t, ParamsMatchType(empty, pm.ActionType_ACTION_TYPE_UPDATE),
		"ACTION_TYPE_UPDATE must match an unset params oneof")
	assert.False(t, ParamsMatchType(empty, pm.ActionType_ACTION_TYPE_PACKAGE),
		"ACTION_TYPE_PACKAGE must NOT match an unset params oneof")
}
