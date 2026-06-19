package actionparams_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
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

// =============================================================================
// PopulateEnvelope — the signed/transported representation
// =============================================================================
//
// Contract restated: PopulateEnvelope unmarshals params JSON into a
// SignedActionEnvelope's oneof, mirroring PopulateAction exactly. It MUST:
//   - set the typed oneof for every params-carrying ACTION_TYPE_* (correct),
//   - leave the oneof unset and return nil for the param-less types
//     (REBOOT/SYNC/UNSPECIFIED) — present-but-empty is fine,
//   - reject malformed JSON (present-but-wrong),
//   - reject an unhandled type (absent case) rather than silently no-op.
// The rejection paths are the point: a swallowed error would let the dispatch
// signer sign (and transport) an envelope with empty params (#368).

// TestPopulateEnvelope_MalformedParamsReturnsError pins that a protojson parse
// failure surfaces as an error and leaves the oneof unset.
func TestPopulateEnvelope_MalformedParamsReturnsError(t *testing.T) {
	env := &pm.SignedActionEnvelope{}
	err := actionparams.PopulateEnvelope(env, int32(pm.ActionType_ACTION_TYPE_SHELL), []byte("{not valid json"))
	require.Error(t, err)
	assert.Nil(t, env.Params, "params oneof must not be set on a parse error")
}

// TestPopulateEnvelope_UnknownTypeWithParamsReturnsError pins that an action
// type the switch doesn't handle errors rather than falling through with nil
// params. "Wrong" type (999999) is sourced from the design rule "every
// dispatched type must be wired", NOT from the switch itself.
func TestPopulateEnvelope_UnknownTypeWithParamsReturnsError(t *testing.T) {
	env := &pm.SignedActionEnvelope{}
	err := actionparams.PopulateEnvelope(env, 999999, []byte(`{"x":1}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unhandled action type")
	assert.Nil(t, env.Params)
}

// TestPopulateEnvelope_NoParamsTypesReturnNil pins that the param-less action
// types (REBOOT/SYNC) and the zero value leave the oneof unset without error —
// instant actions legitimately carry no params.
func TestPopulateEnvelope_NoParamsTypesReturnNil(t *testing.T) {
	for _, at := range []pm.ActionType{
		pm.ActionType_ACTION_TYPE_UNSPECIFIED,
		pm.ActionType_ACTION_TYPE_REBOOT,
		pm.ActionType_ACTION_TYPE_SYNC,
	} {
		env := &pm.SignedActionEnvelope{}
		require.NoErrorf(t, actionparams.PopulateEnvelope(env, int32(at), []byte("{}")), "type %s", at)
		assert.Nil(t, env.Params, "param-less type %s must leave the oneof unset", at)
	}
}

// TestPopulateEnvelope_EveryActionTypeHandled is self-discovering against the
// generated ActionType enum: every value must either be wired into the
// envelope switch or classified as param-less. A new action type added to
// PopulateAction but forgotten in PopulateEnvelope fails HERE — closing the
// "the two switches drifted" gap until the reflection collapse lands. Guards
// against matching zero by requiring a non-empty enum map.
func TestPopulateEnvelope_EveryActionTypeHandled(t *testing.T) {
	require.NotEmpty(t, pm.ActionType_name)
	for v, name := range pm.ActionType_name {
		t.Run(name, func(t *testing.T) {
			env := &pm.SignedActionEnvelope{}
			require.NoErrorf(t, actionparams.PopulateEnvelope(env, v, []byte("{}")),
				"PopulateEnvelope does not handle %s (%d) — add a case or classify it param-less (drift vs PopulateAction)", name, v)
		})
	}
}

// TestPopulateEnvelope_SetsTypedParams pins that a representative params-carrying
// type lands its fields in the envelope's oneof (not just "no error").
func TestPopulateEnvelope_SetsTypedParams(t *testing.T) {
	env := &pm.SignedActionEnvelope{}
	require.NoError(t, actionparams.PopulateEnvelope(env, int32(pm.ActionType_ACTION_TYPE_SHELL), []byte(`{"script":"echo hi","runAsRoot":true}`)))
	require.NotNil(t, env.GetShell())
	assert.Equal(t, "echo hi", env.GetShell().Script)
	assert.True(t, env.GetShell().RunAsRoot)
}

// =============================================================================
// BuildAndSignEnvelope — the single dispatch signing site
// =============================================================================

// recordingEnvelopeSigner captures the exact bytes it was asked to sign so a
// test can prove the signer signs the SAME bytes BuildAndSignEnvelope returns
// (the load-bearing "sign == transport" invariant). It returns a deterministic
// fixed signature.
type recordingEnvelopeSigner struct {
	signed [][]byte
}

func (r *recordingEnvelopeSigner) Sign(envelopeBytes []byte) ([]byte, error) {
	r.signed = append(r.signed, append([]byte(nil), envelopeBytes...))
	return []byte("recorded-sig"), nil
}

// TestBuildAndSignEnvelope_SignsExactTransportedBytes pins the core invariant:
// the bytes handed to the signer are byte-for-byte the envelopeBytes returned
// for transport, AND they deterministically decode to the envelope built from
// the inputs (id/type/desired_state/timeout/device/params all bound).
func TestBuildAndSignEnvelope_SignsExactTransportedBytes(t *testing.T) {
	signer := &recordingEnvelopeSigner{}
	envBytes, sig, err := actionparams.BuildAndSignEnvelope(
		signer,
		"exec-123",
		int32(pm.ActionType_ACTION_TYPE_SHELL),
		[]byte(`{"script":"echo hi"}`),
		int32(pm.DesiredState_DESIRED_STATE_ABSENT),
		420,
		nil,
		"device-xyz",
	)
	require.NoError(t, err)
	assert.Equal(t, []byte("recorded-sig"), sig)

	require.Len(t, signer.signed, 1, "signer must be called exactly once")
	assert.Equal(t, envBytes, signer.signed[0],
		"the bytes signed MUST equal the bytes transported — never re-marshal a second envelope")

	// The transported bytes decode to the bound envelope.
	var env pm.SignedActionEnvelope
	require.NoError(t, proto.Unmarshal(envBytes, &env))
	assert.Equal(t, "exec-123", env.GetActionId().GetValue())
	assert.Equal(t, pm.ActionType_ACTION_TYPE_SHELL, env.GetActionType())
	assert.Equal(t, pm.DesiredState_DESIRED_STATE_ABSENT, env.GetDesiredState())
	assert.Equal(t, int32(420), env.GetTimeoutSeconds())
	assert.Equal(t, "device-xyz", env.GetTargetDeviceId())
	require.NotNil(t, env.GetShell())
	assert.Equal(t, "echo hi", env.GetShell().Script)
}

// TestBuildAndSignEnvelope_NilSignerRejected pins fail-closed on a nil signer —
// a wiring bug must not produce an unsigned envelope.
func TestBuildAndSignEnvelope_NilSignerRejected(t *testing.T) {
	_, _, err := actionparams.BuildAndSignEnvelope(
		nil, "e", int32(pm.ActionType_ACTION_TYPE_SHELL), []byte("{}"), 0, 1, nil, "d")
	require.Error(t, err)
}

// TestBuildAndSignEnvelope_MalformedParamsRejected pins that a params parse
// failure aborts BEFORE signing — we must never sign/transport empty params.
func TestBuildAndSignEnvelope_MalformedParamsRejected(t *testing.T) {
	signer := &recordingEnvelopeSigner{}
	_, _, err := actionparams.BuildAndSignEnvelope(
		signer, "e", int32(pm.ActionType_ACTION_TYPE_SHELL), []byte("{bad"), 0, 1, nil, "d")
	require.Error(t, err)
	assert.Empty(t, signer.signed, "signer must NOT be called when params fail to parse")
}

// TestBuildAndSignEnvelope_UnhandledTypeRejected pins that an unhandled type
// aborts before signing (absent-case rejection).
func TestBuildAndSignEnvelope_UnhandledTypeRejected(t *testing.T) {
	signer := &recordingEnvelopeSigner{}
	_, _, err := actionparams.BuildAndSignEnvelope(
		signer, "e", 999999, []byte(`{"x":1}`), 0, 1, nil, "d")
	require.Error(t, err)
	assert.Empty(t, signer.signed, "signer must NOT be called for an unhandled type")
}
