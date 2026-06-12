package actionparams

import (
	"fmt"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/go/verify"
)

// EnvelopeSigner is the minimal contract BuildAndSignEnvelope needs: sign
// the deterministic wire bytes of a SignedActionEnvelope and return the CA
// signature. Both ca.ActionSigner and the SDK's *verify.ActionSigner
// satisfy it structurally — declaring it here (rather than importing ca)
// keeps actionparams a leaf package with no server-internal dependencies
// and avoids any import cycle.
type EnvelopeSigner interface {
	Sign(envelopeBytes []byte) ([]byte, error)
}

// BuildAndSignEnvelope is the single signing site shared by every dispatch
// path (api.DispatchAction, api.DispatchInstantAction, the control inbox
// reconnect re-dispatch). It builds a pm.SignedActionEnvelope bound to the
// executing device + execution id, deterministically marshals it
// (verify.MarshalEnvelope), and signs THOSE bytes.
//
// The load-bearing contract: the returned envelopeBytes are the exact bytes
// the signature covers AND the exact bytes the caller must transport
// (ActionDispatchPayload.EnvelopeBytes -> ActionDispatch.envelope). The
// agent verifies the signature over the received bytes and unmarshals THOSE
// SAME bytes to execute — so the executed message is byte-for-byte the
// signed message. Never re-marshal a second envelope to verify or transport:
// a re-marshal can diverge and silently break the full-envelope binding.
//
// Fail-closed: a nil signer, an unhandled/malformed params type, a marshal
// failure, or a sign failure all return an error so no caller ever enqueues
// an unsigned or empty-params task the agent would drop.
func BuildAndSignEnvelope(
	signer EnvelopeSigner,
	executionID string,
	actionType int32,
	paramsJSON []byte,
	desiredState int32,
	timeoutSeconds int32,
	schedule *pm.ActionSchedule,
	deviceID string,
) (envelopeBytes []byte, signature []byte, err error) {
	if signer == nil {
		return nil, nil, fmt.Errorf("actionparams.BuildAndSignEnvelope: nil signer")
	}

	env := &pm.SignedActionEnvelope{
		ActionId:       &pm.ActionId{Value: executionID},
		ActionType:     pm.ActionType(actionType),
		DesiredState:   pm.DesiredState(desiredState),
		TimeoutSeconds: timeoutSeconds,
		Schedule:       schedule,
		TargetDeviceId: deviceID,
	}

	// Bind the typed params into the envelope's oneof. Fail-closed on a
	// parse error or an unhandled type — exactly like PopulateAction, so we
	// never sign an envelope with empty params (#368).
	if err := PopulateEnvelope(env, actionType, paramsJSON); err != nil {
		return nil, nil, fmt.Errorf("actionparams.BuildAndSignEnvelope: populate params (type %d): %w", actionType, err)
	}

	envelopeBytes, err = verify.MarshalEnvelope(env)
	if err != nil {
		return nil, nil, fmt.Errorf("actionparams.BuildAndSignEnvelope: marshal envelope: %w", err)
	}

	signature, err = signer.Sign(envelopeBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("actionparams.BuildAndSignEnvelope: sign envelope: %w", err)
	}

	return envelopeBytes, signature, nil
}
