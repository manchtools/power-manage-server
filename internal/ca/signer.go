package ca

import "github.com/manchtools/power-manage-sdk/verify"

// ActionSigner is the minimal contract dispatch / inbox handlers need
// to sign action payloads so agents can verify authenticity. Defined
// as an interface (vs the SDK's concrete *verify.ActionSigner) so
// tests can substitute a NoOp implementation without dragging in the
// real CA.
//
// A nil ActionSigner disables signing globally — this is intentional
// for development bootstraps that haven't yet provisioned a CA, and
// is checked at every dispatch site so production handlers fail
// loudly rather than silently produce unsigned actions.
//
// Previously declared independently in internal/api/action_handler.go
// and internal/control/inbox_worker.go; consolidated here so the two
// can't drift.
//
// Sign takes the DETERMINISTIC wire bytes of a pm.SignedActionEnvelope
// (built via verify.MarshalEnvelope) and returns the CA signature over
// those exact bytes. The caller MUST transport the SAME bytes it signed
// (ActionDispatch.envelope) so the agent verifies and unmarshals one
// representation — there is no separate (id, type, paramsJSON) tuple
// any more. See the verify package docs for the full-envelope binding.
type ActionSigner interface {
	Sign(envelopeBytes []byte) ([]byte, error)
	// SignDomain signs a payload under a named signing domain (WS4). Used for
	// the non-action stream-RPC surfaces (osquery, log query, LUKS revoke,
	// inventory): the control server signs the canonical bytes of each
	// dispatch so the agent can verify fail-closed before running it as root.
	// The domain keeps each surface's signatures disjoint from the action
	// envelope and from each other. Backed by verify.(*ActionSigner).SignDomain.
	SignDomain(domain string, payload []byte) ([]byte, error)
}

// NewActionSigner creates a new action signer using the CA's private key.
func NewActionSigner(ca *CA) *verify.ActionSigner {
	return verify.NewActionSigner(ca.Signer())
}
