package ca

import "github.com/manchtools/power-manage/sdk/go/verify"

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
type ActionSigner interface {
	Sign(actionID string, actionType int32, paramsJSON []byte) ([]byte, error)
}

// NewActionSigner creates a new action signer using the CA's private key.
func NewActionSigner(ca *CA) *verify.ActionSigner {
	return verify.NewActionSigner(ca.Signer())
}
