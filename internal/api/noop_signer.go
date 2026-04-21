package api

// NoOpSigner is a deterministic test-only ActionSigner that returns
// a fixed dummy signature. It exists so test fixtures can construct
// ActionHandler / SystemActionManager without dragging in the real
// CA, while still satisfying the production contract that the
// signer field is non-nil.
//
// In production the wiring uses the real internal/ca signer; passing
// a nil signer to NewActionHandler / NewSystemActionManager is now a
// hard error (see signAction / signActionByID), which forces every
// new test site to make a deliberate choice rather than silently
// produce unsigned actions in the DB.
type NoOpSigner struct{}

// Sign returns a deterministic dummy signature. The bytes are
// distinguishable from real signatures so an accidental escape into
// production logs is greppable.
func (NoOpSigner) Sign(actionID string, actionType int32, paramsJSON []byte) ([]byte, error) {
	_ = actionID
	_ = actionType
	_ = paramsJSON
	return []byte("noop-test-signature"), nil
}
