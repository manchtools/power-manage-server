package api

// This file's `_test.go` suffix means it compiles ONLY during
// `go test`. Production builds do not link NoOpSigner at all — a
// handler that tried to `api.NoOpSigner{}` in non-test code would
// fail to build, closing the "footgun" a reviewer flagged when
// NoOpSigner lived in a regular source file.
//
// NoOpSigner is still in `package api` (not `api_test`) so external
// test files (`package api_test`) can reference `api.NoOpSigner{}`
// the same way they reference any other exported type.

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
