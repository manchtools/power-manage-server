package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// ActionSigner signs action payloads using the CA's private key.
// This ensures agents can verify actions originated from the control server.
type ActionSigner struct {
	key crypto.Signer
}

// NewActionSigner creates a new action signer using the CA's private key.
func NewActionSigner(ca *CA) *ActionSigner {
	return &ActionSigner{key: ca.Signer()}
}

// Sign produces a signature over the canonical action payload.
// The canonical format is: "actionID:actionType:base64(paramsJSON)"
//
// Uses the crypto.Signer interface so any key implementation works,
// including HSM-backed keys via PKCS#11.
func (s *ActionSigner) Sign(actionID string, actionType int32, paramsJSON []byte) ([]byte, error) {
	canonical := fmt.Sprintf("%s:%d:%s", actionID, actionType,
		base64.StdEncoding.EncodeToString(paramsJSON))
	hash := sha256.Sum256([]byte(canonical))

	return s.key.Sign(rand.Reader, hash[:], crypto.SHA256)
}
