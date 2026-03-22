package ca

import "github.com/manchtools/power-manage/sdk/go/verify"

// NewActionSigner creates a new action signer using the CA's private key.
func NewActionSigner(ca *CA) *verify.ActionSigner {
	return verify.NewActionSigner(ca.Signer())
}
