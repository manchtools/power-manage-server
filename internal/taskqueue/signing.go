package taskqueue

import (
	"fmt"

	"github.com/manchtools/power-manage-sdk/verify"
	"github.com/manchtools/power-manage/server/internal/ca"
)

// SignInventoryRequest computes the CA signature over the canonical
// RequestInventory bytes under verify.InventorySignatureDomain (WS4)
// and stores it on the payload. Shared by the manual
// RefreshDeviceInventory RPC and the spec-22 inventory scheduler so
// both emit byte-identical signed requests.
//
// Fail-closed-loud: a nil signer is a wiring bug — return an error so
// the dispatch refuses rather than enqueueing an unsigned task the
// agent would drop on receipt.
func SignInventoryRequest(signer ca.ActionSigner, p *InventoryRequestPayload) error {
	if signer == nil {
		return fmt.Errorf("inventory request: nil signer")
	}
	canonical, err := verify.RequestInventoryCanonical(p.ToProto())
	if err != nil {
		return fmt.Errorf("inventory request: canonical: %w", err)
	}
	sig, err := signer.SignDomain(verify.InventorySignatureDomain, canonical)
	if err != nil {
		return fmt.Errorf("inventory request: sign: %w", err)
	}
	p.Signature = sig
	return nil
}
