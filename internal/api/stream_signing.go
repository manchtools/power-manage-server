package api

import (
	"fmt"

	"github.com/manchtools/power-manage/sdk/go/verify"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// Stream-RPC dispatch signing (WS4). Each helper computes the CA signature over
// the canonical bytes of the dispatch's wire message (payload.ToProto) under
// that surface's disjoint signing domain, then stores it on the payload so the
// gateway can relay it verbatim and the agent verify it fail-closed before
// running the request as root.
//
// Fail-closed-loud: a nil signer is a wiring bug (production wires the real
// internal/ca signer; tests pass NoOpSigner). Each helper returns an error so
// the dispatch refuses rather than enqueueing an unsigned task the agent would
// drop on receipt — the same contract as action dispatch.

func signOSQueryDispatch(signer ca.ActionSigner, p *taskqueue.OSQueryDispatchPayload) error {
	if signer == nil {
		return fmt.Errorf("osquery dispatch: nil signer")
	}
	canonical, err := verify.OSQueryCanonical(p.ToProto())
	if err != nil {
		return fmt.Errorf("osquery dispatch: canonical: %w", err)
	}
	sig, err := signer.SignDomain(verify.OSQuerySignatureDomain, canonical)
	if err != nil {
		return fmt.Errorf("osquery dispatch: sign: %w", err)
	}
	p.Signature = sig
	return nil
}

func signLogQueryDispatch(signer ca.ActionSigner, p *taskqueue.LogQueryDispatchPayload) error {
	if signer == nil {
		return fmt.Errorf("log query dispatch: nil signer")
	}
	canonical, err := verify.LogQueryCanonical(p.ToProto())
	if err != nil {
		return fmt.Errorf("log query dispatch: canonical: %w", err)
	}
	sig, err := signer.SignDomain(verify.LogQuerySignatureDomain, canonical)
	if err != nil {
		return fmt.Errorf("log query dispatch: sign: %w", err)
	}
	p.Signature = sig
	return nil
}

func signInventoryRequest(signer ca.ActionSigner, p *taskqueue.InventoryRequestPayload) error {
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

func signRevokeLuksDeviceKey(signer ca.ActionSigner, p *taskqueue.RevokeLuksDeviceKeyPayload) error {
	if signer == nil {
		return fmt.Errorf("luks revoke dispatch: nil signer")
	}
	canonical, err := verify.RevokeLuksDeviceKeyCanonical(p.ToProto())
	if err != nil {
		return fmt.Errorf("luks revoke dispatch: canonical: %w", err)
	}
	sig, err := signer.SignDomain(verify.LuksRevokeSignatureDomain, canonical)
	if err != nil {
		return fmt.Errorf("luks revoke dispatch: sign: %w", err)
	}
	p.Signature = sig
	return nil
}
