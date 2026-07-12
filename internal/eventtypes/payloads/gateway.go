package payloads

// Gateway identity-lifecycle event payloads (spec 31). The stream type is
// "gateway" and the stream id is the gateway_id (the issued cert CN). None of
// these fields is a secret: a certificate fingerprint and a hostname are public
// material, and no private key or bootstrap token is ever stored on the event.

// GatewayEnrolled records a successful self-enrollment: a fresh gateway_id was
// assigned and a per-gateway cert issued. The fingerprint↦gateway_id mapping is
// what revocation later looks up.
type GatewayEnrolled struct {
	// Fingerprint is hex(sha256(cert DER)) of the issued cert — the value
	// added to the CRL on revocation.
	Fingerprint *string `json:"fingerprint,omitempty"`
	// NotAfter is the issued cert's expiry, RFC 3339 (Nano) formatted.
	NotAfter *string `json:"not_after,omitempty"`
	// Hostname is the operator-facing hostname the gateway self-reported.
	// Optional; not trusted for any authorization decision.
	Hostname *string `json:"hostname,omitempty"`
}

// GatewayCertRenewed records a renewal: the same gateway_id got a new cert. The
// fingerprint advances to the new cert; the superseded fingerprint is revoked
// into the CRL by the renewal handler.
type GatewayCertRenewed struct {
	Fingerprint *string `json:"fingerprint,omitempty"`
	NotAfter    *string `json:"not_after,omitempty"`
}

// GatewayRevoked records an operator revoking a gateway's certificate. The
// projection marks the row revoked; the fingerprint is added to the CRL by the
// revoke handler.
type GatewayRevoked struct {
	// Fingerprint of the cert that was revoked, for the audit trail.
	Fingerprint *string `json:"fingerprint,omitempty"`
}
