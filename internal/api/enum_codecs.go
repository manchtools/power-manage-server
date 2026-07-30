package api

import (
	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// Enum codecs between the wire enums and the lowercase strings the events table
// and projection columns store.
//
// These lived in internal_handler.go, which spec 41 deleted with the rest of
// InternalService. They are not gateway-specific — the four rotation-reason
// callers and the LUKS status caller are ordinary device read paths — so they
// move here rather than dying with the proxy that happened to host them.

// rotationReasonFromString decodes the string-typed rotation_reason column
// stored by the events table and projections back into the wire enum. Unknown
// values (including the empty string) collapse to UNSPECIFIED.
//
// The encoding direction lives with whichever handler writes a rotation; it is
// absent right now because the LPS store path has not been rehomed onto the
// agent stream yet, and carrying an unused encoder is dead code.
func rotationReasonFromString(s string) pm.RotationReason {
	switch s {
	case "initial":
		return pm.RotationReason_ROTATION_REASON_INITIAL
	case "scheduled":
		return pm.RotationReason_ROTATION_REASON_SCHEDULED
	case "auth_grace":
		return pm.RotationReason_ROTATION_REASON_AUTH_GRACE
	default:
		return pm.RotationReason_ROTATION_REASON_UNSPECIFIED
	}
}

// luksRevocationStatusFromString decodes the string-typed revocation_status
// column from luks_keys_projection back into the wire enum. Unknown values
// collapse to UNSPECIFIED.
func luksRevocationStatusFromString(s string) pm.LuksRevocationStatus {
	switch s {
	case "none":
		return pm.LuksRevocationStatus_LUKS_REVOCATION_STATUS_NONE
	case "dispatched":
		return pm.LuksRevocationStatus_LUKS_REVOCATION_STATUS_DISPATCHED
	case "success":
		return pm.LuksRevocationStatus_LUKS_REVOCATION_STATUS_SUCCESS
	case "failed":
		return pm.LuksRevocationStatus_LUKS_REVOCATION_STATUS_FAILED
	default:
		return pm.LuksRevocationStatus_LUKS_REVOCATION_STATUS_UNSPECIFIED
	}
}
