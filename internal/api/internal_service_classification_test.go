package api_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// nonDeviceScopedInternalRPCs lists the InternalService methods whose requests
// do NOT carry a device_id and so are intentionally not device-origin-bound.
// They are gated by the InternalService mTLS peer-class listener plus their own
// session-ownership/scope checks rather than by the device→gateway registry.
// Each entry is justified; the test below fails the build if an entry no longer
// resolves to a real method (stale), or if a new InternalService method appears
// that is neither device-bound nor listed here.
var nonDeviceScopedInternalRPCs = map[string]string{
	"ProxyValidateTerminalToken": "keyed by session_id+token and validated against the session, not a device origin",
	"RenewGatewayCertificate":    "gateway-scoped, not device-scoped: gateway_id is read from the authenticated peer cert CN (spec 31), and proof-of-possession is checked against the presented cert — no device_id involved",
}

// TestEveryInternalServiceRPCIsClassified pins that EVERY InternalService RPC is
// consciously classified into exactly one of:
//
//   - device-origin-bound: its request carries device_id and so is covered by
//     the gateway-binding completeness guard
//     (TestInternalHandlers_GatewayBindingIsSelfDiscovering); or
//   - non-device-scoped: explicitly listed in nonDeviceScopedInternalRPCs with a
//     justification (gated by the peer-class mTLS listener + session ownership).
//
// A newly-added InternalService RPC that is neither device-bound nor listed
// fails here, forcing the author to decide its gating rather than silently
// shipping an unclassified credential-bearing endpoint. This is the
// InternalService counterpart to the ControlService classification enforced by
// internal/auth/permissions_parity_test.go (WS0 / WS2), closing the gap that the
// ControlService parity test did not cover the InternalService surface.
func TestEveryInternalServiceRPCIsClassified(t *testing.T) {
	svc := pm.File_pm_v1_internal_proto.Services().ByName("InternalService")
	require.NotNil(t, svc, "InternalService descriptor must resolve")
	methods := svc.Methods()
	require.NotZero(t, methods.Len(), "matches-zero guard: no InternalService methods discovered — the descriptor walk is dead")

	seenNonDevice := map[string]bool{}
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		name := string(m.Name())
		deviceBound := m.Input().Fields().ByName("device_id") != nil
		_, listedNonDevice := nonDeviceScopedInternalRPCs[name]

		switch {
		case deviceBound && listedNonDevice:
			t.Errorf("InternalService.%s is both device-bound (request carries device_id) and listed in nonDeviceScopedInternalRPCs — remove the allowlist entry", name)
		case !deviceBound && !listedNonDevice:
			t.Errorf("InternalService.%s is UNCLASSIFIED: its request has no device_id (so the device-origin binding guard cannot cover it) and it is not in nonDeviceScopedInternalRPCs.\n  Either add a device_id binding + a case in TestInternalHandlers_GatewayBindingIsSelfDiscovering, or add a justified entry to nonDeviceScopedInternalRPCs.", name)
		case listedNonDevice:
			seenNonDevice[name] = true
		}
	}

	// No-stale-entry guard: every allowlisted non-device-scoped RPC must still
	// resolve to a real method, or the allowlist has rotted open.
	for name := range nonDeviceScopedInternalRPCs {
		if !seenNonDevice[name] {
			t.Errorf("stale nonDeviceScopedInternalRPCs entry %q no longer resolves to an InternalService method (remove it)", name)
		}
	}
}
