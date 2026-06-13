package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/server/internal/gateway/registry"
)

// DeviceGatewayResolver resolves which gateway a device is currently live on.
// *registry.Registry satisfies it; tests inject a fake. Kept as a one-method
// interface so the api package does not depend on the full registry surface.
type DeviceGatewayResolver interface {
	LookupDeviceGateway(ctx context.Context, deviceID string) (string, error)
}

// verifyDeviceGatewayBinding confines a device-origin InternalService request to
// the gateway the device is actually live on. The gateway peer-class mTLS cert
// is shared and carries no per-gateway identity, so control cannot trust the
// transport to tell it which gateway is calling; instead the request
// self-asserts claimedGatewayID and this check cross-references it against the
// device→gateway routing binding the agent's own mTLS-authenticated heartbeat
// wrote into the registry. Without it, ANY gateway could read or overwrite ANY
// device's LUKS/LPS secrets and forge device-attributed events (server SA-C2).
//
// Fail-closed, in the canonical validate-then-auth position (called AFTER
// Validate, before any secret access or event append):
//
//   - resolver nil  → allow. The single-gateway / non-HA exception: the routing
//     registry is only wired in multi-gateway compose, so a nil resolver means
//     "there is exactly one gateway, binding is moot." Documented in the ADR;
//     the resolver MUST be wired wherever more than one gateway can connect.
//   - claimedGatewayID empty → reject InvalidArgument. A resolver is wired, so a
//     request that omits its gateway_id cannot be bound and must not proceed.
//   - ErrNoGateway (device live on no gateway) → reject FailedPrecondition. Never
//     "allow because we can't tell" — that is the whole bypass an attacker wants.
//   - lookup ≠ claimed → reject PermissionDenied. The calling gateway is not the
//     one the device is live on.
func (h *InternalHandler) verifyDeviceGatewayBinding(ctx context.Context, deviceID, claimedGatewayID string) error {
	if h.deviceGatewayResolver == nil {
		return nil // single-gateway / non-HA: binding not enforced (documented)
	}
	if claimedGatewayID == "" {
		return apiErrorCtx(ctx, ErrGatewayDeviceBindingUnknown, connect.CodeInvalidArgument,
			"gateway_id is required when the device→gateway routing registry is enabled")
	}
	actualGatewayID, err := h.deviceGatewayResolver.LookupDeviceGateway(ctx, deviceID)
	if err != nil {
		if errors.Is(err, registry.ErrNoGateway) {
			// Fail-closed: the device is not live on any gateway, so the binding
			// cannot be confirmed. Rejecting (not allowing) is the point.
			return apiErrorCtx(ctx, ErrGatewayDeviceBindingUnknown, connect.CodeFailedPrecondition,
				"device is not live on any gateway")
		}
		h.logger.Error("device→gateway binding lookup failed", "device_id", deviceID, "error", err)
		return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to resolve device gateway")
	}
	if actualGatewayID != claimedGatewayID {
		h.logger.Warn("rejecting device-origin request: gateway binding mismatch",
			"device_id", deviceID, "claimed_gateway_id", claimedGatewayID, "actual_gateway_id", actualGatewayID)
		return apiErrorCtx(ctx, ErrGatewayDeviceBindingMismatch, connect.CodePermissionDenied,
			"device is not live on the calling gateway")
	}
	return nil
}
