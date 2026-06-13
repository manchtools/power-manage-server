package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/server/internal/gateway/registry"
)

// verifyDeviceGatewayBinding confines a device-origin InternalService request to
// the gateway the device is actually live on, in the canonical validate-then-auth
// position (called AFTER Validate, before any secret access or event append).
// The binding policy itself lives in registry.CheckDeviceGatewayBinding (shared
// with the control:inbox worker); this method maps its sentinel results to the
// connect codes the gateway client expects. Without it, ANY gateway could read
// or overwrite ANY device's LUKS/LPS secrets and forge device-attributed events
// (server SA-C2).
func (h *InternalHandler) verifyDeviceGatewayBinding(ctx context.Context, deviceID, claimedGatewayID string) error {
	// These binding rejections are returned to the calling GATEWAY (a server
	// component), never to the web client (the browser talks to ControlService,
	// not InternalService), so they map to existing internal error codes rather
	// than dedicated web-localized ones.
	err := registry.CheckDeviceGatewayBinding(ctx, h.deviceGatewayResolver, deviceID, claimedGatewayID)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, registry.ErrBindingGatewayMissing):
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument,
			"gateway_id is required when the device→gateway routing registry is enabled")
	case errors.Is(err, registry.ErrBindingDeviceNotLive):
		return apiErrorCtx(ctx, ErrDeviceNotConnected, connect.CodeFailedPrecondition,
			"device is not live on any gateway")
	case errors.Is(err, registry.ErrBindingMismatch):
		h.logger.Warn("rejecting device-origin request: gateway binding mismatch",
			"device_id", deviceID, "claimed_gateway_id", claimedGatewayID)
		return apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied,
			"device is not live on the calling gateway")
	default:
		h.logger.Error("device→gateway binding lookup failed", "device_id", deviceID, "error", err)
		return apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to resolve device gateway")
	}
}
