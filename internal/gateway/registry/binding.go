package registry

import (
	"context"
	"errors"
	"fmt"
)

// DeviceGatewayLookup is the one-method view of the registry the
// device→gateway binding check needs. *Registry satisfies it; tests inject a
// real registry over a fake backend. Kept narrow so consumers (the
// InternalService handlers and the control:inbox worker) don't depend on the
// full registry surface.
type DeviceGatewayLookup interface {
	LookupDeviceGateway(ctx context.Context, deviceID string) (string, error)
}

// Sentinel results of CheckDeviceGatewayBinding. Callers map these to their own
// protocol: the InternalService handlers to connect codes
// (InvalidArgument / FailedPrecondition / PermissionDenied), the control:inbox
// worker to a SkipRetry-wrapped drop. Check with errors.Is.
var (
	// ErrBindingGatewayMissing: a resolver is wired but the request/event
	// carried no gateway_id, so it cannot be bound. Reject (InvalidArgument).
	ErrBindingGatewayMissing = errors.New("registry: gateway_id is required for the device→gateway binding")
	// ErrBindingDeviceNotLive: the device is not live on any gateway, so the
	// binding cannot be confirmed. Fail closed (FailedPrecondition), never
	// allow-on-unknown — that is the bypass an attacker wants.
	ErrBindingDeviceNotLive = errors.New("registry: device is not live on any gateway")
	// ErrBindingMismatch: the calling gateway is not the one the device is live
	// on — a compromised/confused gateway reaching for another device's secrets
	// or forging its events. Reject (PermissionDenied).
	ErrBindingMismatch = errors.New("registry: device is not live on the calling gateway")
)

// CheckDeviceGatewayBinding confines a device-origin operation to the gateway
// the device is actually live on. The gateway peer-class mTLS cert is shared
// and carries no per-gateway identity, so the operation self-asserts
// claimedGatewayID and this cross-references it against the device→gateway
// routing binding the agent's own mTLS-authenticated heartbeat wrote into the
// registry. It is the single source of the binding policy, shared by the
// InternalService handlers and the control:inbox worker.
//
// Fail-closed:
//   - lookup nil → error. There is no deployment without the registry (Valkey —
//     and with it the registry — is mandatory for any gateway to function), so a
//     nil resolver is a wiring bug, and a security check must fail closed on a
//     wiring bug, never open (spec 31 D6 — the former allow-on-nil was the
//     bypass an accidental unwiring would silently grant).
//   - claimedGatewayID empty → ErrBindingGatewayMissing.
//   - ErrNoGateway → ErrBindingDeviceNotLive (never allow when we can't tell).
//   - actual ≠ claimed → ErrBindingMismatch.
func CheckDeviceGatewayBinding(ctx context.Context, lookup DeviceGatewayLookup, deviceID, claimedGatewayID string) error {
	if lookup == nil {
		return errors.New("registry: no device→gateway resolver wired — refusing the device-origin operation (fail closed)")
	}
	if claimedGatewayID == "" {
		return ErrBindingGatewayMissing
	}
	actualGatewayID, err := lookup.LookupDeviceGateway(ctx, deviceID)
	if err != nil {
		if errors.Is(err, ErrNoGateway) {
			return ErrBindingDeviceNotLive
		}
		return fmt.Errorf("registry: device→gateway binding lookup failed: %w", err)
	}
	if actualGatewayID != claimedGatewayID {
		return ErrBindingMismatch
	}
	return nil
}
