// Package registry tracks which gateway is currently hosting which
// agent connection in a multi-gateway HA deployment, plus the public
// terminal-WebSocket URL for each live gateway.
//
// Both the gateway and the control server use it via a tiny
// SessionBackend interface so handler tests can fake it without
// miniredis. The production wiring uses Valkey via the existing
// *redis.Client both binaries already maintain.
//
// Two key namespaces:
//
//   pm:gateway:terminal:<gateway_id>  → public WebSocket URL
//     Written by each gateway at startup with a TTL, refreshed by
//     a heartbeat goroutine, deleted on clean shutdown. A crashed
//     gateway is invisible within the TTL.
//
//   pm:device:gateway:<device_id>     → gateway_id
//     Written by the gateway when an agent connects, refreshed on
//     each agent heartbeat, deleted on clean disconnect. A crashed
//     agent or gateway is invisible within the TTL.
//
// The control server queries both keys in turn from
// ControlService.StartTerminal so the minted session token carries
// the URL of the specific gateway hosting the device, not a static
// load-balancer URL. See manchtools/power-manage-sdk#16 and
// manchtools/power-manage-server#6.
package registry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Sensible defaults. Callers may override per call.
const (
	// DefaultGatewayTTL is the lifetime of a gateway registration
	// before TTL eviction. The heartbeat refreshes well before this
	// expires.
	DefaultGatewayTTL = 45 * time.Second
	// DefaultGatewayRefreshInterval is how often the heartbeat
	// goroutine refreshes the gateway registration. 3x safety margin
	// against the default TTL.
	DefaultGatewayRefreshInterval = 15 * time.Second
	// DefaultDeviceTTL is the lifetime of a device→gateway mapping.
	// Sized so an agent missing two heartbeats (default 30s) still
	// looks alive, but a third missing heartbeat evicts the entry.
	DefaultDeviceTTL = 90 * time.Second
)

// Errors returned by the Registry. Wrap with %w in callers; check
// with errors.Is.
var (
	// ErrNoGateway is returned by LookupDeviceGateway when the
	// device is not currently registered against any gateway, or
	// by LookupGatewayTerminalURL when the gateway has expired or
	// never registered.
	ErrNoGateway = errors.New("registry: no live gateway for the requested key")
)

// gateway/device key prefixes. Constants kept private so external
// code uses the typed Registry methods rather than building keys
// directly.
const (
	gatewayKeyPrefix = "pm:gateway:terminal:"
	deviceKeyPrefix  = "pm:device:gateway:"
)

func gatewayKey(gatewayID string) string { return gatewayKeyPrefix + gatewayID }
func deviceKey(deviceID string) string   { return deviceKeyPrefix + deviceID }

// Backend is the storage interface the Registry depends on. Two
// implementations ship with this package: ValkeyBackend (production)
// and FakeBackend (tests). Implementations must be safe for
// concurrent use from any goroutine.
type Backend interface {
	// Set stores the value under key with the given TTL. The TTL
	// must be enforced — implementations without native TTL must
	// emulate it via lazy expiry on read.
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	// Get returns the stored value, or ErrNoGateway if the key has
	// expired or was never set.
	Get(ctx context.Context, key string) (string, error)
	// Delete removes the key. Idempotent: missing keys return nil.
	Delete(ctx context.Context, key string) error
}

// Registry is the high-level façade used by gateway and control.
// Wraps a Backend with the gateway/device key conventions and the
// background heartbeat goroutine for gateway registrations.
type Registry struct {
	backend Backend
	logger  *slog.Logger
}

// New constructs a Registry over the supplied backend.
func New(backend Backend, logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.Default()
	}
	return &Registry{backend: backend, logger: logger}
}

// RegisterGateway publishes pm:gateway:terminal:<gatewayID> with
// the supplied terminalURL and TTL, then starts a background
// goroutine that refreshes the TTL every refreshInterval. Returns a
// stop function the caller MUST defer to clean up: stop() deletes
// the key (so no stale entries linger after a clean shutdown) and
// terminates the refresh goroutine.
//
// A non-positive ttl falls back to DefaultGatewayTTL; a non-positive
// refreshInterval falls back to DefaultGatewayRefreshInterval.
func (r *Registry) RegisterGateway(ctx context.Context, gatewayID, terminalURL string, ttl, refreshInterval time.Duration) (stop func(), err error) {
	if gatewayID == "" {
		return nil, errors.New("registry: gatewayID is required")
	}
	if terminalURL == "" {
		return nil, errors.New("registry: terminalURL is required")
	}
	if ttl <= 0 {
		ttl = DefaultGatewayTTL
	}
	if refreshInterval <= 0 {
		refreshInterval = DefaultGatewayRefreshInterval
	}

	// Initial publish so subsequent control lookups can find us
	// immediately, before the first heartbeat tick.
	if err := r.backend.Set(ctx, gatewayKey(gatewayID), terminalURL, ttl); err != nil {
		return nil, fmt.Errorf("registry: initial gateway publish: %w", err)
	}

	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	var stopOnce sync.Once

	go func() {
		defer close(doneCh)
		t := time.NewTicker(refreshInterval)
		defer t.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-t.C:
				// Use a bounded context so a hung backend can't
				// stall the gateway forever. Background context is
				// fine here because the goroutine has its own stop
				// signal.
				refreshCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := r.backend.Set(refreshCtx, gatewayKey(gatewayID), terminalURL, ttl); err != nil {
					r.logger.Warn("registry: gateway heartbeat refresh failed",
						"gateway_id", gatewayID, "error", err)
				}
				cancel()
			}
		}
	}()

	stop = func() {
		stopOnce.Do(func() {
			close(stopCh)
			<-doneCh
			// Best-effort cleanup. A bounded context so shutdown
			// isn't blocked by a flaky backend.
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := r.backend.Delete(cleanupCtx, gatewayKey(gatewayID)); err != nil {
				r.logger.Warn("registry: gateway deregister failed",
					"gateway_id", gatewayID, "error", err)
			}
		})
	}
	return stop, nil
}

// AttachDevice records pm:device:gateway:<deviceID> = <gatewayID>
// with the given TTL. Called by the gateway when a new agent bidi
// stream is established.
func (r *Registry) AttachDevice(ctx context.Context, deviceID, gatewayID string, ttl time.Duration) error {
	if deviceID == "" || gatewayID == "" {
		return errors.New("registry: deviceID and gatewayID are required")
	}
	if ttl <= 0 {
		ttl = DefaultDeviceTTL
	}
	if err := r.backend.Set(ctx, deviceKey(deviceID), gatewayID, ttl); err != nil {
		return fmt.Errorf("registry: attach device: %w", err)
	}
	return nil
}

// RefreshDevice extends the TTL on pm:device:gateway:<deviceID> by
// rewriting the same value. Called from the agent heartbeat handler.
// Refresh is intentionally not atomic with the original Set: a
// refresh on a key that has already expired will succeed and the
// next eviction will be one full TTL away. That matches the desired
// behaviour — a heartbeat means the agent is alive, regardless of
// whether the registry happened to evict in the gap.
func (r *Registry) RefreshDevice(ctx context.Context, deviceID, gatewayID string, ttl time.Duration) error {
	return r.AttachDevice(ctx, deviceID, gatewayID, ttl)
}

// DetachDevice removes pm:device:gateway:<deviceID>. Called on
// clean disconnect. Idempotent.
func (r *Registry) DetachDevice(ctx context.Context, deviceID string) error {
	if deviceID == "" {
		return errors.New("registry: deviceID is required")
	}
	if err := r.backend.Delete(ctx, deviceKey(deviceID)); err != nil {
		return fmt.Errorf("registry: detach device: %w", err)
	}
	return nil
}

// LookupDeviceGateway returns the gatewayID currently hosting the
// given device, or ErrNoGateway if the device is not registered
// against any live gateway.
func (r *Registry) LookupDeviceGateway(ctx context.Context, deviceID string) (string, error) {
	if deviceID == "" {
		return "", errors.New("registry: deviceID is required")
	}
	val, err := r.backend.Get(ctx, deviceKey(deviceID))
	if err != nil {
		if errors.Is(err, ErrNoGateway) {
			return "", ErrNoGateway
		}
		return "", fmt.Errorf("registry: lookup device gateway: %w", err)
	}
	return val, nil
}

// LookupGatewayTerminalURL returns the public terminal WebSocket
// URL for the given gatewayID, or ErrNoGateway if the gateway has
// expired or never registered.
func (r *Registry) LookupGatewayTerminalURL(ctx context.Context, gatewayID string) (string, error) {
	if gatewayID == "" {
		return "", errors.New("registry: gatewayID is required")
	}
	val, err := r.backend.Get(ctx, gatewayKey(gatewayID))
	if err != nil {
		if errors.Is(err, ErrNoGateway) {
			return "", ErrNoGateway
		}
		return "", fmt.Errorf("registry: lookup gateway URL: %w", err)
	}
	return val, nil
}
