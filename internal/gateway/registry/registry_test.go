package registry

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRegistry_AttachLookupRoundTrip(t *testing.T) {
	r := New(NewFakeBackend(nil), nil)
	ctx := context.Background()

	if err := r.AttachDevice(ctx, "device-1", "gw-A", DefaultDeviceTTL); err != nil {
		t.Fatalf("attach: %v", err)
	}

	got, err := r.LookupDeviceGateway(ctx, "device-1")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got != "gw-A" {
		t.Errorf("device gateway = %q, want gw-A", got)
	}
}

func TestRegistry_DetachDevice(t *testing.T) {
	r := New(NewFakeBackend(nil), nil)
	ctx := context.Background()

	_ = r.AttachDevice(ctx, "device-1", "gw-A", DefaultDeviceTTL)
	if err := r.DetachDevice(ctx, "device-1", "gw-A"); err != nil {
		t.Fatalf("detach: %v", err)
	}

	if _, err := r.LookupDeviceGateway(ctx, "device-1"); !errors.Is(err, ErrNoGateway) {
		t.Errorf("after detach: expected ErrNoGateway, got %v", err)
	}
}

func TestRegistry_DetachDevice_Idempotent(t *testing.T) {
	r := New(NewFakeBackend(nil), nil)
	ctx := context.Background()
	if err := r.DetachDevice(ctx, "never-attached", "gw-A"); err != nil {
		t.Errorf("detach of unknown device should be idempotent, got %v", err)
	}
}

// TestRegistry_ReconnectHandoff verifies that when an agent
// reconnects to a different gateway (gw-B), stale heartbeats and
// disconnects from the old gateway (gw-A) do not overwrite the
// fresh mapping. This is the critical HA correctness test.
func TestRegistry_ReconnectHandoff(t *testing.T) {
	r := New(NewFakeBackend(nil), nil)
	ctx := context.Background()

	// Agent connects to gw-A.
	_ = r.AttachDevice(ctx, "device-1", "gw-A", DefaultDeviceTTL)

	// Agent reconnects to gw-B (overwrites the mapping).
	_ = r.AttachDevice(ctx, "device-1", "gw-B", DefaultDeviceTTL)

	// Stale heartbeat from gw-A arrives — must NOT overwrite gw-B.
	_ = r.RefreshDevice(ctx, "device-1", "gw-A", DefaultDeviceTTL)
	got, err := r.LookupDeviceGateway(ctx, "device-1")
	if err != nil {
		t.Fatalf("lookup after stale refresh: %v", err)
	}
	if got != "gw-B" {
		t.Errorf("after stale refresh: device gateway = %q, want gw-B", got)
	}

	// Stale disconnect from gw-A arrives — must NOT delete gw-B's entry.
	_ = r.DetachDevice(ctx, "device-1", "gw-A")
	got, err = r.LookupDeviceGateway(ctx, "device-1")
	if err != nil {
		t.Fatalf("lookup after stale detach: %v", err)
	}
	if got != "gw-B" {
		t.Errorf("after stale detach: device gateway = %q, want gw-B", got)
	}

	// Clean disconnect from gw-B — SHOULD delete.
	_ = r.DetachDevice(ctx, "device-1", "gw-B")
	if _, err := r.LookupDeviceGateway(ctx, "device-1"); !errors.Is(err, ErrNoGateway) {
		t.Errorf("after owner detach: expected ErrNoGateway, got %v", err)
	}
}

func TestRegistry_LookupDeviceGateway_Unknown(t *testing.T) {
	r := New(NewFakeBackend(nil), nil)
	if _, err := r.LookupDeviceGateway(context.Background(), "no-such-device"); !errors.Is(err, ErrNoGateway) {
		t.Errorf("expected ErrNoGateway, got %v", err)
	}
}

func TestRegistry_LookupGatewayTerminalURL_Unknown(t *testing.T) {
	r := New(NewFakeBackend(nil), nil)
	if _, err := r.LookupGatewayTerminalURL(context.Background(), "no-such-gateway"); !errors.Is(err, ErrNoGateway) {
		t.Errorf("expected ErrNoGateway, got %v", err)
	}
}

func TestRegistry_RegisterGateway_PublishesURL(t *testing.T) {
	r := New(NewFakeBackend(nil), nil)
	ctx := context.Background()

	stop, err := r.RegisterGateway(ctx, "gw-A", "wss://gw-A.example.com/terminal", DefaultGatewayTTL, DefaultGatewayRefreshInterval)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer stop()

	got, err := r.LookupGatewayTerminalURL(ctx, "gw-A")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got != "wss://gw-A.example.com/terminal" {
		t.Errorf("URL = %q, want wss://gw-A.example.com/terminal", got)
	}
}

func TestRegistry_RegisterGateway_StopDeletesEntry(t *testing.T) {
	r := New(NewFakeBackend(nil), nil)
	ctx := context.Background()

	stop, err := r.RegisterGateway(ctx, "gw-A", "wss://gw-A.example.com/terminal", DefaultGatewayTTL, DefaultGatewayRefreshInterval)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	stop()

	if _, err := r.LookupGatewayTerminalURL(ctx, "gw-A"); !errors.Is(err, ErrNoGateway) {
		t.Errorf("after stop: expected ErrNoGateway, got %v", err)
	}
}

func TestRegistry_RegisterGateway_StopIsIdempotent(t *testing.T) {
	r := New(NewFakeBackend(nil), nil)
	stop, err := r.RegisterGateway(context.Background(), "gw-A", "wss://x", DefaultGatewayTTL, DefaultGatewayRefreshInterval)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	stop()
	stop() // must not panic, must not deadlock
}

func TestRegistry_RegisterGateway_RequiresFields(t *testing.T) {
	r := New(NewFakeBackend(nil), nil)
	ctx := context.Background()
	if _, err := r.RegisterGateway(ctx, "", "wss://x", DefaultGatewayTTL, DefaultGatewayRefreshInterval); err == nil {
		t.Error("expected error for empty gatewayID")
	}
	if _, err := r.RegisterGateway(ctx, "gw-A", "", DefaultGatewayTTL, DefaultGatewayRefreshInterval); err == nil {
		t.Error("expected error for empty terminalURL")
	}
}

// TestRegistry_TTLExpiry verifies the FakeBackend's lazy expiry
// matches the contract the production Valkey backend implements via
// native TTL eviction. Uses a frozen clock to advance time
// deterministically without sleeping.
func TestRegistry_TTLExpiry(t *testing.T) {
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	r := New(NewFakeBackend(clock), nil)
	ctx := context.Background()

	if err := r.AttachDevice(ctx, "device-1", "gw-A", 10*time.Second); err != nil {
		t.Fatalf("attach: %v", err)
	}

	// Still alive at t+5s.
	now = now.Add(5 * time.Second)
	if _, err := r.LookupDeviceGateway(ctx, "device-1"); err != nil {
		t.Errorf("lookup at t+5s: %v", err)
	}

	// Refresh extends the lifetime.
	if err := r.RefreshDevice(ctx, "device-1", "gw-A", 10*time.Second); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	now = now.Add(8 * time.Second) // t+13s, but the refresh at t+5 reset the clock
	if _, err := r.LookupDeviceGateway(ctx, "device-1"); err != nil {
		t.Errorf("lookup after refresh at t+13s: %v", err)
	}

	// Past the refreshed expiry: t+5+10+1 = t+16s. The refresh at
	// t+5 set expiry to t+15, so t+16 must be evicted.
	now = now.Add(3 * time.Second) // total t+16s
	if _, err := r.LookupDeviceGateway(ctx, "device-1"); !errors.Is(err, ErrNoGateway) {
		t.Errorf("lookup at t+16s: expected ErrNoGateway, got %v", err)
	}
}

// TestRegistry_RegisterGateway_RefreshLoop verifies that the
// background heartbeat goroutine actually refreshes the entry. Uses
// a counting backend wrapper to observe Set calls.
func TestRegistry_RegisterGateway_RefreshLoop(t *testing.T) {
	counted := &countingBackend{inner: NewFakeBackend(nil)}
	r := New(counted, nil)

	// Use a tight refresh interval so the test runs in milliseconds.
	stop, err := r.RegisterGateway(context.Background(), "gw-A", "wss://x", DefaultGatewayTTL, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Wait for at least 3 refreshes (initial + 2 from the ticker).
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if counted.SetCalls() >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	stop()

	if got := counted.SetCalls(); got < 3 {
		t.Errorf("expected at least 3 Set calls (initial + 2 refreshes), got %d", got)
	}
}

// TestRegistry_AttachDevice_RequiresFields locks the input
// validation contract.
func TestRegistry_AttachDevice_RequiresFields(t *testing.T) {
	r := New(NewFakeBackend(nil), nil)
	ctx := context.Background()
	cases := []struct {
		device, gateway string
	}{
		{"", "gw-A"},
		{"device-1", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if err := r.AttachDevice(ctx, tc.device, tc.gateway, DefaultDeviceTTL); err == nil {
			t.Errorf("AttachDevice(%q, %q): expected error", tc.device, tc.gateway)
		}
	}
}

// countingBackend wraps a Backend and counts Set calls so the
// heartbeat refresh test can observe progress without sleeping
// for the full TTL.
type countingBackend struct {
	inner Backend
	mu    sync.Mutex
	sets  int
}

func (b *countingBackend) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	b.mu.Lock()
	b.sets++
	b.mu.Unlock()
	return b.inner.Set(ctx, key, value, ttl)
}

func (b *countingBackend) Get(ctx context.Context, key string) (string, error) {
	return b.inner.Get(ctx, key)
}

func (b *countingBackend) Delete(ctx context.Context, key string) error {
	return b.inner.Delete(ctx, key)
}

func (b *countingBackend) ScanPrefix(ctx context.Context, prefix string) (map[string]string, error) {
	return b.inner.ScanPrefix(ctx, prefix)
}

func (b *countingBackend) SetCalls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sets
}
