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

// TestRegistry_RegisterGateway_InitialPublishFailureRecovers is the
// regression lock for #524: a gateway that (re)starts during a transient
// Valkey outage must NOT lose terminal sessions until an operator restarts
// it. RegisterGateway's refresh loop IS the retry mechanism — a failed
// initial publish starts it anyway, and the key appears on the first tick
// after the backend recovers. Observed in production 2026-07-04→09: a
// Valkey blip at gateway startup left StartTerminal dead for five days
// while the internal-URL and Traefik registrations (which retry) recovered
// on their own.
func TestRegistry_RegisterGateway_InitialPublishFailureRecovers(t *testing.T) {
	flaky := &flakyBackend{inner: NewFakeBackend(nil), failFirst: 2}
	r := New(flaky, nil)

	stop, err := r.RegisterGateway(context.Background(), "gw-A", "wss://x", DefaultGatewayTTL, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("a transient initial-publish failure must not disable registration (fail-open into the refresh loop): %v", err)
	}
	defer stop()

	// The key must appear once the backend recovers — within a few ticks.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got, gErr := r.LookupGatewayTerminalURL(context.Background(), "gw-A"); gErr == nil && got == "wss://x" {
			return // recovered
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("terminal URL never appeared after the backend recovered — the refresh loop is not retrying the failed initial publish")
}

// TestRegistry_RegisterGateway_ValidationErrorsStillFail pins the split:
// config/validation errors (empty id/url, refresh >= ttl) must STILL return
// an error — only the transient publish failure is fail-open.
func TestRegistry_RegisterGateway_ValidationErrorsStillFail(t *testing.T) {
	r := New(&flakyBackend{inner: NewFakeBackend(nil), failFirst: 1}, nil)
	if _, err := r.RegisterGateway(context.Background(), "", "wss://x", DefaultGatewayTTL, DefaultGatewayRefreshInterval); err == nil {
		t.Error("empty gatewayID must error")
	}
	if _, err := r.RegisterGateway(context.Background(), "gw-A", "", DefaultGatewayTTL, DefaultGatewayRefreshInterval); err == nil {
		t.Error("empty terminalURL must error")
	}
	if _, err := r.RegisterGateway(context.Background(), "gw-A", "wss://x", time.Second, time.Second); err == nil {
		t.Error("refreshInterval >= ttl must error")
	}
}

// flakyBackend fails the first failFirst Set calls, then delegates —
// simulating a Valkey outage window at gateway startup.
type flakyBackend struct {
	inner     Backend
	mu        sync.Mutex
	failFirst int
	setCalls  int
}

func (b *flakyBackend) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	b.mu.Lock()
	b.setCalls++
	failing := b.setCalls <= b.failFirst
	b.mu.Unlock()
	if failing {
		return errors.New("dial tcp: connect: connection refused")
	}
	return b.inner.Set(ctx, key, value, ttl)
}

func (b *flakyBackend) Get(ctx context.Context, key string) (string, error) {
	return b.inner.Get(ctx, key)
}

func (b *flakyBackend) Delete(ctx context.Context, key string) error {
	return b.inner.Delete(ctx, key)
}

func (b *flakyBackend) ScanPrefix(ctx context.Context, prefix string) (map[string]string, error) {
	return b.inner.ScanPrefix(ctx, prefix)
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

// TestRegisterGatewayAlive_ListLive_AndDeregister pins the spec-31 liveness fix:
// a live gateway shows up in ListLiveGatewayIDs, and stop() (clean shutdown or
// TTL expiry) removes it — so a restarted gateway's departed ephemeral id stops
// counting as live (the "stale Active" bug).
func TestRegisterGatewayAlive_ListLive_AndDeregister(t *testing.T) {
	r := New(NewFakeBackend(nil), nil)
	ctx := context.Background()

	live, err := r.ListLiveGatewayIDs(ctx)
	if err != nil {
		t.Fatalf("ListLiveGatewayIDs: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("expected no live gateways initially, got %d", len(live))
	}

	stop1, err := r.RegisterGatewayAlive(ctx, "gw-1", time.Minute, time.Second)
	if err != nil {
		t.Fatalf("RegisterGatewayAlive gw-1: %v", err)
	}
	stop2, err := r.RegisterGatewayAlive(ctx, "gw-2", time.Minute, time.Second)
	if err != nil {
		t.Fatalf("RegisterGatewayAlive gw-2: %v", err)
	}
	defer stop2()

	live, _ = r.ListLiveGatewayIDs(ctx)
	if _, ok := live["gw-1"]; !ok {
		t.Error("gw-1 must be live after RegisterGatewayAlive")
	}
	if _, ok := live["gw-2"]; !ok {
		t.Error("gw-2 must be live after RegisterGatewayAlive")
	}

	stop1() // clean shutdown deletes the marker
	live, _ = r.ListLiveGatewayIDs(ctx)
	if _, ok := live["gw-1"]; ok {
		t.Error("gw-1 must NOT be live after stop() — a departed gateway is not Active")
	}
	if _, ok := live["gw-2"]; !ok {
		t.Error("gw-2 must still be live")
	}
}

func TestRegisterGatewayAlive_RejectsEmptyID(t *testing.T) {
	r := New(NewFakeBackend(nil), nil)
	if _, err := r.RegisterGatewayAlive(context.Background(), "", time.Minute, time.Second); err == nil {
		t.Error("empty gatewayID must be rejected")
	}
}
