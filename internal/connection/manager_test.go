package connection

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

func TestManager_RegisterGet(t *testing.T) {
	m := NewManager()

	agent := m.Register(context.Background(), "device-1", "host1", "1.0.0", nil)
	assert.Equal(t, "device-1", agent.DeviceID)
	assert.Equal(t, "host1", agent.Hostname)
	assert.Equal(t, "1.0.0", agent.Version)
	assert.False(t, agent.ConnectedAt.IsZero())
	assert.False(t, agent.LastSeen.IsZero())

	got, ok := m.Get("device-1")
	require.True(t, ok)
	assert.Equal(t, agent, got)
}

func TestManager_GetNotFound(t *testing.T) {
	m := NewManager()
	_, ok := m.Get("nonexistent")
	assert.False(t, ok)
}

func TestManager_ReplaceExisting(t *testing.T) {
	m := NewManager()

	agent1 := m.Register(context.Background(), "device-1", "host1", "1.0.0", nil)
	agent2 := m.Register(context.Background(), "device-1", "host1", "2.0.0", nil)

	assert.NotEqual(t, agent1, agent2)

	got, ok := m.Get("device-1")
	require.True(t, ok)
	assert.Equal(t, "2.0.0", got.Version)

	// Old agent's context should be cancelled
	select {
	case <-agent1.ctx.Done():
		// Expected
	default:
		t.Error("old agent context should be cancelled")
	}
}

func TestManager_Unregister(t *testing.T) {
	m := NewManager()

	agent := m.Register(context.Background(), "device-1", "host1", "1.0.0", nil)
	m.Unregister("device-1")

	_, ok := m.Get("device-1")
	assert.False(t, ok)

	// Agent's context should be cancelled
	select {
	case <-agent.ctx.Done():
		// Expected
	default:
		t.Error("agent context should be cancelled after unregister")
	}
}

func TestManager_UnregisterNonexistent(t *testing.T) {
	m := NewManager()
	m.Unregister("nonexistent") // Should not panic
}

func TestManager_Count(t *testing.T) {
	m := NewManager()

	assert.Equal(t, 0, m.Count())

	m.Register(context.Background(), "device-1", "host1", "1.0.0", nil)
	assert.Equal(t, 1, m.Count())

	m.Register(context.Background(), "device-2", "host2", "1.0.0", nil)
	assert.Equal(t, 2, m.Count())

	m.Unregister("device-1")
	assert.Equal(t, 1, m.Count())
}

func TestManager_List(t *testing.T) {
	m := NewManager()

	m.Register(context.Background(), "device-1", "host1", "1.0.0", nil)
	m.Register(context.Background(), "device-2", "host2", "1.0.0", nil)
	m.Register(context.Background(), "device-3", "host3", "1.0.0", nil)

	ids := m.List()
	assert.Len(t, ids, 3)
	assert.Contains(t, ids, "device-1")
	assert.Contains(t, ids, "device-2")
	assert.Contains(t, ids, "device-3")
}

func TestManager_IsConnected(t *testing.T) {
	m := NewManager()

	assert.False(t, m.IsConnected("device-1"))

	m.Register(context.Background(), "device-1", "host1", "1.0.0", nil)
	assert.True(t, m.IsConnected("device-1"))

	m.Unregister("device-1")
	assert.False(t, m.IsConnected("device-1"))
}

func TestManager_UpdateLastSeen(t *testing.T) {
	m := NewManager()

	agent := m.Register(context.Background(), "device-1", "host1", "1.0.0", nil)
	initial := agent.LastSeen

	m.UpdateLastSeen("device-1")

	got, _ := m.Get("device-1")
	assert.True(t, got.LastSeen.After(initial) || got.LastSeen.Equal(initial))
}

func TestManager_UpdateLastSeen_Nonexistent(t *testing.T) {
	m := NewManager()
	m.UpdateLastSeen("nonexistent") // Should not panic
}

func TestManager_SendNotConnected(t *testing.T) {
	m := NewManager()
	err := m.Send("device-1", nil)
	assert.ErrorIs(t, err, ErrAgentNotConnected)
}

func TestManager_Context(t *testing.T) {
	m := NewManager()

	m.Register(context.Background(), "device-1", "host1", "1.0.0", nil)

	ctx, ok := m.Context("device-1")
	require.True(t, ok)
	assert.NotNil(t, ctx)
	assert.NoError(t, ctx.Err())

	m.Unregister("device-1")

	_, ok = m.Context("device-1")
	assert.False(t, ok)
}

func TestManager_ConcurrentAccess(t *testing.T) {
	m := NewManager()
	var wg sync.WaitGroup

	// Concurrent register
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			m.Register(context.Background(), id, "host", "1.0.0", nil)
		}(string(rune('a' + i)))
	}

	// Concurrent reads
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Count()
			m.List()
			m.IsConnected("a")
		}()
	}

	wg.Wait()
	assert.Equal(t, 50, m.Count())
}

// A device that stops reading must not strand the server.
//
// A write blocks on TCP backpressure until the transport's deadline fires, and
// the send mutex is held for its whole duration. Unbounded, the first stalled write
// pins every later send to that device — including the terminate frame that ends
// a live root shell — and pins Broadcast for every device queued behind it.
func TestAgent_SendDoesNotBlockForeverOnAStalledDevice(t *testing.T) {
	restore := SendTimeout
	SendTimeout = 50 * time.Millisecond
	t.Cleanup(func() { SendTimeout = restore })

	m := NewManager()
	agent := m.Register(context.Background(), "device-1", "host1", "1.0.0", nil)

	// A device that accepted the stream and then stopped reading it, wired the
	// way the real transport behaves: the write blocks until the armed deadline
	// fires, then returns os.ErrDeadlineExceeded.
	stalledDevice(t, agent)

	done := make(chan error, 1)
	go func() { done <- agent.Send(&pm.ServerMessage{}) }()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, ErrSendTimeout,
			"a stalled write must be reported as a timeout, not as success")
	case <-time.After(5 * time.Second):
		t.Fatal("Send never returned — a device that stops reading blocks the server indefinitely")
	}

	// Fail closed: the connection is declared dead rather than retried.
	assert.True(t, agent.Terminated(),
		"a device that cannot accept a frame must be disconnected, not left registered")
}

// The stall must not leak past the one device: a second device's send still
// works while the first is wedged. This is the Broadcast property.
func TestAgent_StalledDeviceDoesNotBlockAnother(t *testing.T) {
	restore := SendTimeout
	SendTimeout = 50 * time.Millisecond
	t.Cleanup(func() { SendTimeout = restore })

	m := NewManager()
	stalled := m.Register(context.Background(), "device-1", "host1", "1.0.0", nil)
	healthy := m.Register(context.Background(), "device-2", "host2", "1.0.0", nil)

	stalledDevice(t, stalled)

	var delivered atomic.Int32
	healthy.write = func(*pm.ServerMessage) error { delivered.Add(1); return nil }

	stalledDone := make(chan struct{})
	go func() { defer close(stalledDone); _ = stalled.Send(&pm.ServerMessage{}) }()
	time.Sleep(10 * time.Millisecond) // let the stalled write take its lock

	require.NoError(t, healthy.Send(&pm.ServerMessage{}),
		"a healthy device must be reachable while another is wedged")
	assert.Equal(t, int32(1), delivered.Load())

	// Join before returning: the cleanup restores the SendTimeout package var,
	// which this goroutine is still reading inside Send.
	<-stalledDone
}

// After a timeout the connection is closed, so a retry is refused outright
// instead of entering the stream again.
func TestAgent_SendAfterTimeoutIsRefusedNotQueued(t *testing.T) {
	restore := SendTimeout
	SendTimeout = 50 * time.Millisecond
	t.Cleanup(func() { SendTimeout = restore })

	m := NewManager()
	agent := m.Register(context.Background(), "device-1", "host1", "1.0.0", nil)

	writes := stalledDevice(t, agent)

	require.ErrorIs(t, agent.Send(&pm.ServerMessage{}), ErrSendTimeout)

	start := time.Now()
	err := agent.Send(&pm.ServerMessage{})
	assert.ErrorIs(t, err, ErrAgentNotConnected)
	assert.Less(t, time.Since(start), SendTimeout,
		"the retry must be refused immediately, not wait out another timeout")
	assert.Equal(t, int32(1), writes.Load(),
		"only the first send may enter the stream — connect streams are not safe for concurrent use")
}

// stalledDevice wires an agent to behave like a device that accepted the stream
// and then stopped reading: the write blocks until the deadline the transport
// armed for it expires, then returns os.ErrDeadlineExceeded — exactly what
// net/http reports when a write deadline fires.
//
// Faking the DEADLINE rather than the timeout is the point. The bound under test
// belongs to the transport, so a fake that ignored the deadline and returned on
// a timer of its own would pass whether or not Send ever armed one.
func stalledDevice(t *testing.T, a *Agent) *atomic.Int32 {
	t.Helper()
	var writes atomic.Int32
	deadline := make(chan time.Time, 1)

	a.SetWriteDeadlineFunc(func(d time.Time) error {
		if d.IsZero() { // cleared after the write
			return nil
		}
		select {
		case deadline <- d:
		default:
		}
		return nil
	})
	a.write = func(*pm.ServerMessage) error {
		writes.Add(1)
		select {
		case d := <-deadline:
			time.Sleep(time.Until(d))
			return os.ErrDeadlineExceeded
		case <-time.After(5 * time.Second):
			return errors.New("Send never armed a write deadline — the write would block forever on a real transport")
		}
	}
	return &writes
}

// A departing handler must not tear down the connection that replaced it.
//
// Teardown used to be Get-then-Unregister with the lock released in between. A
// device reconnecting in that gap had its FRESH registration deleted by the
// handler that was leaving: the device believed it was connected while the
// server held no route to it, and the shared per-device worker was stopped out
// from under the live connection.
//
// UnregisterIfCurrent decides and deletes under one lock, so the outcome is the
// same whichever side wins the race — the newcomer survives either way.
func TestManager_UnregisterIfCurrentLeavesAReplacementAlone(t *testing.T) {
	m := NewManager()

	old := m.Register(context.Background(), "device-1", "host1", "1.0.0", nil)
	// The device reconnects: Register replaces the entry, exactly as a real
	// reconnect does while the previous handler is still unwinding.
	fresh := m.Register(context.Background(), "device-1", "host1", "1.0.1", nil)
	require.NotSame(t, old, fresh)

	// The departing handler now runs its teardown.
	assert.False(t, m.UnregisterIfCurrent("device-1", old),
		"the stale handler must report that it removed nothing — it no longer owns the registration")

	got, ok := m.Get("device-1")
	require.True(t, ok, "the reconnected device was unregistered by the handler it replaced")
	assert.Same(t, fresh, got, "the surviving registration must be the new one")
	assert.False(t, fresh.Terminated(), "the replacement's connection was closed by the departing handler")
}

// The ordinary case still works: the current registration removes itself.
func TestManager_UnregisterIfCurrentRemovesTheLiveRegistration(t *testing.T) {
	m := NewManager()
	agent := m.Register(context.Background(), "device-1", "host1", "1.0.0", nil)

	assert.True(t, m.UnregisterIfCurrent("device-1", agent))
	_, ok := m.Get("device-1")
	assert.False(t, ok, "the live registration must actually be removed")
	assert.True(t, agent.Terminated(), "removing a registration must close its connection")

	assert.False(t, m.UnregisterIfCurrent("device-1", agent),
		"a second teardown must be a no-op, not a removal of whatever is there now")
}
