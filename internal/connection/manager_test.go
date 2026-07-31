package connection

import (
	"context"
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
// Stream.Send blocks on TCP backpressure with no deadline of its own, and the
// send mutex is held for its whole duration. Unbounded, the first stalled write
// pins every later send to that device — including the terminate frame that ends
// a live root shell — and pins Broadcast for every device queued behind it.
func TestAgent_SendDoesNotBlockForeverOnAStalledDevice(t *testing.T) {
	restore := SendTimeout
	SendTimeout = 50 * time.Millisecond
	t.Cleanup(func() { SendTimeout = restore })

	m := NewManager()
	agent := m.Register(context.Background(), "device-1", "host1", "1.0.0", nil)

	// A device that accepted the stream and then stopped reading it.
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	agent.write = func(*pm.ServerMessage) error { <-release; return nil }

	done := make(chan error, 1)
	go func() { done <- agent.Send(&pm.ServerMessage{}) }()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, ErrSendTimeout,
			"a stalled write must be reported as a timeout, not as success")
	case <-time.After(5 * time.Second):
		t.Fatal("Send never returned — a device that stops reading blocks the server indefinitely")
	}

	// Fail closed: the connection is declared dead, which is also what makes the
	// abandoned write goroutine safe (no later caller can reach the stream).
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

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	stalled.write = func(*pm.ServerMessage) error { <-release; return nil }

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
// rather than queueing behind the abandoned write — the property that keeps
// exactly one goroutine in the non-concurrency-safe stream.
func TestAgent_SendAfterTimeoutIsRefusedNotQueued(t *testing.T) {
	restore := SendTimeout
	SendTimeout = 50 * time.Millisecond
	t.Cleanup(func() { SendTimeout = restore })

	m := NewManager()
	agent := m.Register(context.Background(), "device-1", "host1", "1.0.0", nil)

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var writes atomic.Int32
	agent.write = func(*pm.ServerMessage) error { writes.Add(1); <-release; return nil }

	require.ErrorIs(t, agent.Send(&pm.ServerMessage{}), ErrSendTimeout)

	start := time.Now()
	err := agent.Send(&pm.ServerMessage{})
	assert.ErrorIs(t, err, ErrAgentNotConnected)
	assert.Less(t, time.Since(start), SendTimeout,
		"the retry must be refused immediately, not wait out another timeout")
	assert.Equal(t, int32(1), writes.Load(),
		"only the first send may enter the stream — connect streams are not safe for concurrent use")
}
