package connection

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager_RegisterGet(t *testing.T) {
	m := NewManager()

	agent := m.Register("device-1", "host1", "1.0.0", nil)
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

	agent1 := m.Register("device-1", "host1", "1.0.0", nil)
	agent2 := m.Register("device-1", "host1", "2.0.0", nil)

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

	agent := m.Register("device-1", "host1", "1.0.0", nil)
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

	m.Register("device-1", "host1", "1.0.0", nil)
	assert.Equal(t, 1, m.Count())

	m.Register("device-2", "host2", "1.0.0", nil)
	assert.Equal(t, 2, m.Count())

	m.Unregister("device-1")
	assert.Equal(t, 1, m.Count())
}

func TestManager_List(t *testing.T) {
	m := NewManager()

	m.Register("device-1", "host1", "1.0.0", nil)
	m.Register("device-2", "host2", "1.0.0", nil)
	m.Register("device-3", "host3", "1.0.0", nil)

	ids := m.List()
	assert.Len(t, ids, 3)
	assert.Contains(t, ids, "device-1")
	assert.Contains(t, ids, "device-2")
	assert.Contains(t, ids, "device-3")
}

func TestManager_IsConnected(t *testing.T) {
	m := NewManager()

	assert.False(t, m.IsConnected("device-1"))

	m.Register("device-1", "host1", "1.0.0", nil)
	assert.True(t, m.IsConnected("device-1"))

	m.Unregister("device-1")
	assert.False(t, m.IsConnected("device-1"))
}

func TestManager_UpdateLastSeen(t *testing.T) {
	m := NewManager()

	agent := m.Register("device-1", "host1", "1.0.0", nil)
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

	m.Register("device-1", "host1", "1.0.0", nil)

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
			m.Register(id, "host", "1.0.0", nil)
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
