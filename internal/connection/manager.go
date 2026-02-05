// Package connection manages agent connections and message routing.
package connection

import (
	"context"
	"sync"
	"time"

	"connectrpc.com/connect"
	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// Agent represents a connected agent.
type Agent struct {
	DeviceID     string
	Hostname     string
	Version      string
	ConnectedAt  time.Time
	LastSeen     time.Time
	Stream       *connect.BidiStream[pm.AgentMessage, pm.ServerMessage]
	sendMu       sync.Mutex
	ctx          context.Context
	cancel       context.CancelFunc
}

// Send sends a message to the agent.
func (a *Agent) Send(msg *pm.ServerMessage) error {
	// Check if the agent connection has been closed
	select {
	case <-a.ctx.Done():
		return ErrAgentNotConnected
	default:
	}

	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	return a.Stream.Send(msg)
}

// Close closes the agent connection.
func (a *Agent) Close() {
	a.cancel()
}

// Manager manages connected agents.
type Manager struct {
	mu     sync.RWMutex
	agents map[string]*Agent // deviceID -> agent
}

// NewManager creates a new connection manager.
func NewManager() *Manager {
	return &Manager{
		agents: make(map[string]*Agent),
	}
}

// Register registers a new agent connection.
func (m *Manager) Register(deviceID, hostname, version string, stream *connect.BidiStream[pm.AgentMessage, pm.ServerMessage]) *Agent {
	ctx, cancel := context.WithCancel(context.Background())

	agent := &Agent{
		DeviceID:    deviceID,
		Hostname:    hostname,
		Version:     version,
		ConnectedAt: time.Now(),
		LastSeen:    time.Now(),
		Stream:      stream,
		ctx:         ctx,
		cancel:      cancel,
	}

	m.mu.Lock()
	// Close existing connection if any
	if existing, ok := m.agents[deviceID]; ok {
		existing.Close()
	}
	m.agents[deviceID] = agent
	m.mu.Unlock()

	return agent
}

// Unregister removes an agent connection.
func (m *Manager) Unregister(deviceID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if agent, ok := m.agents[deviceID]; ok {
		agent.Close()
		delete(m.agents, deviceID)
	}
}

// Get returns an agent by device ID.
func (m *Manager) Get(deviceID string) (*Agent, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	agent, ok := m.agents[deviceID]
	return agent, ok
}

// UpdateLastSeen updates the last seen timestamp for an agent.
func (m *Manager) UpdateLastSeen(deviceID string) {
	m.mu.RLock()
	agent, ok := m.agents[deviceID]
	m.mu.RUnlock()

	if ok {
		agent.LastSeen = time.Now()
	}
}

// Send sends a message to a specific agent.
func (m *Manager) Send(deviceID string, msg *pm.ServerMessage) error {
	m.mu.RLock()
	agent, ok := m.agents[deviceID]
	m.mu.RUnlock()

	if !ok {
		return ErrAgentNotConnected
	}

	return agent.Send(msg)
}

// Broadcast sends a message to all connected agents.
func (m *Manager) Broadcast(msg *pm.ServerMessage) {
	m.mu.RLock()
	agents := make([]*Agent, 0, len(m.agents))
	for _, agent := range m.agents {
		agents = append(agents, agent)
	}
	m.mu.RUnlock()

	for _, agent := range agents {
		_ = agent.Send(msg) // Ignore errors for broadcast
	}
}

// Count returns the number of connected agents.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.agents)
}

// List returns all connected agent device IDs.
func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]string, 0, len(m.agents))
	for id := range m.agents {
		ids = append(ids, id)
	}
	return ids
}

// IsConnected checks if an agent is connected.
func (m *Manager) IsConnected(deviceID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.agents[deviceID]
	return ok
}

// Context returns the agent's context (for cancellation).
func (m *Manager) Context(deviceID string) (context.Context, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if agent, ok := m.agents[deviceID]; ok {
		return agent.ctx, true
	}
	return nil, false
}
