// Package connection manages agent connections and message routing.
package connection

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"connectrpc.com/connect"
	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// Agent represents a connected agent.
type Agent struct {
	DeviceID    string
	Hostname    string
	Version     string
	ConnectedAt time.Time
	LastSeen    time.Time
	Stream      *connect.BidiStream[pm.AgentMessage, pm.ServerMessage]
	sendMu      sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc

	// write puts one frame on the wire. Production wires it to Stream.Send in
	// Register; it is a seam because connect.BidiStream is a concrete type with
	// no interface, so a test cannot otherwise produce the case that matters
	// here — a write that blocks because the device stopped reading.
	write func(*pm.ServerMessage) error
}

// SendTimeout bounds a single frame's write to a device. A package var so tests
// can shorten it; there is no per-call deadline because connect's BidiStream.Send
// takes no context and blocks on the underlying HTTP/2 write.
//
// Any value is a trade-off between tolerating a briefly congested link and
// holding server-side state for a device that is gone. Ten seconds is far longer
// than a healthy write and far shorter than the hours an unbounded write can
// hang for on a black-holed connection.
var SendTimeout = 10 * time.Second

// Send sends a message to the agent, bounded by SendTimeout.
//
// The bound matters because a device that stops reading — suspended laptop,
// black-holed route, hung agent — leaves Stream.Send blocked on TCP backpressure
// indefinitely. Unbounded, that stalls every later send to the same device
// behind the mutex, including the terminate frame that ends a live root shell,
// and stalls Broadcast for every device queued behind it.
//
// On timeout the connection is declared dead rather than retried. That is also
// what makes this safe: the abandoned write goroutine still owns Stream.Send,
// and connect streams are not safe for concurrent use, so no other caller may
// ever reach it. Cancelling the context guarantees that — every later Send
// short-circuits on the ctx check below, and the cancellation tears the stream
// down, which unblocks the abandoned write and lets its goroutine exit.
func (a *Agent) Send(msg *pm.ServerMessage) error {
	// Acquire the send lock FIRST, then check the context. If we checked
	// the context before locking, Close() could race in between — cancelling
	// the ctx while our goroutine still holds a stale "not done" read — and
	// we'd send on a stream the handler has already declared dead.
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	select {
	case <-a.ctx.Done():
		return ErrAgentNotConnected
	default:
	}
	if a.write == nil {
		// No stream was ever attached. Registered-but-unwritable is not a
		// connection an agent can be reached on.
		return ErrAgentNotConnected
	}

	done := make(chan error, 1) // buffered: the goroutine must never block on a timed-out send
	go func() { done <- a.write(msg) }()

	timer := time.NewTimer(SendTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		// Fail closed: a device that cannot accept a frame is not connected,
		// and leaving it registered would keep offering it work it never takes.
		a.cancel()
		return ErrSendTimeout
	}
}

// Close closes the agent connection.
func (a *Agent) Close() {
	a.cancel()
}

// Done reports the agent's own cancellation, which fires on Close — Unregister,
// or a newer connection superseding this one.
//
// Exported because cancelling it has to actually reach the stream handler. The
// handler blocks in Receive, which only returns when the client sends or the
// RPC context dies; neither observes this cancellation. Without a channel to
// select on, revoking a certificate would cancel this context and leave the
// authenticated stream running until the agent happened to disconnect.
func (a *Agent) Done() <-chan struct{} {
	return a.ctx.Done()
}

// Terminated reports whether this agent's connection has been closed, for the
// re-check between receiving a frame and acting on it.
func (a *Agent) Terminated() bool {
	return a.ctx.Err() != nil
}

// Manager manages connected agents.
type Manager struct {
	now    func() time.Time // clock seam; defaults to time.Now, overridden in tests
	mu     sync.RWMutex
	agents map[string]*Agent // deviceID -> agent
}

// NewManager creates a new connection manager.
func NewManager() *Manager {
	return &Manager{
		now:    time.Now,
		agents: make(map[string]*Agent),
	}
}

// Register registers a new agent connection. The parent ctx should be
// the handler's request ctx so the agent's lifetime ends when the RPC
// ends (graceful shutdown, client disconnect). Close() still cancels
// independently for Unregister-driven teardown.
func (m *Manager) Register(parentCtx context.Context, deviceID, hostname, version string, stream *connect.BidiStream[pm.AgentMessage, pm.ServerMessage]) *Agent {
	ctx, cancel := context.WithCancel(parentCtx)

	agent := &Agent{
		DeviceID:    deviceID,
		Hostname:    hostname,
		Version:     version,
		ConnectedAt: m.now(),
		LastSeen:    m.now(),
		Stream:      stream,
		ctx:         ctx,
		cancel:      cancel,
	}
	if stream != nil {
		agent.write = stream.Send
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
	m.mu.Lock()
	agent, ok := m.agents[deviceID]
	if ok {
		agent.LastSeen = m.now()
	}
	m.mu.Unlock()
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
		if err := agent.Send(msg); err != nil {
			slog.Warn("broadcast send failed", "device_id", agent.DeviceID, "error", err)
		}
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
