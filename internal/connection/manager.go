// Package connection manages agent connections and message routing.
package connection

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	pm "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
)

// Agent represents a connected agent.
type Agent struct {
	DeviceID    string
	Hostname    string
	Version     string
	ConnectedAt time.Time
	LastSeen    time.Time
	// Epoch increases for every accepted connection. Delivery sends name the
	// epoch they were prepared for so a replaced stream cannot receive new work.
	Epoch  int64
	Stream *connect.BidiStream[pm.AgentMessage, pm.ServerMessage]
	sendMu sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc

	// write puts one frame on the wire. Production wires it to Stream.Send in
	// Register; it is a seam because connect.BidiStream is a concrete type with
	// no interface, so a test cannot otherwise produce the case that matters
	// here — a write that blocks because the device stopped reading.
	write func(*pm.ServerMessage) error

	// setWriteDeadline arms the TRANSPORT's write deadline, so a blocked write
	// returns instead of being abandoned. Production wires it to
	// http.ResponseController.SetWriteDeadline; nil means the transport offers
	// no deadline support and Send falls back to an unbounded write.
	setWriteDeadline func(time.Time) error

	// now is the clock seam, copied from the manager at Register.
	now func() time.Time
}

// SendTimeout bounds a single frame's write to a device. A package var so tests
// can shorten it.
//
// Any value is a trade-off between tolerating a briefly congested link and
// holding server-side state for a device that is gone. Ten seconds is far longer
// than a healthy write and far shorter than the hours an unbounded write can
// hang for on a black-holed connection.
var SendTimeout = 10 * time.Second

// Send sends a message to the agent, bounded by SendTimeout.
//
// The bound matters because a device that stops reading — suspended laptop,
// black-holed route, hung agent — leaves the write blocked on TCP backpressure
// indefinitely. Unbounded, that stalls every later send to the same device
// behind the mutex, including the terminate frame that ends a live root shell,
// and stalls Broadcast for every device queued behind it.
//
// The bound is the TRANSPORT's write deadline, and it has to be: connect streams
// are not safe for concurrent use, and the handler owns the stream only until it
// returns. An earlier version ran the write on its own goroutine and abandoned
// it on timeout — which bounded the caller but left that goroutine inside
// Stream.Send while cancellation let the handler return and connect finalise the
// response underneath it. That traded a wedged device for a data race. Here the
// write is synchronous: the deadline makes it return on its own, so there is
// never a write in flight that nobody is waiting for.
//
// A transport with no deadline support leaves the write unbounded — the
// pre-existing behaviour, and better than pretending to bound it.
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

	if a.setWriteDeadline != nil && a.now != nil {
		if err := a.setWriteDeadline(a.now().Add(SendTimeout)); err != nil {
			// The transport refused a deadline. Send anyway rather than drop a
			// frame we could deliver, but the write is then unbounded.
			a.setWriteDeadline = nil
		} else {
			// Clear it afterwards so an idle stream is not torn down by a
			// deadline left armed from the previous frame.
			defer func() { _ = a.setWriteDeadline(time.Time{}) }()
		}
	}

	err := a.write(msg)
	if err != nil && errors.Is(err, os.ErrDeadlineExceeded) {
		// Fail closed: a device that cannot accept a frame is not connected,
		// and leaving it registered would keep offering it work it never takes.
		a.cancel()
		return ErrSendTimeout
	}
	return err
}

// SetWriteDeadlineFunc installs the transport write-deadline seam. The agent
// stream handler wires this from http.ResponseController once it has the
// response writer; without it Send cannot bound a stalled write.
func (a *Agent) SetWriteDeadlineFunc(fn func(time.Time) error) {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	a.setWriteDeadline = fn
}

// WaitForInFlightSend blocks until no Send is inside the stream. The stream
// handler calls it on the way out, and nobody else needs to.
//
// The handler owns the connect stream — and the net/http ResponseWriter beneath
// it — only until it returns: connect finalises the response as the handler
// unwinds, and net/http forbids touching the writer after ServeHTTP returns. A
// per-device dispatch worker or a terminal bridge can be inside Send at exactly
// that moment, holding the send lock at a.write, and at the deferred deadline
// clear that drives http.ResponseController on that same writer. Returning
// through that window is the data race the bounded write was introduced to
// avoid, arriving from the other direction.
//
// Taking and releasing the send lock IS the wait — Send holds it for the whole
// write. It quiesces the connection only if no LATER send can enter, so the
// caller must have cancelled the agent first: Send re-checks the context under
// the lock and refuses a cancelled one. The transport write deadline bounds the
// wait at SendTimeout; a transport with no deadline support leaves it exactly as
// unbounded as the write it is waiting for.
//
// Deliberately NOT folded into Close/Unregister: Unregister holds the manager's
// write lock across Close, so waiting there would pin every other device's
// Register/Get behind one device's stalled write.
func (a *Agent) WaitForInFlightSend() {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
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
	now       func() time.Time // clock seam; defaults to time.Now, overridden in tests
	nextEpoch atomic.Int64
	mu        sync.RWMutex
	agents    map[string]*Agent // deviceID -> agent
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
		Epoch:       m.nextEpoch.Add(1),
		Stream:      stream,
		ctx:         ctx,
		cancel:      cancel,
	}
	if stream != nil {
		agent.write = stream.Send
	}
	agent.now = m.now

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

// UnregisterIfCurrent removes deviceID's registration ONLY if it is still the
// one passed in, and reports whether it did.
//
// The stream handler's teardown cannot use Get-then-Unregister: between the two
// the same device can reconnect and Register a replacement, and the departing
// handler then closes the newcomer's connection and deletes its entry. The
// device is left believing it is connected while the server has no route to it,
// until the next reconnect — and the shared per-device worker is stopped out
// from under the live registration.
//
// The comparison and the delete happen under one lock, so a reconnect either
// wins the map before this runs (nothing is removed, false) or after it
// (removal already done, the newcomer is untouched).
func (m *Manager) UnregisterIfCurrent(deviceID string, agent *Agent) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	current, ok := m.agents[deviceID]
	if !ok || current != agent {
		return false
	}
	current.Close()
	delete(m.agents, deviceID)
	return true
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
	defer m.mu.RUnlock()
	agent, ok := m.agents[deviceID]

	if !ok {
		return ErrAgentNotConnected
	}

	return agent.Send(msg)
}

// SendAtEpoch sends only when epoch still names the device's current
// connection. The manager read lock remains held through the bounded write, so
// Register cannot replace the connection between the epoch check and the send.
func (m *Manager) SendAtEpoch(deviceID string, epoch int64, msg *pm.ServerMessage) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	agent, ok := m.agents[deviceID]
	if !ok {
		return ErrAgentNotConnected
	}
	if agent.Epoch != epoch {
		return ErrStaleConnection
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
