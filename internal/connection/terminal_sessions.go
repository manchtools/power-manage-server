package connection

import (
	"sync"
	"time"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// TerminalSession represents a live WebSocket terminal bridge session
// registered by the gateway. The bridge goroutine reads from OutputCh;
// the agent bidi stream handler writes to it via RouteAgentMessage.
type TerminalSession struct {
	SessionID string
	DeviceID  string
	UserID    string
	TtyUser   string
	Cols      uint32
	Rows      uint32
	StartedAt time.Time

	// OutputCh carries TerminalOutput and TerminalStateChange messages
	// from the agent to the WebSocket bridge goroutine. Buffered so a
	// briefly-slow WebSocket client doesn't block the bidi stream
	// receive loop. If the channel is full, RouteAgentMessage drops
	// the message (the user sees a brief stutter, which is acceptable
	// for a terminal UI).
	OutputCh chan *pm.AgentMessage

	mu             sync.Mutex
	lastActivityAt time.Time
}

// NewTerminalSession constructs a session with a buffered output channel.
func NewTerminalSession(sessionID, deviceID, userID, ttyUser string, cols, rows uint32) *TerminalSession {
	return &TerminalSession{
		SessionID:      sessionID,
		DeviceID:       deviceID,
		UserID:         userID,
		TtyUser:        ttyUser,
		Cols:           cols,
		Rows:           rows,
		StartedAt:      time.Now(),
		lastActivityAt: time.Now(),
		OutputCh:       make(chan *pm.AgentMessage, 64),
	}
}

// Touch updates the last activity timestamp.
func (s *TerminalSession) Touch() {
	s.mu.Lock()
	s.lastActivityAt = time.Now()
	s.mu.Unlock()
}

// LastActivity returns the most recent activity timestamp.
func (s *TerminalSession) LastActivity() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastActivityAt
}

// TerminalSessionRegistry is a concurrent-safe map of active terminal
// sessions on this gateway, keyed by session_id. The WebSocket bridge
// handler registers/unregisters sessions; the agent bidi stream
// handler routes TerminalOutput/TerminalStateChange messages through
// it.
type TerminalSessionRegistry struct {
	mu       sync.RWMutex
	sessions map[string]*TerminalSession
}

// NewTerminalSessionRegistry creates an empty registry.
func NewTerminalSessionRegistry() *TerminalSessionRegistry {
	return &TerminalSessionRegistry{
		sessions: make(map[string]*TerminalSession),
	}
}

// Register adds a session to the registry. Replaces any existing
// session with the same ID (shouldn't happen with ULIDs, but
// defensive).
func (r *TerminalSessionRegistry) Register(s *TerminalSession) {
	r.mu.Lock()
	if old, exists := r.sessions[s.SessionID]; exists {
		close(old.OutputCh)
	}
	r.sessions[s.SessionID] = s
	r.mu.Unlock()
}

// Unregister removes a session and closes its OutputCh so any
// blocked reader unblocks. Idempotent.
func (r *TerminalSessionRegistry) Unregister(sessionID string) {
	r.mu.Lock()
	if s, ok := r.sessions[sessionID]; ok {
		close(s.OutputCh)
		delete(r.sessions, sessionID)
	}
	r.mu.Unlock()
}

// Get returns the session for the given ID, or nil.
func (r *TerminalSessionRegistry) Get(sessionID string) *TerminalSession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessions[sessionID]
}

// RouteAgentMessage sends the message to the session's OutputCh.
// Returns true if the session exists and the message was delivered
// (or dropped because the channel is full). Returns false if no
// session with that ID is registered.
//
// This is the hot path: called from the bidi stream receive loop on
// every TerminalOutput/TerminalStateChange frame. It must never
// block the receive loop, so a full channel drops the message
// rather than blocking.
func (r *TerminalSessionRegistry) RouteAgentMessage(sessionID string, msg *pm.AgentMessage) bool {
	// Hold RLock through the entire send so Unregister (which takes
	// the write lock before closing OutputCh) cannot race with us.
	// Without this, Unregister can close OutputCh between our lookup
	// and the select, causing a send-on-closed-channel panic.
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[sessionID]
	if !ok {
		return false
	}
	select {
	case s.OutputCh <- msg:
	default:
		// Channel full — drop the frame. The user sees a brief
		// stutter in the terminal output, which is acceptable.
	}
	return true
}

// Count returns the number of active sessions.
func (r *TerminalSessionRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

// List returns a snapshot of all active sessions for the admin
// GatewayService.ListGatewayTerminalSessions RPC.
func (r *TerminalSessionRegistry) List() []*TerminalSession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*TerminalSession, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, s)
	}
	return out
}
