package payloads

// TerminalSessionStarted is the wire shape for TerminalSessionStarted.
// session_id is the same ULID minted by the start handler that the
// agent sees on the wire; tty_user / cols / rows are the requested
// pty geometry.
type TerminalSessionStarted struct {
	SessionID string `json:"session_id"`
	TtyUser   string `json:"tty_user"`
	Cols      uint32 `json:"cols"`
	Rows      uint32 `json:"rows"`
}

// TerminalSessionStopped is the wire shape for TerminalSessionStopped.
// reason is a free-form string; today's writers use "user_stopped",
// "agent_disconnect", and "operator_disconnect".
type TerminalSessionStopped struct {
	SessionID string `json:"session_id"`
	Reason    string `json:"reason"`
}

// TerminalSessionTerminated is the wire shape for the
// TerminalSessionTerminated event. Same key set as Stopped today —
// kept distinct so the projector / audit listing can render the two
// states with different language.
type TerminalSessionTerminated struct {
	SessionID string `json:"session_id"`
	Reason    string `json:"reason"`
}
