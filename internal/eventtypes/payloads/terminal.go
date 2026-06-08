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

// TerminalAdminMembershipRevoked is the wire shape for the
// TerminalAdminMembershipRevoked event (#70). Emitted by the global
// TerminalAdmin reconciler each time a previously-present
// pm-tty-<linux_username> is removed from a global action's users[].
// Carries enough context for audit consumers to render a meaningful
// row without re-reading the action's params:
//   - UserID identifies the human operator who lost membership.
//   - LinuxUsername is the pm-tty-* string that was dropped (without
//     the pm-tty- prefix so audit can compose the prefix itself).
//   - ActionID points at the LIMITED or FULL global action row.
//   - AccessLevel is the wire-string form of pm.AdminAccessLevel
//     ("ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_LIMITED" / "_FULL").
type TerminalAdminMembershipRevoked struct {
	UserID        string `json:"user_id"`
	LinuxUsername string `json:"linux_username"`
	ActionID      string `json:"action_id"`
	AccessLevel   string `json:"access_level"`
}
