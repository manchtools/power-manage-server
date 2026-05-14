package store

import (
	"context"
	"time"
)

// StartTerminalSession is the param shape for the Upsert that opens
// a terminal session row. Carries everything needed to reconstruct
// the session record from a TerminalSessionStarted event.
type StartTerminalSession struct {
	SessionID string
	DeviceID  string
	UserID    string
	TtyUser   string
	StartedAt time.Time
	Cols      int32
	Rows      int32
}

// StopTerminalSession is the param shape for the graceful-end path
// (TerminalSessionStopped event from the bridge). DeviceID + UserID
// participate in the upsert key so a missing-row case still creates
// a complete record rather than silently no-opping.
type StopTerminalSession struct {
	SessionID string
	DeviceID  string
	UserID    string
	StoppedAt *time.Time
	ExitCode  *int32
}

// TerminateTerminalSession is the param shape for the admin
// force-kill path (TerminalSessionTerminated event). Same upsert
// posture as StopTerminalSession; TerminatedBy carries the admin
// user ID for the audit trail.
type TerminateTerminalSession struct {
	SessionID    string
	DeviceID     string
	UserID       string
	StoppedAt    *time.Time
	TerminatedBy *string
}

// TerminalSessionRepo records terminal-session lifecycle from the
// control-side handler. Reads (history / replay) live elsewhere —
// the control handler only writes. The first-finalizer-wins guard
// in the underlying upserts ensures a Stop after a Terminate does
// not overwrite the Terminate, and vice versa.
type TerminalSessionRepo interface {
	UpsertStart(ctx context.Context, p StartTerminalSession) error
	MarkStopped(ctx context.Context, p StopTerminalSession) error
	MarkTerminated(ctx context.Context, p TerminateTerminalSession) error
}
