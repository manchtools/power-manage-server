package postgres

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// TerminalSession implements store.TerminalSessionRepo against
// the terminal_sessions table.
type TerminalSession struct {
	q *generated.Queries
}

// NewTerminalSession returns a TerminalSession repo bound to the
// given sqlc handle.
func NewTerminalSession(q *generated.Queries) *TerminalSession {
	return &TerminalSession{q: q}
}

func (t *TerminalSession) UpsertStart(ctx context.Context, p store.StartTerminalSession) error {
	if err := t.q.UpsertTerminalSessionStart(ctx, generated.UpsertTerminalSessionStartParams{
		SessionID: p.SessionID,
		DeviceID:  p.DeviceID,
		UserID:    p.UserID,
		TtyUser:   p.TtyUser,
		StartedAt: p.StartedAt,
		Cols:      p.Cols,
		Rows:      p.Rows,
	}); err != nil {
		return fmt.Errorf("terminal_session: upsert start: %w", err)
	}
	return nil
}

func (t *TerminalSession) MarkStopped(ctx context.Context, p store.StopTerminalSession) error {
	if err := t.q.MarkTerminalSessionStopped(ctx, generated.MarkTerminalSessionStoppedParams{
		SessionID: p.SessionID,
		StoppedAt: p.StoppedAt,
		ExitCode:  p.ExitCode,
		DeviceID:  p.DeviceID,
		UserID:    p.UserID,
	}); err != nil {
		return fmt.Errorf("terminal_session: mark stopped: %w", err)
	}
	return nil
}

func (t *TerminalSession) MarkTerminated(ctx context.Context, p store.TerminateTerminalSession) error {
	if err := t.q.MarkTerminalSessionTerminated(ctx, generated.MarkTerminalSessionTerminatedParams{
		SessionID:    p.SessionID,
		StoppedAt:    p.StoppedAt,
		TerminatedBy: p.TerminatedBy,
		DeviceID:     p.DeviceID,
		UserID:       p.UserID,
	}); err != nil {
		return fmt.Errorf("terminal_session: mark terminated: %w", err)
	}
	return nil
}
