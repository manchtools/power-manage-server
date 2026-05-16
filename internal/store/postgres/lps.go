package postgres

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Lps implements store.LpsRepo against lps_passwords_projection.
type Lps struct {
	q *generated.Queries
}

// NewLps returns an Lps repo bound to the given sqlc handle.
func NewLps(q *generated.Queries) *Lps {
	return &Lps{q: q}
}

func (l *Lps) ListCurrent(ctx context.Context, deviceID string) ([]store.LpsPassword, error) {
	rows, err := l.q.GetCurrentLpsPasswords(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("lps: list current: %w", err)
	}
	out := make([]store.LpsPassword, len(rows))
	for i, r := range rows {
		out[i] = lpsFromRow(r)
	}
	return out, nil
}

func (l *Lps) ListHistory(ctx context.Context, deviceID string) ([]store.LpsPassword, error) {
	rows, err := l.q.GetLpsPasswordHistory(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("lps: list history: %w", err)
	}
	out := make([]store.LpsPassword, len(rows))
	for i, r := range rows {
		out[i] = lpsFromRow(r)
	}
	return out, nil
}

func lpsFromRow(r generated.LpsPasswordsProjection) store.LpsPassword {
	return store.LpsPassword{
		ID:             r.ID.String(),
		DeviceID:       r.DeviceID,
		ActionID:       r.ActionID,
		Username:       r.Username,
		Password:       r.Password,
		RotatedAt:      r.RotatedAt,
		RotationReason: r.RotationReason,
		IsCurrent:      r.IsCurrent,
		CreatedAt:      r.CreatedAt,
	}
}
