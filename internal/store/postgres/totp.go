package postgres

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Totp implements store.TotpRepo against totp_projection.
type Totp struct {
	q *generated.Queries
}

// NewTotp returns a Totp repo bound to the given sqlc handle.
func NewTotp(q *generated.Queries) *Totp {
	return &Totp{q: q}
}

func (t *Totp) GetByUserID(ctx context.Context, userID string) (store.TotpRecord, error) {
	row, err := t.q.GetTOTPByUserID(ctx, userID)
	if err != nil {
		return store.TotpRecord{}, fmt.Errorf("totp: get by user: %w", translateNotFound(err))
	}
	return store.TotpRecord{
		UserID:            row.UserID,
		SecretEncrypted:   row.SecretEncrypted,
		Verified:          row.Verified,
		Enabled:           row.Enabled,
		BackupCodesHash:   row.BackupCodesHash,
		BackupCodesUsed:   row.BackupCodesUsed,
		CreatedAt:         row.CreatedAt,
		UpdatedAt:         row.UpdatedAt,
		ProjectionVersion: row.ProjectionVersion,
	}, nil
}

func (t *Totp) GetStatus(ctx context.Context, userID string) (store.TotpStatus, error) {
	row, err := t.q.GetTOTPStatus(ctx, userID)
	if err != nil {
		return store.TotpStatus{}, fmt.Errorf("totp: get status: %w", translateNotFound(err))
	}
	return store.TotpStatus{
		Enabled:              row.Enabled,
		BackupCodesRemaining: row.BackupCodesRemaining,
	}, nil
}
