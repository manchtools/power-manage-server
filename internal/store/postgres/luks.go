package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Luks implements store.LuksRepo against luks_keys_projection +
// luks_tokens.
type Luks struct {
	q *generated.Queries
}

// NewLuks returns a Luks repo bound to the given sqlc handle.
func NewLuks(q *generated.Queries) *Luks {
	return &Luks{q: q}
}

func (l *Luks) ListCurrent(ctx context.Context, deviceID string) ([]store.LuksKey, error) {
	rows, err := l.q.GetCurrentLuksKeys(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("luks: list current: %w", err)
	}
	out := make([]store.LuksKey, len(rows))
	for i, r := range rows {
		out[i] = luksFromRow(r)
	}
	return out, nil
}

func (l *Luks) ListHistory(ctx context.Context, deviceID string) ([]store.LuksKey, error) {
	rows, err := l.q.GetLuksKeyHistory(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("luks: list history: %w", err)
	}
	out := make([]store.LuksKey, len(rows))
	for i, r := range rows {
		out[i] = luksFromRow(r)
	}
	return out, nil
}

func (l *Luks) GetCurrentForAction(ctx context.Context, key store.LuksKeyByActionKey) (store.LuksKey, error) {
	row, err := l.q.GetCurrentLuksKeyForAction(ctx, generated.GetCurrentLuksKeyForActionParams{
		DeviceID: key.DeviceID,
		ActionID: key.ActionID,
	})
	if err != nil {
		return store.LuksKey{}, fmt.Errorf("luks: get current for action: %w", translateNotFound(err))
	}
	return luksFromRow(row), nil
}

func (l *Luks) CreateToken(ctx context.Context, p store.CreateLuksTokenParams) (store.LuksToken, error) {
	row, err := l.q.CreateLuksToken(ctx, generated.CreateLuksTokenParams{
		DeviceID:   p.DeviceID,
		ActionID:   p.ActionID,
		Token:      p.Token,
		MinLength:  p.MinLength,
		Complexity: p.Complexity,
	})
	if err != nil {
		return store.LuksToken{}, fmt.Errorf("luks: create token: %w", err)
	}
	return luksTokenFromRow(row), nil
}

func (l *Luks) ConsumeToken(ctx context.Context, p store.ConsumeLuksTokenParams) (store.LuksToken, error) {
	row, err := l.q.ValidateAndConsumeLuksToken(ctx, generated.ValidateAndConsumeLuksTokenParams{
		Token:    p.Token,
		DeviceID: p.DeviceID,
	})
	if err != nil {
		return store.LuksToken{}, fmt.Errorf("luks: consume token: %w", translateNotFound(err))
	}
	return luksTokenFromRow(row), nil
}

func (l *Luks) GetRevocationStreamID(ctx context.Context, key store.LuksRevocationStreamKey) (string, error) {
	rows, err := l.q.ListLuksRevocationCandidates(ctx)
	if err != nil {
		return "", fmt.Errorf("luks: list revocation candidates: %w", err)
	}
	var payload struct {
		DeviceID string `json:"device_id"`
		ActionID string `json:"action_id"`
	}
	for _, r := range rows {
		if err := json.Unmarshal(r.Data, &payload); err != nil {
			continue
		}
		if payload.DeviceID == key.DeviceID && payload.ActionID == key.ActionID {
			return r.StreamID, nil
		}
	}
	return "", fmt.Errorf("luks: get revocation stream id: %w", store.ErrNotFound)
}

func luksFromRow(r generated.LuksKeysProjection) store.LuksKey {
	return store.LuksKey{
		ID:               r.ID,
		DeviceID:         r.DeviceID,
		ActionID:         r.ActionID,
		DevicePath:       r.DevicePath,
		Passphrase:       r.Passphrase,
		RotatedAt:        r.RotatedAt,
		RotationReason:   r.RotationReason,
		IsCurrent:        r.IsCurrent,
		CreatedAt:        r.CreatedAt,
		RevocationStatus: r.RevocationStatus,
		RevocationError:  r.RevocationError,
		RevocationAt:     r.RevocationAt,
	}
}

func luksTokenFromRow(r generated.LuksToken) store.LuksToken {
	return store.LuksToken{
		ID:         r.ID,
		DeviceID:   r.DeviceID,
		ActionID:   r.ActionID,
		Token:      r.Token,
		MinLength:  r.MinLength,
		Complexity: r.Complexity,
		CreatedAt:  r.CreatedAt,
		ExpiresAt:  r.ExpiresAt,
		Used:       r.Used,
	}
}
