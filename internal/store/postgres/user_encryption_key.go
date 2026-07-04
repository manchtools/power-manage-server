package postgres

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// UserEncryptionKey implements store.UserEncryptionKeyRepo against
// user_encryption_keys — the crypto-shred key material (spec 19 /
// ADR 0030).
type UserEncryptionKey struct {
	q *generated.Queries
}

// NewUserEncryptionKey returns the repo bound to the given sqlc handle.
func NewUserEncryptionKey(q *generated.Queries) *UserEncryptionKey {
	return &UserEncryptionKey{q: q}
}

func (r *UserEncryptionKey) Mint(ctx context.Context, userID, wrappedDEK string) (bool, error) {
	n, err := r.q.InsertUserEncryptionKey(ctx, generated.InsertUserEncryptionKeyParams{
		UserID:     userID,
		WrappedDek: wrappedDEK,
	})
	if err != nil {
		return false, fmt.Errorf("user_encryption_key: mint: %w", err)
	}
	return n == 1, nil
}

func (r *UserEncryptionKey) Get(ctx context.Context, userID string) (store.UserEncryptionKey, error) {
	row, err := r.q.GetUserEncryptionKey(ctx, userID)
	if err != nil {
		return store.UserEncryptionKey{}, fmt.Errorf("user_encryption_key: get: %w", translateNotFound(err))
	}
	return store.UserEncryptionKey{
		UserID:     row.UserID,
		WrappedDEK: row.WrappedDek,
		CreatedAt:  row.CreatedAt,
	}, nil
}

func (r *UserEncryptionKey) Shred(ctx context.Context, userID string) (bool, error) {
	n, err := r.q.DeleteUserEncryptionKey(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("user_encryption_key: shred: %w", err)
	}
	return n == 1, nil
}
