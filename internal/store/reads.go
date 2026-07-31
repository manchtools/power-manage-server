package store

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Reads are exported one at a time rather than by handing out the
// generated query surface. A read method cannot become a write by
// accident, and the set of things a caller can do to the database
// stays enumerable: this file plus WithAudit.

// AuditOperationRow is one stored operation row.
type AuditOperationRow = generated.AuditOperation

// AuditEffectRow is one stored effect row.
type AuditEffectRow = generated.AuditEffect

// DeviceRow is one stored device.
type DeviceRow = generated.Device

// UserRow is one stored user.
type UserRow = generated.User

// AuditChainTip is a stream's current chain position.
type AuditChainTip struct {
	Stream   string
	HeadHash []byte
	Height   int64
}

// GetAuditOperation returns one operation row. ErrNotFound when the
// operation is unknown or has been archived away by retention.
func (s *Store) GetAuditOperation(ctx context.Context, operationID string) (AuditOperationRow, error) {
	row, err := s.queries.GetAuditOperation(ctx, operationID)
	if err != nil {
		return AuditOperationRow{}, fmt.Errorf("audit: get operation: %w", translateNotFound(err))
	}
	return row, nil
}

// ListAuditEffects returns an operation's effects in the order they
// were recorded, including any appended long after the operation
// itself.
func (s *Store) ListAuditEffects(ctx context.Context, operationID string) ([]AuditEffectRow, error) {
	rows, err := s.queries.ListAuditEffectsForOperation(ctx, operationID)
	if err != nil {
		return nil, fmt.Errorf("audit: list effects: %w", err)
	}
	return rows, nil
}

// AuditChainTipOf returns the stream's current head without locking it.
func (s *Store) AuditChainTipOf(ctx context.Context, stream string) (AuditChainTip, error) {
	if stream == "" {
		stream = DefaultAuditStream
	}
	row, err := s.queries.GetAuditChainHead(ctx, stream)
	if err != nil {
		return AuditChainTip{}, fmt.Errorf("audit: chain head: %w", translateNotFound(err))
	}
	return AuditChainTip{Stream: row.Stream, HeadHash: row.HeadHash, Height: row.Height}, nil
}

// CountAuditOperations returns how many operation rows a stream
// currently holds.
func (s *Store) CountAuditOperations(ctx context.Context, stream string) (int64, error) {
	if stream == "" {
		stream = DefaultAuditStream
	}
	n, err := s.queries.CountAuditOperations(ctx, stream)
	if err != nil {
		return 0, fmt.Errorf("audit: count operations: %w", err)
	}
	return n, nil
}

// GetDevice returns one live device. ErrNotFound when it is unknown or
// deleted.
func (s *Store) GetDevice(ctx context.Context, id string) (DeviceRow, error) {
	row, err := s.queries.GetDevice(ctx, id)
	if err != nil {
		return DeviceRow{}, fmt.Errorf("device: get: %w", translateNotFound(err))
	}
	return row, nil
}

// CountDevices returns the number of live devices.
func (s *Store) CountDevices(ctx context.Context) (int64, error) {
	n, err := s.queries.CountDevices(ctx)
	if err != nil {
		return 0, fmt.Errorf("device: count: %w", err)
	}
	return n, nil
}

// GetUser returns one live user. ErrNotFound when unknown or deleted.
func (s *Store) GetUser(ctx context.Context, id string) (UserRow, error) {
	row, err := s.queries.GetUser(ctx, id)
	if err != nil {
		return UserRow{}, fmt.Errorf("user: get: %w", translateNotFound(err))
	}
	return row, nil
}

// CountUsers returns the number of live users.
func (s *Store) CountUsers(ctx context.Context) (int64, error) {
	n, err := s.queries.CountUsers(ctx)
	if err != nil {
		return 0, fmt.Errorf("user: count: %w", err)
	}
	return n, nil
}

// GetUserEncryptionKey returns a subject's wrapped DEK. ErrNotFound
// when the subject has no key, which for an erased subject IS the
// expected state.
func (s *Store) GetUserEncryptionKey(ctx context.Context, userID string) (generated.UserEncryptionKey, error) {
	row, err := s.queries.GetUserEncryptionKey(ctx, userID)
	if err != nil {
		return generated.UserEncryptionKey{}, fmt.Errorf("user_encryption_key: get: %w", translateNotFound(err))
	}
	return row, nil
}
