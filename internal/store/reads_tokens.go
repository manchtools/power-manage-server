package store

import (
	"context"
	"fmt"

	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// RegistrationTokenRow is the non-secret stored registration-token shape.
// value_hash remains internal to the state service and is never copied onto
// the protobuf read surface.
type RegistrationTokenRow = db.Token

// RegistrationTokenListFilter is the deterministic keyset page requested by
// the registration-token RPC surface.
type RegistrationTokenListFilter struct {
	AfterID         string
	Limit           int32
	IncludeDisabled bool
}

// GetRegistrationToken returns one live, non-bootstrap registration token.
func (s *Store) GetRegistrationToken(ctx context.Context, id string) (RegistrationTokenRow, error) {
	row, err := s.queries.GetRegistrationToken(ctx, db.GetRegistrationTokenParams{
		ID: id, ReservedName: BootstrapAdminTokenName,
	})
	if err != nil {
		return RegistrationTokenRow{}, fmt.Errorf("registration token: get: %w", translateNotFound(err))
	}
	return row, nil
}

// ListRegistrationTokens returns live non-bootstrap tokens in id order.
func (s *Store) ListRegistrationTokens(ctx context.Context, f RegistrationTokenListFilter) ([]RegistrationTokenRow, error) {
	rows, err := s.queries.ListRegistrationTokens(ctx, db.ListRegistrationTokensParams{
		ReservedName: BootstrapAdminTokenName, AfterID: f.AfterID,
		IncludeDisabled: f.IncludeDisabled, RowLimit: f.Limit,
	})
	if err != nil {
		return nil, fmt.Errorf("registration token: list: %w", err)
	}
	return rows, nil
}

// CountRegistrationTokens counts the same live token population as the list.
func (s *Store) CountRegistrationTokens(ctx context.Context, includeDisabled bool) (int64, error) {
	n, err := s.queries.CountRegistrationTokens(ctx, db.CountRegistrationTokensParams{
		ReservedName: BootstrapAdminTokenName, IncludeDisabled: includeDisabled,
	})
	if err != nil {
		return 0, fmt.Errorf("registration token: count: %w", err)
	}
	return n, nil
}
