package postgres

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Settings implements store.SettingsRepo against the Postgres
// server_settings_projection via sqlc-generated queries.
type Settings struct {
	q *generated.Queries
}

// NewSettings returns a Settings repo bound to the given sqlc handle.
func NewSettings(q *generated.Queries) *Settings {
	return &Settings{q: q}
}

// GetServer returns the global settings row, translating
// pgx.ErrNoRows to store.ErrNotFound at the repo boundary so callers
// rely solely on store.IsNotFound.
func (s *Settings) GetServer(ctx context.Context) (store.ServerSettings, error) {
	row, err := s.q.GetServerSettings(ctx)
	if err != nil {
		return store.ServerSettings{}, fmt.Errorf("settings: get server: %w", translateNotFound(err))
	}
	return store.ServerSettings{
		UserProvisioningEnabled: row.UserProvisioningEnabled,
		SshAccessForAll:         row.SshAccessForAll,
		UpdatedAt:               row.UpdatedAt,
	}, nil
}
