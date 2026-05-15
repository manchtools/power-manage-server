package postgres

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// UserSelection implements store.UserSelectionRepo against
// user_selections_projection.
type UserSelection struct {
	q *generated.Queries
}

// NewUserSelection returns a UserSelection repo bound to the given
// sqlc handle.
func NewUserSelection(q *generated.Queries) *UserSelection {
	return &UserSelection{q: q}
}

func (u *UserSelection) Get(ctx context.Context, key store.GetUserSelectionKey) (store.UserSelection, error) {
	row, err := u.q.GetUserSelection(ctx, generated.GetUserSelectionParams{
		DeviceID:   key.DeviceID,
		SourceType: key.SourceType,
		SourceID:   key.SourceID,
	})
	if err != nil {
		return store.UserSelection{}, fmt.Errorf("user_selection: get: %w", translateNotFound(err))
	}
	return userSelectionFromRow(row), nil
}

func (u *UserSelection) ListForDevice(ctx context.Context, deviceID string) ([]store.UserSelection, error) {
	rows, err := u.q.ListUserSelectionsForDevice(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("user_selection: list for device: %w", err)
	}
	out := make([]store.UserSelection, len(rows))
	for i, row := range rows {
		out[i] = userSelectionFromRow(row)
	}
	return out, nil
}

func userSelectionFromRow(row generated.UserSelectionsProjection) store.UserSelection {
	return store.UserSelection{
		ID:         row.ID,
		DeviceID:   row.DeviceID,
		SourceType: row.SourceType,
		SourceID:   row.SourceID,
		Selected:   row.Selected,
		UpdatedAt:  row.UpdatedAt,
		CreatedBy:  row.CreatedBy,
	}
}
