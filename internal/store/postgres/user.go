package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// User implements store.UserRepo against users_projection.
type User struct {
	q *generated.Queries
}

// NewUser returns a User repo bound to the given sqlc handle.
func NewUser(q *generated.Queries) *User {
	return &User{q: q}
}

func (u *User) Get(ctx context.Context, id string) (store.User, error) {
	row, err := u.q.GetUserByID(ctx, id)
	if err != nil {
		return store.User{}, fmt.Errorf("user: get: %w", translateNotFound(err))
	}
	return userFromRow(row), nil
}

func (u *User) GetByEmail(ctx context.Context, email string) (store.User, error) {
	row, err := u.q.GetUserByEmail(ctx, email)
	if err != nil {
		return store.User{}, fmt.Errorf("user: get by email: %w", translateNotFound(err))
	}
	return userFromRow(row), nil
}

func (u *User) SessionInfo(ctx context.Context, userID string) (store.UserSessionInfo, error) {
	row, err := u.q.GetUserSessionInfo(ctx, userID)
	if err != nil {
		return store.UserSessionInfo{}, fmt.Errorf("user: session info: %w", translateNotFound(err))
	}
	return store.UserSessionInfo{
		Disabled:       row.Disabled,
		SessionVersion: row.SessionVersion,
		IsDeleted:      row.IsDeleted,
	}, nil
}

func (u *User) Permissions(ctx context.Context, userID string) ([]string, error) {
	perms, err := u.q.GetUserPermissionsWithGroups(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user: permissions: %w", err)
	}
	return perms, nil
}

func (u *User) NextLinuxUID(ctx context.Context) (int32, error) {
	uid, err := u.q.GetNextLinuxUID(ctx)
	if err != nil {
		return 0, fmt.Errorf("user: next linux uid: %w", translateNotFound(err))
	}
	return uid, nil
}

func (u *User) List(ctx context.Context, filter store.ListUsersFilter) ([]store.User, error) {
	rows, err := u.q.ListUsers(ctx, generated.ListUsersParams{
		Limit:  filter.Limit,
		Offset: filter.Offset,
	})
	if err != nil {
		return nil, fmt.Errorf("user: list: %w", err)
	}
	out := make([]store.User, len(rows))
	for i, r := range rows {
		out[i] = userFromRow(r)
	}
	return out, nil
}

func (u *User) Count(ctx context.Context) (int64, error) {
	n, err := u.q.CountUsers(ctx)
	if err != nil {
		return 0, fmt.Errorf("user: count: %w", translateNotFound(err))
	}
	return n, nil
}

func (u *User) ListAllNonDeleted(ctx context.Context) ([]store.User, error) {
	rows, err := u.q.ListAllNonDeletedUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("user: list all non-deleted: %w", err)
	}
	out := make([]store.User, len(rows))
	for i, r := range rows {
		out[i] = userFromRow(r)
	}
	return out, nil
}

// userFromRow translates a sqlc projection row to the domain shape.
// Shared so the field mapping lives in one place.
func userFromRow(r generated.UsersProjection) store.User {
	return store.User{
		ID:                      r.ID,
		Email:                   r.Email,
		PasswordHash:            r.PasswordHash,
		Role:                    r.Role,
		CreatedAt:               r.CreatedAt,
		UpdatedAt:               r.UpdatedAt,
		LastLoginAt:             r.LastLoginAt,
		Disabled:                r.Disabled,
		IsDeleted:               r.IsDeleted,
		SessionVersion:          r.SessionVersion,
		HasPassword:             r.HasPassword,
		TotpEnabled:             r.TotpEnabled,
		DisplayName:             r.DisplayName,
		GivenName:               r.GivenName,
		FamilyName:              r.FamilyName,
		PreferredUsername:       r.PreferredUsername,
		Picture:                 r.Picture,
		Locale:                  r.Locale,
		LinuxUsername:           r.LinuxUsername,
		LinuxUID:                r.LinuxUid,
		SshPublicKeys:           json.RawMessage(r.SshPublicKeys),
		SshAccessEnabled:        r.SshAccessEnabled,
		SshAllowPubkey:          r.SshAllowPubkey,
		SshAllowPassword:        r.SshAllowPassword,
		SystemUserActionID:      r.SystemUserActionID,
		SystemSshActionID:       r.SystemSshActionID,
		UserProvisioningEnabled: r.UserProvisioningEnabled,
		SystemTtyActionID:       r.SystemTtyActionID,
	}
}
