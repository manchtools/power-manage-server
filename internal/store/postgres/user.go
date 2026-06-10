package postgres

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// User implements store.UserRepo against users_projection +
// user_ssh_keys (the SSH keys live in a child table after Wave E.3).
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
	user := userFromRow(row)
	keys, err := u.q.ListUserSshKeys(ctx, id)
	if err != nil {
		return store.User{}, fmt.Errorf("user: list ssh keys: %w", err)
	}
	user.SshPublicKeys = sshKeysFromRows(keys)
	return user, nil
}

func (u *User) GetByEmail(ctx context.Context, email string) (store.User, error) {
	row, err := u.q.GetUserByEmail(ctx, email)
	if err != nil {
		return store.User{}, fmt.Errorf("user: get by email: %w", translateNotFound(err))
	}
	user := userFromRow(row)
	keys, err := u.q.ListUserSshKeys(ctx, user.ID)
	if err != nil {
		return store.User{}, fmt.Errorf("user: list ssh keys: %w", err)
	}
	user.SshPublicKeys = sshKeysFromRows(keys)
	return user, nil
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

func (u *User) ScopedGrants(ctx context.Context, userID string) ([]store.ScopedGrant, error) {
	rows, err := u.q.GetUserScopedGrants(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user: scoped grants: %w", err)
	}
	grants := make([]store.ScopedGrant, len(rows))
	for i, r := range rows {
		grants[i] = store.ScopedGrant{
			Permission: r.Permission,
			ScopeKind:  derefString(r.ScopeKind),
			ScopeID:    derefString(r.ScopeID),
		}
	}
	return grants, nil
}

// derefString returns the pointed-to string, or "" when the pointer is
// nil. The scope columns are nullable TEXT (NULL = unscoped/global), and
// the store contract represents that as an empty string rather than a
// pointer.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
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
	ids := make([]string, len(rows))
	for i, r := range rows {
		out[i] = userFromRow(r)
		ids[i] = r.ID
	}
	if err := u.attachSshKeys(ctx, out, ids); err != nil {
		return nil, err
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
	ids := make([]string, len(rows))
	for i, r := range rows {
		out[i] = userFromRow(r)
		ids[i] = r.ID
	}
	if err := u.attachSshKeys(ctx, out, ids); err != nil {
		return nil, err
	}
	return out, nil
}

// attachSshKeys batch-loads SSH keys for the given user IDs and
// distributes them across the matching slice entries. Single round-trip
// for list endpoints so callers don't N+1.
func (u *User) attachSshKeys(ctx context.Context, users []store.User, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	rows, err := u.q.ListUserSshKeysBatch(ctx, ids)
	if err != nil {
		return fmt.Errorf("user: list ssh keys batch: %w", err)
	}
	byUser := make(map[string][]store.SshPublicKey, len(ids))
	for _, k := range rows {
		byUser[k.UserID] = append(byUser[k.UserID], sshKeyFromRow(k))
	}
	for i := range users {
		users[i].SshPublicKeys = byUser[users[i].ID]
	}
	return nil
}

func sshKeysFromRows(rows []generated.UserSshKey) []store.SshPublicKey {
	if len(rows) == 0 {
		return nil
	}
	out := make([]store.SshPublicKey, len(rows))
	for i, r := range rows {
		out[i] = sshKeyFromRow(r)
	}
	return out
}

func sshKeyFromRow(r generated.UserSshKey) store.SshPublicKey {
	return store.SshPublicKey{
		KeyID:     r.KeyID,
		PublicKey: r.PublicKey,
		Comment:   r.Comment,
		AddedAt:   r.AddedAt,
	}
}

// userFromRow translates a sqlc projection row to the domain shape.
// SshPublicKeys is populated separately from the user_ssh_keys child
// table — callers should follow up with a ListUserSshKeys / batch fetch
// (the Get / List methods on this repo do this automatically).
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
		SshAccessEnabled:        r.SshAccessEnabled,
		SshAllowPubkey:          r.SshAllowPubkey,
		SshAllowPassword:        r.SshAllowPassword,
		SystemUserActionID:      r.SystemUserActionID,
		SystemSshActionID:       r.SystemSshActionID,
		UserProvisioningEnabled: r.UserProvisioningEnabled,
		SystemTtyActionID:       r.SystemTtyActionID,
	}
}
