package store

import (
	"context"
	"encoding/json"
	"time"
)

// User is the user projection row. PasswordHash and SSH key material
// stay encoded as-stored at the boundary; handlers verify against
// auth.VerifyPassword / parse SSH keys when they actually need to
// consume those bytes.
//
// SshPublicKeys is JSON at the row level (an array of {id, key, …}
// objects) and stays as json.RawMessage at the boundary per the
// JSONB normalize plan in #242.
type User struct {
	ID                      string
	Email                   string
	PasswordHash            *string
	Role                    string
	CreatedAt               *time.Time
	UpdatedAt               *time.Time
	LastLoginAt             *time.Time
	Disabled                bool
	IsDeleted               bool
	SessionVersion          int32
	HasPassword             bool
	TotpEnabled             bool
	DisplayName             string
	GivenName               string
	FamilyName              string
	PreferredUsername       string
	Picture                 string
	Locale                  string
	LinuxUsername           string
	LinuxUID                int32
	SshPublicKeys           json.RawMessage
	SshAccessEnabled        bool
	SshAllowPubkey          bool
	SshAllowPassword        bool
	SystemUserActionID      string
	SystemSshActionID       string
	UserProvisioningEnabled bool
	SystemTtyActionID       string
}

// UserSessionInfo is the narrow shape returned for the refresh-token
// validation path. Pulling only the three fields the handler needs
// keeps the hot login path light.
type UserSessionInfo struct {
	Disabled       bool
	SessionVersion int32
	IsDeleted      bool
}

// ListUsersFilter is the pagination shape for the user list endpoint.
type ListUsersFilter struct {
	Limit  int32
	Offset int32
}

// UserRepo reads user-projection state. Writes flow through events
// (UserCreated / UserUpdated / UserDeleted / UserPasswordChanged /
// UserDisabled / etc.) — there are no Set / Update / Delete methods
// on this interface by design.
type UserRepo interface {
	// Get returns a user by ID. Returns ErrNotFound when no user
	// with that ID exists.
	Get(ctx context.Context, id string) (User, error)

	// GetByEmail returns a user by email address. Returns
	// ErrNotFound when the email is not registered.
	GetByEmail(ctx context.Context, email string) (User, error)

	// SessionInfo returns the narrow disabled / session_version /
	// is_deleted shape used by the refresh-token validation path.
	SessionInfo(ctx context.Context, userID string) (UserSessionInfo, error)

	// Permissions returns the flattened permission list for the
	// user, combining direct role permissions with permissions
	// inherited from user_group memberships.
	Permissions(ctx context.Context, userID string) ([]string, error)

	// NextLinuxUID returns the next available Linux UID for new
	// user provisioning. The underlying query is a SERIAL-style
	// allocator backed by users.linux_uid + a synthesized bump.
	NextLinuxUID(ctx context.Context) (int32, error)

	// List returns a page of users.
	List(ctx context.Context, filter ListUsersFilter) ([]User, error)

	// Count returns the total non-deleted user count.
	Count(ctx context.Context) (int64, error)

	// ListAllNonDeleted returns every non-deleted user. Used by
	// the server-settings handler's batch-enable propagation
	// (provisioning + SSH access) and the system-action
	// reconciler — both of which legitimately need every user.
	ListAllNonDeleted(ctx context.Context) ([]User, error)
}
