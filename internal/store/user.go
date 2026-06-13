package store

import (
	"context"
	"time"
)

// User is the user projection row. PasswordHash stays encoded
// as-stored at the boundary; handlers verify against auth.VerifyPassword
// when they actually need to consume those bytes.
//
// SshPublicKeys is a typed slice loaded from the user_ssh_keys child
// table (Wave E.3, tracker #242) — repo implementations populate it
// alongside the core row.
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
	SshPublicKeys           []SshPublicKey
	SshAccessEnabled        bool
	SshAllowPubkey          bool
	SshAllowPassword        bool
	SystemUserActionID      string
	SystemSshActionID       string
	UserProvisioningEnabled bool
	SystemTtyActionID       string
}

// SshPublicKey is one row from the user_ssh_keys child table. PublicKey
// and Comment are pointers because the projector preserves "field
// absent in payload" semantics (PL/pgSQL parity: missing keys become
// SQL NULL, which round-trips as nil for downstream consumers).
type SshPublicKey struct {
	KeyID     string
	PublicKey *string
	Comment   *string
	AddedAt   time.Time
}

// UserSessionInfo is the narrow shape returned for the refresh-token
// validation path. Pulling only the three fields the handler needs
// keeps the hot login path light.
type UserSessionInfo struct {
	Disabled       bool
	SessionVersion int32
	IsDeleted      bool
}

// ListUsersFilter is the pagination shape for the user list endpoint,
// plus the #3 user-group scope restriction.
type ListUsersFilter struct {
	Limit  int32
	Offset int32
	Scope  ScopeGroupFilter
}

// ScopedGrant is one (permission, scope) tuple a user holds. ScopeKind
// and ScopeID are empty together for an unscoped (global) grant; when
// set, ScopeKind is one of "device_group" / "user_group" and ScopeID is
// the group's id. The permission is constrained to that scope (#7 S2b).
type ScopedGrant struct {
	Permission string
	ScopeKind  string
	ScopeID    string
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

	// ScopedGrants returns every (permission, scope) tuple the user
	// holds — from direct role grants AND grants inherited via
	// user-group membership — carrying each grant's scope. A grant with
	// no scope (ScopeKind/ScopeID empty) is global. The cascade is a
	// property of the GRANT: every permission a grant materializes
	// inherits the grant's scope. Drives the JWT `sgrants` claim and the
	// auth scope-enforcement primitives (#7 S2b).
	ScopedGrants(ctx context.Context, userID string) ([]ScopedGrant, error)

	// NextLinuxUID returns the next available Linux UID for new
	// user provisioning. The underlying query is a SERIAL-style
	// allocator backed by users.linux_uid + a synthesized bump.
	NextLinuxUID(ctx context.Context) (int32, error)

	// List returns a page of users.
	List(ctx context.Context, filter ListUsersFilter) ([]User, error)

	// Count returns the total non-deleted user count, scoped to the
	// caller's user-group scope when restricted.
	Count(ctx context.Context, scope ScopeGroupFilter) (int64, error)

	// ListAllNonDeleted returns every non-deleted user. Used by
	// the server-settings handler's batch-enable propagation
	// (provisioning + SSH access) and the system-action
	// reconciler — both of which legitimately need every user.
	ListAllNonDeleted(ctx context.Context) ([]User, error)
}
