package auth

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
)

type contextKey string

const (
	userContextKey contextKey = "user"
)

// PrincipalKind names what sort of actor is on the request.
type PrincipalKind string

const (
	// PrincipalUser is an ordinary human subject with a row in users.
	// Only this kind can own a resource, and therefore only this kind
	// can satisfy a `:self` grant.
	PrincipalUser PrincipalKind = "user"
	// PrincipalBootstrapAdmin is the host-authorized setup principal.
	// It is permanently reserved, has no users row, and can never be
	// the owner of anything.
	PrincipalBootstrapAdmin PrincipalKind = "bootstrap_admin"
)

// BootstrapPrincipalID is the reserved actor id of the bootstrap-admin
// principal.
//
// It is deliberately NOT a ULID. Every owner id in this system is a
// ULID, and ULIDs are 26 Crockford-base32 characters, so this value
// cannot equal any user's id no matter how the comparison is reached.
// That is the second of two independent barriers against the principal
// satisfying `:self`; the first is PrincipalKind.
const BootstrapPrincipalID = "bootstrap-admin"

// UserContext is the authenticated actor on a request.
type UserContext struct {
	ID             string
	Kind           PrincipalKind
	Email          string
	Permissions    []string
	ScopedGrants   []ScopedGrant
	SessionVersion int32
}

// CanOwnResources reports whether this principal may be the owner of a
// resource, which is the precondition for a `:self` grant to admit it.
//
// Both barriers are checked here rather than at each call site: the
// principal must be an ordinary user AND its id must be a well-formed
// ULID. A reserved non-user principal fails on both counts.
func (u *UserContext) CanOwnResources() bool {
	if u == nil || u.Kind != PrincipalUser {
		return false
	}
	_, err := ulid.ParseStrict(u.ID)
	return err == nil
}

// WithUser puts the authenticated actor on the context.
func WithUser(ctx context.Context, user *UserContext) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

// UserFromContext retrieves the authenticated actor.
func UserFromContext(ctx context.Context) (*UserContext, bool) {
	user, ok := ctx.Value(userContextKey).(*UserContext)
	if !ok || user == nil {
		return nil, false
	}
	return user, true
}

// HasPermission reports whether the actor holds a permission key
// exactly.
func HasPermission(ctx context.Context, perm string) bool {
	user, ok := UserFromContext(ctx)
	if !ok {
		return false
	}
	for _, p := range user.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}

// EnforceSelfScope admits an actor holding the unrestricted permission,
// or one holding only the `:self` variant when the target is the actor
// itself.
//
// A principal that cannot own resources is refused on the `:self` path
// even if it somehow holds the key: `:self` means "the row that is me",
// and a reserved non-user principal is no row.
func EnforceSelfScope(ctx context.Context, action, resourceID string) error {
	user, ok := UserFromContext(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}
	if HasPermission(ctx, action) {
		return nil
	}
	if HasPermission(ctx, action+":self") && user.CanOwnResources() && resourceID == user.ID {
		return nil
	}
	return connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
}
