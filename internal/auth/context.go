package auth

import (
	"context"
	"errors"

	"connectrpc.com/connect"
)

type contextKey string

const (
	userContextKey contextKey = "user"
)

// UserContext holds authenticated user information.
type UserContext struct {
	ID             string
	Email          string
	Permissions    []string
	ScopedGrants   []ScopedGrant
	SessionVersion int32
}

// WithUser adds user context to the context.
func WithUser(ctx context.Context, user *UserContext) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

// UserFromContext retrieves user context from the context.
func UserFromContext(ctx context.Context) (*UserContext, bool) {
	user, ok := ctx.Value(userContextKey).(*UserContext)
	return user, ok
}

// HasPermission checks if the user in context has a specific permission (exact match).
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

// EnforceSelfScope checks whether the caller has the unrestricted permission
// or only the :self scoped variant. When only :self is present, it verifies
// that resourceID matches the caller's ID.
func EnforceSelfScope(ctx context.Context, action, resourceID string) error {
	user, ok := UserFromContext(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}
	if HasPermission(ctx, action) {
		return nil
	}
	if HasPermission(ctx, action+":self") {
		if resourceID == user.ID {
			return nil
		}
		return connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
	}
	return connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
}
