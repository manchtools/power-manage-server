package auth

import (
	"context"
	"errors"

	"connectrpc.com/connect"
)

type contextKey string

const (
	userContextKey   contextKey = "user"
	deviceContextKey contextKey = "device"
)

// UserContext holds authenticated user information.
type UserContext struct {
	ID             string
	Email          string
	Permissions    []string
	SessionVersion int32
}

// DeviceContext holds authenticated device information.
type DeviceContext struct {
	ID          string
	Hostname    string
	Fingerprint string
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

// WithDevice adds device context to the context.
func WithDevice(ctx context.Context, device *DeviceContext) context.Context {
	return context.WithValue(ctx, deviceContextKey, device)
}

// DeviceFromContext retrieves device context from the context.
func DeviceFromContext(ctx context.Context) (*DeviceContext, bool) {
	device, ok := ctx.Value(deviceContextKey).(*DeviceContext)
	return device, ok
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

// SubjectFromContext returns the subject ID from context.
// It checks for user first, then device.
func SubjectFromContext(ctx context.Context) (id string, isDevice bool, ok bool) {
	if user, ok := UserFromContext(ctx); ok {
		return user.ID, false, true
	}
	if device, ok := DeviceFromContext(ctx); ok {
		return device.ID, true, true
	}
	return "", false, false
}
