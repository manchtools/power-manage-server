package auth

import "context"

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
