package auth

import "context"

type contextKey string

const (
	userContextKey   contextKey = "user"
	deviceContextKey contextKey = "device"
)

// UserContext holds authenticated user information.
type UserContext struct {
	ID    string
	Email string
	Role  string
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

// SubjectFromContext returns the subject ID and role from context.
// It checks for user first, then device.
func SubjectFromContext(ctx context.Context) (id, role string, ok bool) {
	if user, ok := UserFromContext(ctx); ok {
		return user.ID, user.Role, true
	}
	if device, ok := DeviceFromContext(ctx); ok {
		return device.ID, "device", true
	}
	return "", "", false
}
