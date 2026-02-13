package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithUser_UserFromContext(t *testing.T) {
	user := &UserContext{ID: "u1", Email: "a@b.com", Role: "admin"}
	ctx := WithUser(context.Background(), user)

	got, ok := UserFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "u1", got.ID)
	assert.Equal(t, "a@b.com", got.Email)
	assert.Equal(t, "admin", got.Role)
}

func TestUserFromContext_Empty(t *testing.T) {
	_, ok := UserFromContext(context.Background())
	assert.False(t, ok)
}

func TestWithDevice_DeviceFromContext(t *testing.T) {
	device := &DeviceContext{ID: "d1", Hostname: "test-host", Fingerprint: "abc123"}
	ctx := WithDevice(context.Background(), device)

	got, ok := DeviceFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "d1", got.ID)
	assert.Equal(t, "test-host", got.Hostname)
	assert.Equal(t, "abc123", got.Fingerprint)
}

func TestDeviceFromContext_Empty(t *testing.T) {
	_, ok := DeviceFromContext(context.Background())
	assert.False(t, ok)
}

func TestSubjectFromContext_User(t *testing.T) {
	user := &UserContext{ID: "u1", Email: "a@b.com", Role: "admin"}
	ctx := WithUser(context.Background(), user)

	id, role, ok := SubjectFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "u1", id)
	assert.Equal(t, "admin", role)
}

func TestSubjectFromContext_Device(t *testing.T) {
	device := &DeviceContext{ID: "d1", Hostname: "host", Fingerprint: "fp"}
	ctx := WithDevice(context.Background(), device)

	id, role, ok := SubjectFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "d1", id)
	assert.Equal(t, "device", role)
}

func TestSubjectFromContext_UserPrecedence(t *testing.T) {
	// If both user and device are in context, user takes precedence
	user := &UserContext{ID: "u1", Email: "a@b.com", Role: "admin"}
	device := &DeviceContext{ID: "d1", Hostname: "host", Fingerprint: "fp"}
	ctx := WithUser(WithDevice(context.Background(), device), user)

	id, role, ok := SubjectFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "u1", id)
	assert.Equal(t, "admin", role)
}

func TestSubjectFromContext_Empty(t *testing.T) {
	_, _, ok := SubjectFromContext(context.Background())
	assert.False(t, ok)
}
