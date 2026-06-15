package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithUser_UserFromContext(t *testing.T) {
	user := &UserContext{ID: "u1", Email: "a@b.com", Permissions: []string{"ListDevices"}}
	ctx := WithUser(context.Background(), user)

	got, ok := UserFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "u1", got.ID)
	assert.Equal(t, "a@b.com", got.Email)
	assert.Equal(t, []string{"ListDevices"}, got.Permissions)
}

func TestUserFromContext_Empty(t *testing.T) {
	_, ok := UserFromContext(context.Background())
	assert.False(t, ok)
}

func TestHasPermission_Found(t *testing.T) {
	user := &UserContext{ID: "u1", Permissions: []string{"ListDevices", "GetUser:self"}}
	ctx := WithUser(context.Background(), user)

	assert.True(t, HasPermission(ctx, "ListDevices"))
	assert.True(t, HasPermission(ctx, "GetUser:self"))
	assert.False(t, HasPermission(ctx, "CreateUser"))
}

func TestHasPermission_NoUser(t *testing.T) {
	assert.False(t, HasPermission(context.Background(), "ListDevices"))
}
