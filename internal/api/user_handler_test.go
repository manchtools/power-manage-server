package api_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestCreateUser_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateUser(ctx, connect.NewRequest(&pm.CreateUserRequest{
		Email:    testutil.NewID() + "@new.com",
		Password: "secure-pass-123",
		Role:     "user",
	}))
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Msg.User.Id)
	assert.Equal(t, "user", resp.Msg.User.Role)
	assert.False(t, resp.Msg.User.Disabled)
}

func TestCreateUser_RoleRequired(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.CreateUser(ctx, connect.NewRequest(&pm.CreateUserRequest{
		Email:    testutil.NewID() + "@new.com",
		Password: "secure-pass-123",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestCreateUser_Unauthenticated(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st)

	_, err := h.CreateUser(context.Background(), connect.NewRequest(&pm.CreateUserRequest{
		Email:    "test@test.com",
		Password: "secure-pass-123",
		Role:     "user",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestGetUser_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st)

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")
	ctx := testutil.AdminContext(testutil.NewID())

	resp, err := h.GetUser(ctx, connect.NewRequest(&pm.GetUserRequest{Id: userID}))
	require.NoError(t, err)

	assert.Equal(t, userID, resp.Msg.User.Id)
	assert.Equal(t, email, resp.Msg.User.Email)
}

func TestGetUser_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st)
	ctx := testutil.AdminContext(testutil.NewID())

	_, err := h.GetUser(ctx, connect.NewRequest(&pm.GetUserRequest{Id: testutil.NewID()}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestListUsers_Pagination(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st)

	for i := 0; i < 5; i++ {
		testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	}

	ctx := testutil.AdminContext(testutil.NewID())

	resp, err := h.ListUsers(ctx, connect.NewRequest(&pm.ListUsersRequest{PageSize: 3}))
	require.NoError(t, err)
	assert.Len(t, resp.Msg.Users, 3)
	assert.NotEmpty(t, resp.Msg.NextPageToken)
	assert.GreaterOrEqual(t, resp.Msg.TotalCount, int32(5))

	// Fetch next page
	resp2, err := h.ListUsers(ctx, connect.NewRequest(&pm.ListUsersRequest{
		PageSize:  3,
		PageToken: resp.Msg.NextPageToken,
	}))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp2.Msg.Users), 2)
}

func TestUpdateUserEmail(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	ctx := testutil.AdminContext(adminID)

	newEmail := testutil.NewID() + "@updated.com"
	resp, err := h.UpdateUserEmail(ctx, connect.NewRequest(&pm.UpdateUserEmailRequest{
		Id:    userID,
		Email: newEmail,
	}))
	require.NoError(t, err)
	assert.Equal(t, newEmail, resp.Msg.User.Email)
}

func TestUpdateUserPassword_Self(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st)

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "old-password", "user")
	ctx := testutil.UserContext(userID)

	_, err := h.UpdateUserPassword(ctx, connect.NewRequest(&pm.UpdateUserPasswordRequest{
		Id:              userID,
		CurrentPassword: "old-password",
		NewPassword:     "new-password-123",
	}))
	require.NoError(t, err)
}

func TestUpdateUserPassword_Self_WrongCurrent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st)

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "real-password", "user")
	ctx := testutil.UserContext(userID)

	_, err := h.UpdateUserPassword(ctx, connect.NewRequest(&pm.UpdateUserPasswordRequest{
		Id:              userID,
		CurrentPassword: "wrong-password",
		NewPassword:     "new-password",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestUpdateUserPassword_Admin(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	ctx := testutil.AdminContext(adminID)

	_, err := h.UpdateUserPassword(ctx, connect.NewRequest(&pm.UpdateUserPasswordRequest{
		Id:          userID,
		NewPassword: "admin-set-password",
	}))
	require.NoError(t, err)
}

func TestUpdateUserRole(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.UpdateUserRole(ctx, connect.NewRequest(&pm.UpdateUserRoleRequest{
		Id:   userID,
		Role: "admin",
	}))
	require.NoError(t, err)
	assert.Equal(t, "admin", resp.Msg.User.Role)
}

func TestSetUserDisabled(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.SetUserDisabled(ctx, connect.NewRequest(&pm.SetUserDisabledRequest{
		Id:       userID,
		Disabled: true,
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.User.Disabled)

	resp, err = h.SetUserDisabled(ctx, connect.NewRequest(&pm.SetUserDisabledRequest{
		Id:       userID,
		Disabled: false,
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.User.Disabled)
}

func TestDeleteUser(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	ctx := testutil.AdminContext(adminID)

	_, err := h.DeleteUser(ctx, connect.NewRequest(&pm.DeleteUserRequest{Id: userID}))
	require.NoError(t, err)

	// User should not be found
	_, err = h.GetUser(ctx, connect.NewRequest(&pm.GetUserRequest{Id: userID}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}
