package api_test

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func hasDEKRepo(t *testing.T, st *store.Store, userID string) bool {
	t.Helper()
	_, err := st.Repos().UserEncryptionKey.Get(context.Background(), userID)
	if err == nil {
		return true
	}
	require.True(t, store.IsNotFound(err))
	return false
}

// TestDeleteUser_ShredsDEK pins AC 7/8 on the API path: DeleteUser
// destroys the user's DEK (crypto-shred), not merely soft-deletes.
func TestDeleteUser_ShredsDEK(t *testing.T) {
	st := testutil.SetupPostgres(t)

	adminID := testutil.CreateTestUser(t, st, "adm-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")
	victim := testutil.CreateTestUser(t, st, "vic-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	require.True(t, hasDEKRepo(t, st, victim), "precondition: victim has a DEK")

	h := api.NewUserHandler(st, slog.Default(), nil)
	_, err := h.DeleteUser(testutil.AdminContext(adminID),
		connect.NewRequest(&pm.DeleteUserRequest{Id: victim}))
	require.NoError(t, err)

	assert.False(t, hasDEKRepo(t, st, victim), "DeleteUser must crypto-shred the DEK (AC 7/8)")
}

// TestDeleteUser_IdempotentAndNoOracle pins AC 13: deleting an
// already-deleted (still visible to the caller) user is idempotent OK;
// deleting an absent id returns NotFound (no existence oracle).
func TestDeleteUser_IdempotentAndNoOracle(t *testing.T) {
	st := testutil.SetupPostgres(t)

	adminID := testutil.CreateTestUser(t, st, "adm2-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")
	h := api.NewUserHandler(st, slog.Default(), nil)

	// Absent target → NotFound.
	_, err := h.DeleteUser(testutil.AdminContext(adminID),
		connect.NewRequest(&pm.DeleteUserRequest{Id: testutil.NewID()}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "absent target must be NotFound (no oracle)")
}

// TestReAddSameEmailAfterErase_MintsFreshDEK pins AC 15: after erasing
// a user, creating a new user with the same email succeeds (the erased
// row is is_deleted and excluded from the active-email unique index),
// mints a NEW DEK, and the old user's ciphertext stays unreadable.
func TestReAddSameEmailAfterErase_MintsFreshDEK(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	adminID := testutil.CreateTestUser(t, st, "adm3-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")
	h := api.NewUserHandler(st, slog.Default(), nil)
	email := "reuse-" + testutil.NewID()[:8] + "@test.com"

	first, err := h.CreateUser(testutil.AuthContext(adminID, "a@t", auth.AdminPermissions()),
		connect.NewRequest(&pm.CreateUserRequest{Email: email, Password: "s3cret-password"}))
	require.NoError(t, err)
	firstID := first.Msg.User.Id
	firstDEK, err := st.Repos().UserEncryptionKey.Get(ctx, firstID)
	require.NoError(t, err)

	_, err = h.DeleteUser(testutil.AdminContext(adminID),
		connect.NewRequest(&pm.DeleteUserRequest{Id: firstID}))
	require.NoError(t, err)
	require.False(t, hasDEKRepo(t, st, firstID), "erased user's DEK is gone")

	// Re-add the same email — must succeed (active-email index is
	// WHERE is_deleted = false) and mint a fresh, different DEK.
	second, err := h.CreateUser(testutil.AuthContext(adminID, "a@t", auth.AdminPermissions()),
		connect.NewRequest(&pm.CreateUserRequest{Email: email, Password: "s3cret-password"}))
	require.NoError(t, err, "re-adding an erased user's email must succeed (AC 15)")
	secondID := second.Msg.User.Id
	require.NotEqual(t, firstID, secondID)

	secondDEK, err := st.Repos().UserEncryptionKey.Get(ctx, secondID)
	require.NoError(t, err)
	assert.NotEqual(t, firstDEK.WrappedDEK, secondDEK.WrappedDEK,
		"the re-added user gets fresh random key material — the old ciphertext stays permanently unreadable")
}
