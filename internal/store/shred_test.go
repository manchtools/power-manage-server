package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// Spec 19 AC 7/14 — the shared delete-with-shred flow: appending
// UserDeleted and destroying the user's DEK happen in ONE transaction,
// all-or-nothing.

func hasDEK(t *testing.T, st *store.Store, userID string) bool {
	t.Helper()
	_, err := st.Repos().UserEncryptionKey.Get(context.Background(), userID)
	if err == nil {
		return true
	}
	require.True(t, store.IsNotFound(err), "unexpected error: %v", err)
	return false
}

func userDeletedEvent(userID string) store.Event {
	return store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  "UserDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userID,
	}
}

func countUserEvents(t *testing.T, st *store.Store, userID, eventType string) int {
	t.Helper()
	var n int
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		`SELECT COUNT(*) FROM events WHERE stream_id = $1 AND event_type = $2`,
		userID, eventType).Scan(&n))
	return n
}

// TestAppendUserDeletionWithShred_AppendsAndShredsAtomically pins AC 7:
// the DEK is destroyed and the UserDeleted event is appended together.
func TestAppendUserDeletionWithShred_AppendsAndShredsAtomically(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, "shred-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	require.True(t, hasDEK(t, st, userID), "precondition: user has a DEK")

	require.NoError(t, st.AppendUserDeletionWithShred(ctx, userDeletedEvent(userID)))

	assert.False(t, hasDEK(t, st, userID), "the DEK must be destroyed (crypto-shred)")
	assert.Equal(t, 1, countUserEvents(t, st, userID, "UserDeleted"), "UserDeleted appended exactly once")
}

// TestAppendUserDeletionWithShred_FiresProjector pins that the
// post-commit listeners run — the UserDeleted projector soft-deletes
// and redacts (AC 7 end to end).
func TestAppendUserDeletionWithShred_FiresProjector(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	email := "fire-" + testutil.NewID()[:8] + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")

	require.NoError(t, st.AppendUserDeletionWithShred(ctx, userDeletedEvent(userID)))

	// Soft-deleted: no longer visible via the active-user query.
	_, err := st.Repos().User.GetByEmail(ctx, email)
	assert.True(t, store.IsNotFound(err), "deleted user must not resolve by email")
}

// TestAppendUserDeletionWithShred_Idempotent pins the store-level
// idempotency (defense in depth): re-running for an already-deleted user is a
// no-op success — DEK stays absent, no duplicate/orphaned writes. The API
// handler never re-enters this flow for an erased user (it returns uniform
// NotFound, AC 13); this idempotency backs the SCIM path and direct callers.
func TestAppendUserDeletionWithShred_Idempotent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, "idem-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	require.NoError(t, st.AppendUserDeletionWithShred(ctx, userDeletedEvent(userID)))
	require.NoError(t, st.AppendUserDeletionWithShred(ctx, userDeletedEvent(userID)),
		"a second shred of an already-erased user is a no-op success")

	assert.False(t, hasDEK(t, st, userID))
}

// TestAppendUserDeletionWithShred_DEKShredFailureRollsBack pins AC 14: if the
// DEK delete fails, the whole transaction rolls back — the already-appended
// UserDeleted event does NOT survive and the projection stays unredacted
// (no half-erased state). The failure is injected AT the shred step (after
// the append) so the rollback of a committed-in-tx append is what's proven.
func TestAppendUserDeletionWithShred_DEKShredFailureRollsBack(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	email := "rollback-" + testutil.NewID()[:8] + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")
	require.True(t, hasDEK(t, st, userID), "precondition: user has a DEK")

	st.TestingSetDEKShredHook(func(string) error { return errors.New("injected DEK-delete failure") })

	err := st.AppendUserDeletionWithShred(ctx, userDeletedEvent(userID))
	require.Error(t, err, "a DEK-shred failure must surface as an error")

	assert.Equal(t, 0, countUserEvents(t, st, userID, "UserDeleted"),
		"AC 14: no UserDeleted event may survive a rolled-back shred")
	assert.True(t, hasDEK(t, st, userID),
		"AC 14: the DEK must still be present — nothing was destroyed")
	_, gerr := st.Repos().User.GetByEmail(ctx, email)
	require.NoError(t, gerr, "AC 14: the projection stays unredacted — the user still resolves")

	// Clear the seam: a normal shred now succeeds, proving the hook was the
	// only thing blocking (the flow itself is healthy).
	st.TestingSetDEKShredHook(nil)
	require.NoError(t, st.AppendUserDeletionWithShred(ctx, userDeletedEvent(userID)))
	assert.False(t, hasDEK(t, st, userID))
}
