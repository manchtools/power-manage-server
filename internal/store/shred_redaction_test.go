package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// userProjectionPII reads the raw PII columns of a (possibly deleted)
// user projection row — Repos().User.Get filters is_deleted, so the
// erased row is only reachable by direct query.
func userProjectionPII(t *testing.T, st *store.Store, userID string) map[string]string {
	t.Helper()
	cols := map[string]string{}
	var email, display, given, family, preferred, picture, linux string
	err := st.TestingPool().QueryRow(context.Background(),
		`SELECT email, display_name, given_name, family_name, preferred_username, picture, linux_username
		   FROM users_projection WHERE id = $1`, userID).
		Scan(&email, &display, &given, &family, &preferred, &picture, &linux)
	require.NoError(t, err)
	cols["email"], cols["display_name"], cols["given_name"] = email, display, given
	cols["family_name"], cols["preferred_username"], cols["picture"], cols["linux_username"] = family, preferred, picture, linux
	return cols
}

func seedUserWithProfile(t *testing.T, st *store.Store) string {
	t.Helper()
	ctx := context.Background()
	userID := testutil.CreateTestUser(t, st, "prof-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	dn, gn, fn := "Alice Example", "Alice", "Example"
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", StreamID: userID, EventType: "UserProfileUpdated",
		Data:      map[string]any{"display_name": dn, "given_name": gn, "family_name": fn},
		ActorType: "user", ActorID: userID,
	}))
	return userID
}

// TestUserDeleted_RedactsAllPIIColumns pins AC 7: the UserDeleted
// projector overwrites every PII column with the redaction sentinel.
func TestUserDeleted_RedactsAllPIIColumns(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	userID := seedUserWithProfile(t, st)
	before := userProjectionPII(t, st, userID)
	require.Equal(t, "Alice", before["given_name"], "precondition: profile projected in plaintext")

	require.NoError(t, st.AppendUserDeletionWithShred(ctx, userDeletedEvent(userID)))

	after := userProjectionPII(t, st, userID)
	for col, v := range after {
		assert.Equalf(t, crypto.RedactionSentinel, v,
			"PII column %q must be redacted after delete, got %q", col, v)
	}
}

// TestUserDeleted_RebuildReproducesSentinel pins AC 11: a rebuild
// reproduces the deleted user's PII as the sentinel while live users
// reproduce 1:1 — live delete and rebuild share the one redaction path.
func TestUserDeleted_RebuildReproducesSentinel(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	deleted := seedUserWithProfile(t, st)
	liveEmail := "live-" + testutil.NewID()[:8] + "@test.com"
	live := testutil.CreateTestUser(t, st, liveEmail, "pass", "user")

	require.NoError(t, st.AppendUserDeletionWithShred(ctx, userDeletedEvent(deleted)))

	_, err := st.RebuildAll(ctx)
	require.NoError(t, err)

	after := userProjectionPII(t, st, deleted)
	assert.Equal(t, crypto.RedactionSentinel, after["email"],
		"deleted user's PII reproduces as the sentinel after rebuild")

	liveUser, err := st.Repos().User.Get(ctx, live)
	require.NoError(t, err)
	assert.Equal(t, liveEmail, liveUser.Email, "live users reproduce 1:1")
}
