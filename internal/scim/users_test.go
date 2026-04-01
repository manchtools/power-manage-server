package scim_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestSCIMCreateUser_LinuxFieldsPopulated verifies that SCIM user creation
// populates linux_username and linux_uid in the user projection. This is a
// regression test for a bug where SCIM-created users had empty linux fields,
// which broke user provisioning on managed devices.
func TestSCIMCreateUser_LinuxFieldsPopulated(t *testing.T) {
	env := setupSCIM(t)

	user := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   "linux-test@example.com",
		"externalId": "ext-linux-test",
		"active":     true,
	}

	w := env.request("POST", "/Users", user)
	require.Equal(t, http.StatusCreated, w.Code)

	var created map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	userID := created["id"].(string)

	// Verify the user projection has linux fields populated
	dbUser, err := env.st.Queries().GetUserByID(context.Background(), userID)
	require.NoError(t, err)
	assert.NotEmpty(t, dbUser.LinuxUsername, "SCIM-created user must have linux_username")
	assert.Greater(t, dbUser.LinuxUid, int32(0), "SCIM-created user must have linux_uid > 0")
}

// TestSCIMCreateUser_LinuxUIDUniqueness verifies that multiple SCIM-created
// users get unique linux UIDs. A duplicate UID would cause conflicts when
// provisioning users on managed devices.
func TestSCIMCreateUser_LinuxUIDUniqueness(t *testing.T) {
	env := setupSCIM(t)

	uids := make(map[int32]string)
	for i := 0; i < 5; i++ {
		user := map[string]any{
			"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			"userName":   testutil.NewID()[:8] + "@example.com",
			"externalId": "ext-uid-" + testutil.NewID()[:8],
			"active":     true,
		}

		w := env.request("POST", "/Users", user)
		require.Equal(t, http.StatusCreated, w.Code)

		var created map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
		userID := created["id"].(string)

		dbUser, err := env.st.Queries().GetUserByID(context.Background(), userID)
		require.NoError(t, err)

		existing, dupe := uids[dbUser.LinuxUid]
		assert.False(t, dupe, "linux_uid %d duplicated between users %s and %s", dbUser.LinuxUid, existing, userID)
		uids[dbUser.LinuxUid] = userID
	}
}

// TestUserCreatedEvent_WithLinuxFields verifies the projection correctly stores
// linux_uid and linux_username when they are present in the UserCreated event.
func TestUserCreatedEvent_WithLinuxFields(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	userID := testutil.NewID()
	err := st.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  "UserCreated",
		Data: map[string]any{
			"email":          "linux-event@test.com",
			"linux_username": "linuxuser",
			"linux_uid":      int32(5001),
		},
		ActorType: "system",
		ActorID:   "test",
	})
	require.NoError(t, err)

	dbUser, err := st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, "linuxuser", dbUser.LinuxUsername)
	assert.Equal(t, int32(5001), dbUser.LinuxUid)
}

// TestUserCreatedEvent_WithoutLinuxFields verifies that the projection handles
// a UserCreated event without linux fields (the old behavior before the fix).
// The fields should default to zero values.
func TestUserCreatedEvent_WithoutLinuxFields(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	userID := testutil.NewID()
	err := st.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  "UserCreated",
		Data: map[string]any{
			"email": "no-linux@test.com",
			"role":  "user",
		},
		ActorType: "system",
		ActorID:   "test",
	})
	require.NoError(t, err)

	dbUser, err := st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.Empty(t, dbUser.LinuxUsername)
	assert.Equal(t, int32(0), dbUser.LinuxUid)
}

// TestGetNextLinuxUID_ReturnsPositive verifies that GetNextLinuxUID returns a
// valid UID (> 0). This is a basic sanity check for the sequence used by SCIM.
func TestGetNextLinuxUID_ReturnsPositive(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	uid, err := st.Queries().GetNextLinuxUID(ctx)
	require.NoError(t, err)
	assert.Greater(t, uid, int32(0), "GetNextLinuxUID must return a positive UID")
}
