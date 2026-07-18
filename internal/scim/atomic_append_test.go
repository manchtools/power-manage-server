package scim_test

// Spec 28 regression tests: the SCIM multi-stream write paths now commit
// through store.AppendEvents (atomic) instead of sequential AppendEvent
// calls, so a mid-sequence failure can no longer leave partial state.
//
// Failure is injected with store.TestingSetInsertHook — the same seam
// the store-level AppendEvents tests use. It fires inside the shared
// appendOne, so it works on BOTH the old sequential path and the new
// batch path, giving these tests a real red (pre-migration) / green
// (post-migration) transition.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// AC 8 — the audit regression. Driving the real createGroup with the
// SCIMGroupMapped append forced to fail must leave NO orphan user_group
// projection row; the group and its mapping either both exist or neither
// does. Pre-migration (sequential appends) UserGroupCreated committed
// before the mapping failed, and the IdP's next sync then created a
// duplicate group and leaked the first.
func TestCreateGroup_MappingFailureLeavesNoOrphan(t *testing.T) {
	env := setupSCIM(t)
	ctx := context.Background()

	displayName := "Atomic Group " + testutil.NewID()[:8]
	body := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": displayName,
		"externalId":  "ext-" + testutil.NewID()[:8],
	}

	// Fail the mapping append (2nd event in the create batch).
	env.st.TestingSetInsertHook(func(streamType, eventType string) error {
		if streamType == "scim_group_mapping" {
			return errors.New("synthetic mapping-append failure")
		}
		return nil
	})

	w := env.request("POST", "/Groups", body)
	require.Equal(t, http.StatusInternalServerError, w.Code, "mapping failure must surface as 500: %s", w.Body.String())

	_, err := env.st.Repos().UserGroup.GetByName(ctx, displayName)
	assert.True(t, store.IsNotFound(err),
		"no orphan user_group may exist after a failed create — group and mapping are all-or-nothing")

	// A subsequent clean sync creates the group exactly once (the leak the
	// audit finding described no longer happens).
	env.st.TestingSetInsertHook(nil)

	w = env.request("POST", "/Groups", body)
	require.Equal(t, http.StatusCreated, w.Code, "clean sync must create the group: %s", w.Body.String())

	grp, err := env.st.Repos().UserGroup.GetByName(ctx, displayName)
	require.NoError(t, err, "clean sync must create the group")
	assert.Equal(t, displayName, grp.Name)

	// Re-POST is idempotent (existing behaviour) — still exactly one group,
	// no duplicate.
	w = env.request("POST", "/Groups", body)
	require.Equal(t, http.StatusOK, w.Code, "re-POST is idempotent, not a second create: %s", w.Body.String())
}

// replaceUser is now atomic across its per-field appends. Forcing the
// profile append to fail must roll back the email change made earlier in
// the same PUT — the request either applies every change or none.
func TestReplaceUser_PartialFailureRollsBackEmail(t *testing.T) {
	env := setupSCIM(t)
	ctx := context.Background()

	createResp := env.request("POST", "/Users", map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   strings.ToLower("atomic-"+testutil.NewID()[:8]) + "@example.com",
		"externalId": "ext-" + testutil.NewID()[:8],
		"active":     true,
	})
	require.Equal(t, http.StatusCreated, createResp.Code, "%s", createResp.Body.String())
	var created map[string]any
	require.NoError(t, json.Unmarshal(createResp.Body.Bytes(), &created))
	userID := created["id"].(string)

	before, err := env.st.Repos().User.Get(ctx, userID)
	require.NoError(t, err)

	// Fail the profile append (last in the batch); the email change is
	// inserted earlier in the same tx and must roll back with it.
	env.st.TestingSetInsertHook(func(streamType, eventType string) error {
		if eventType == string(eventtypes.UserProfileUpdated) {
			return errors.New("synthetic profile-append failure")
		}
		return nil
	})

	newEmail := strings.ToLower("changed-"+testutil.NewID()[:8]) + "@example.com"
	require.NotEqual(t, before.Email, newEmail)
	w := env.request("PUT", "/Users/"+userID, map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": newEmail,
		"name":     map[string]any{"givenName": "New", "familyName": "Name"},
		"active":   true,
	})
	require.Equal(t, http.StatusInternalServerError, w.Code, "a failed profile update must fail the request")

	after, err := env.st.Repos().User.Get(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, before.Email, after.Email,
		"email change must roll back when the profile update in the same PUT fails")
}

// Audit L7 — createUser is now atomic across its UserCreatedWithRoles +
// IdentityLinked appends. Forcing the identity-link append to fail must leave
// NO orphan user row: otherwise the IdP's next POST misses the externalID dedup
// (no link projection) and, with auto-link off, mints a DUPLICATE user under a
// fresh ULID. Pre-fix (sequential appends) the user row committed before the
// link append failed.
func TestCreateUser_IdentityLinkFailureLeavesNoOrphan(t *testing.T) {
	env := setupSCIM(t)
	ctx := context.Background()

	countDEKs := func() int {
		var n int
		require.NoError(t, env.st.TestingPool().QueryRow(ctx, "SELECT count(*) FROM user_encryption_keys").Scan(&n))
		return n
	}

	email := strings.ToLower("orphan-"+testutil.NewID()[:8]) + "@example.com"
	body := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   email,
		"externalId": "ext-" + testutil.NewID()[:8],
		"active":     true,
	}

	deksBefore := countDEKs()

	// Fail the identity-link append (2nd event in the create batch).
	env.st.TestingSetInsertHook(func(streamType, eventType string) error {
		if eventType == string(eventtypes.IdentityLinked) {
			return errors.New("synthetic identity-link append failure")
		}
		return nil
	})

	w := env.request("POST", "/Users", body)
	require.Equal(t, http.StatusInternalServerError, w.Code, "identity-link failure must surface as 500: %s", w.Body.String())

	_, err := env.st.Repos().User.GetByEmail(ctx, email)
	assert.True(t, store.IsNotFound(err),
		"no orphan user may exist after a failed create — user and identity link are all-or-nothing")

	// The DEK minted before the batch must not leak: it is shredded on rollback,
	// so a persistent create failure can't accumulate a wrapped key per retry.
	assert.Equal(t, deksBefore, countDEKs(),
		"orphaned user DEK must be shredded when the create batch rolls back")

	// A subsequent clean sync creates the user exactly once.
	env.st.TestingSetInsertHook(nil)

	w = env.request("POST", "/Users", body)
	require.Equal(t, http.StatusCreated, w.Code, "clean sync must create the user: %s", w.Body.String())

	created, err := env.st.Repos().User.GetByEmail(ctx, email)
	require.NoError(t, err, "clean sync must create the user")
	assert.Equal(t, email, created.Email)
}

// Audit L7 — a SCIM re-POST of an already-linked user syncs via syncUserFromSCIM,
// whose appends previously went through the SWALLOWING appendEvent helper: an
// append failure was logged and dropped, and the handler still returned 200 while
// the projection silently diverged from what the IdP believed it provisioned. The
// identity-link sync append must now fail the request closed so the IdP retries.
func TestCreateUser_RepostSyncFailureFailsClosed(t *testing.T) {
	env := setupSCIM(t)

	email := strings.ToLower("resync-"+testutil.NewID()[:8]) + "@example.com"
	body := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   email,
		"externalId": "ext-" + testutil.NewID()[:8],
		"active":     true,
	}

	// Clean create establishes the linked user.
	w := env.request("POST", "/Users", body)
	require.Equal(t, http.StatusCreated, w.Code, "%s", w.Body.String())

	// Re-POST hits the idempotent externalID branch → syncUserFromSCIM →
	// syncIdentityLink emits IdentityLinkLoginUpdated on every sync. Force it.
	env.st.TestingSetInsertHook(func(streamType, eventType string) error {
		if eventType == string(eventtypes.IdentityLinkLoginUpdated) {
			return errors.New("synthetic identity-link-sync append failure")
		}
		return nil
	})

	w = env.request("POST", "/Users", body)
	require.Equal(t, http.StatusInternalServerError, w.Code,
		"a swallowed sync append must now fail the request closed, not return 200: %s", w.Body.String())
}
