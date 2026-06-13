package scim_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/testutil"
)

// WS5 #1/#4 — SCIM cross-provider isolation. A SCIM provider may only add users
// it OWNS (has an identity link to) to its groups, and may only read/modify
// users it owns. Adding/reading another provider's user is a cross-provider
// IDOR. These tests build TWO providers and prove provider B cannot reach
// provider A's user through any member-add sink or user-resource verb.

// secondSCIMProvider provisions a second SCIM-enabled provider on the same
// store and returns its slug + bearer token + provider id.
func secondSCIMProvider(t *testing.T, env *scimTestEnv) (slug, token, providerID string) {
	t.Helper()
	slug = "scim-b-" + testutil.NewID()[:8]
	providerID = testutil.CreateTestIdentityProvider(t, env.st, env.enc, env.adminID, "SCIM Test B", slug)
	token = testutil.EnableSCIMForProvider(t, env.st, env.adminID, providerID)
	return slug, token, providerID
}

// scimReq issues a SCIM request as an arbitrary (slug, token) pair so a test
// can act as a specific provider.
func scimReq(t *testing.T, env *scimTestEnv, slug, token, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reqBody *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(b)
	} else {
		reqBody = &bytes.Buffer{}
	}
	req := httptest.NewRequest(method, "/scim/v2/"+slug+path, reqBody)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/scim+json")
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	return w
}

// createSCIMGroup POSTs a group as the given provider and returns its id.
func createSCIMGroup(t *testing.T, env *scimTestEnv, slug, token, displayName string, members []map[string]any) string {
	t.Helper()
	body := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": displayName,
	}
	if members != nil {
		body["members"] = members
	}
	w := scimReq(t, env, slug, token, http.MethodPost, "/Groups", body)
	require.Equal(t, http.StatusCreated, w.Code, "group create: %s", w.Body.String())
	var resp struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.ID)
	return resp.ID
}

func groupMemberIDs(t *testing.T, env *scimTestEnv, groupID string) []string {
	t.Helper()
	ids, err := env.st.Repos().UserGroup.ListMemberIDs(context.Background(), groupID)
	require.NoError(t, err)
	return ids
}

// TestGroupMemberAdd_RejectsCrossProviderUser pins #1: every member-ADD sink
// must refuse a user owned by a DIFFERENT provider, while accepting an owned
// user. Drives all four sinks (patch-add, patch-replace, PUT/reconcile,
// create-with-members).
func TestGroupMemberAdd_RejectsCrossProviderUser(t *testing.T) {
	env := setupSCIM(t) // providerA = env.providerID / env.slug / env.token
	slugB, tokenB, providerB := secondSCIMProvider(t, env)

	// userA is owned by providerA; userB is owned by providerB.
	userA := testutil.CreateTestUser(t, env.st, testutil.NewID()+"@a.com", "pass", "user")
	testutil.CreateTestIdentityLink(t, env.st, userA, env.providerID, "ext-a", "a@a.com")
	userB := testutil.CreateTestUser(t, env.st, testutil.NewID()+"@b.com", "pass", "user")
	testutil.CreateTestIdentityLink(t, env.st, userB, providerB, "ext-b", "b@b.com")

	t.Run("correct_owned_user_added", func(t *testing.T) {
		gid := createSCIMGroup(t, env, slugB, tokenB, "g-correct-"+testutil.NewID()[:6], nil)
		w := scimReq(t, env, slugB, tokenB, http.MethodPatch, "/Groups/"+gid, patchAdd(userB))
		require.Equal(t, http.StatusOK, w.Code, "%s", w.Body.String())
		assert.Contains(t, groupMemberIDs(t, env, gid), userB, "providerB must be able to add its OWN user")
	})

	t.Run("patch_add_cross_provider_rejected", func(t *testing.T) {
		gid := createSCIMGroup(t, env, slugB, tokenB, "g-padd-"+testutil.NewID()[:6], nil)
		scimReq(t, env, slugB, tokenB, http.MethodPatch, "/Groups/"+gid, patchAdd(userA))
		assert.NotContains(t, groupMemberIDs(t, env, gid), userA,
			"providerB must NOT add providerA's user via PATCH add (IDOR)")
	})

	t.Run("patch_replace_cross_provider_rejected", func(t *testing.T) {
		gid := createSCIMGroup(t, env, slugB, tokenB, "g-prep-"+testutil.NewID()[:6], nil)
		scimReq(t, env, slugB, tokenB, http.MethodPatch, "/Groups/"+gid, patchReplaceMembers(userA))
		assert.NotContains(t, groupMemberIDs(t, env, gid), userA,
			"providerB must NOT add providerA's user via PATCH replace members (IDOR)")
	})

	t.Run("put_reconcile_cross_provider_rejected", func(t *testing.T) {
		gid := createSCIMGroup(t, env, slugB, tokenB, "g-put-"+testutil.NewID()[:6], nil)
		put := map[string]any{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
			"displayName": "g-put-" + testutil.NewID()[:6],
			"members":     []map[string]any{{"value": userA}},
		}
		scimReq(t, env, slugB, tokenB, http.MethodPut, "/Groups/"+gid, put)
		assert.NotContains(t, groupMemberIDs(t, env, gid), userA,
			"providerB must NOT add providerA's user via PUT reconcile (IDOR)")
	})

	t.Run("create_with_members_cross_provider_rejected", func(t *testing.T) {
		gid := createSCIMGroup(t, env, slugB, tokenB, "g-create-"+testutil.NewID()[:6],
			[]map[string]any{{"value": userA}})
		assert.NotContains(t, groupMemberIDs(t, env, gid), userA,
			"providerB must NOT add providerA's user via create-with-members (IDOR)")
	})
}

// TestUserResource_CrossProviderIDOR pins #4: provider B cannot GET/PUT/PATCH/
// DELETE provider A's user (404 for all), while provider A can read its own.
func TestUserResource_CrossProviderIDOR(t *testing.T) {
	env := setupSCIM(t)
	slugB, tokenB, _ := secondSCIMProvider(t, env)

	userA := testutil.CreateTestUser(t, env.st, testutil.NewID()+"@a.com", "pass", "user")
	testutil.CreateTestIdentityLink(t, env.st, userA, env.providerID, "ext-a-idor", "a@a.com")

	for _, verb := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run("providerB_"+verb+"_404", func(t *testing.T) {
			var body any
			switch verb {
			case http.MethodPut:
				body = map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": "x@a.com"}
			case http.MethodPatch:
				body = map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}}}
			}
			w := scimReq(t, env, slugB, tokenB, verb, "/Users/"+userA, body)
			assert.Equalf(t, http.StatusNotFound, w.Code,
				"providerB %s on providerA's user must 404 (IDOR), got %d: %s", verb, w.Code, w.Body.String())
		})
	}

	// Inverse positive: providerA reads its own user → 200 (proves the 404s
	// above are scoping, not a blanket failure).
	w := scimReq(t, env, env.slug, env.token, http.MethodGet, "/Users/"+userA, nil)
	assert.Equal(t, http.StatusOK, w.Code, "providerA must read its OWN user")
}

// patchAdd / patchReplaceMembers build SCIM PatchOp bodies.
func patchAdd(userID string) map[string]any {
	return map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "add", "path": "members", "value": []map[string]any{{"value": userID}}}},
	}
}

func patchReplaceMembers(userID string) map[string]any {
	return map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "replace", "path": "members", "value": []map[string]any{{"value": userID}}}},
	}
}
