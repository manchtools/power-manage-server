package scim_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/scim"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// scimTestEnv holds shared state for SCIM integration tests.
type scimTestEnv struct {
	handler    http.Handler
	st         *store.Store
	enc        *crypto.Encryptor
	adminID    string
	providerID string
	slug       string
	token      string
}

func setupSCIM(t *testing.T) *scimTestEnv {
	t.Helper()
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	handler := scim.NewHandler(st, logger)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	slug := "scim-test-" + testutil.NewID()[:8]
	providerID := testutil.CreateTestIdentityProvider(t, st, enc, adminID, "SCIM Test", slug)
	token := testutil.EnableSCIMForProvider(t, st, adminID, providerID)

	return &scimTestEnv{
		handler:    handler,
		st:         st,
		enc:        enc,
		adminID:    adminID,
		providerID: providerID,
		slug:       slug,
		token:      token,
	}
}

func (e *scimTestEnv) request(method, path string, body ...any) *httptest.ResponseRecorder {
	var reqBody *bytes.Buffer
	if len(body) > 0 && body[0] != nil {
		b, _ := json.Marshal(body[0])
		reqBody = bytes.NewBuffer(b)
	} else {
		reqBody = &bytes.Buffer{}
	}

	req := httptest.NewRequest(method, "/scim/v2/"+e.slug+path, reqBody)
	req.Header.Set("Authorization", "Bearer "+e.token)
	req.Header.Set("Content-Type", "application/scim+json")

	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, req)
	return w
}

func (e *scimTestEnv) requestNoAuth(method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/scim/v2/"+e.slug+path, nil)
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, req)
	return w
}

// --- Auth Tests ---

func TestAuth_MissingToken(t *testing.T) {
	env := setupSCIM(t)
	w := env.requestNoAuth("GET", "/Users")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuth_InvalidToken(t *testing.T) {
	env := setupSCIM(t)
	req := httptest.NewRequest("GET", "/scim/v2/"+env.slug+"/Users", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuth_NonExistentProvider(t *testing.T) {
	env := setupSCIM(t)
	req := httptest.NewRequest("GET", "/scim/v2/nonexistent/Users", nil)
	req.Header.Set("Authorization", "Bearer "+env.token)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuth_ValidToken(t *testing.T) {
	env := setupSCIM(t)
	w := env.request("GET", "/Users")
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Discovery Tests ---

func TestServiceProviderConfig(t *testing.T) {
	env := setupSCIM(t)
	w := env.request("GET", "/ServiceProviderConfig")
	assert.Equal(t, http.StatusOK, w.Code)

	var config map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &config))
	assert.Contains(t, config["schemas"], "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig")

	patch := config["patch"].(map[string]any)
	assert.Equal(t, true, patch["supported"])
}

func TestSchemas(t *testing.T) {
	env := setupSCIM(t)
	w := env.request("GET", "/Schemas")
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(2), resp["totalResults"])
}

func TestResourceTypes(t *testing.T) {
	env := setupSCIM(t)
	w := env.request("GET", "/ResourceTypes")
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(2), resp["totalResults"])
}

// --- User Tests ---

func TestCreateUser_Success(t *testing.T) {
	env := setupSCIM(t)

	user := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   "newuser@example.com",
		"externalId": "ext-123",
		"active":     true,
	}

	w := env.request("POST", "/Users", user)
	assert.Equal(t, http.StatusCreated, w.Code)

	var created map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	assert.NotEmpty(t, created["id"])
	assert.Equal(t, "newuser@example.com", created["userName"])
	assert.Equal(t, "ext-123", created["externalId"])
	assert.Equal(t, true, created["active"])
}

func TestGetUser_Success(t *testing.T) {
	env := setupSCIM(t)

	// Create user first
	user := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   "getuser@example.com",
		"externalId": "ext-get",
	}
	createResp := env.request("POST", "/Users", user)
	require.Equal(t, http.StatusCreated, createResp.Code)

	var created map[string]any
	json.Unmarshal(createResp.Body.Bytes(), &created)
	userID := created["id"].(string)

	// Get the user
	w := env.request("GET", "/Users/"+userID)
	assert.Equal(t, http.StatusOK, w.Code)

	var fetched map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &fetched))
	assert.Equal(t, userID, fetched["id"])
	assert.Equal(t, "getuser@example.com", fetched["userName"])
}

func TestGetUser_NotFound(t *testing.T) {
	env := setupSCIM(t)
	w := env.request("GET", "/Users/"+testutil.NewID())
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListUsers_Empty(t *testing.T) {
	env := setupSCIM(t)
	w := env.request("GET", "/Users")
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(0), resp["totalResults"])
}

func TestListUsers_WithFilter(t *testing.T) {
	env := setupSCIM(t)

	// Create a user
	user := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   "filtered@example.com",
		"externalId": "ext-filter",
	}
	createResp := env.request("POST", "/Users", user)
	require.Equal(t, http.StatusCreated, createResp.Code)

	// Filter by userName
	req := httptest.NewRequest("GET", "/scim/v2/"+env.slug+"/Users?filter=userName+eq+%22filtered%40example.com%22", nil)
	req.Header.Set("Authorization", "Bearer "+env.token)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(1), resp["totalResults"])
}

func TestReplaceUser_UpdateEmail(t *testing.T) {
	env := setupSCIM(t)

	// Create user
	user := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   "replace@example.com",
		"externalId": "ext-replace",
	}
	createResp := env.request("POST", "/Users", user)
	require.Equal(t, http.StatusCreated, createResp.Code)

	var created map[string]any
	json.Unmarshal(createResp.Body.Bytes(), &created)
	userID := created["id"].(string)

	// Replace (PUT) with new email
	updated := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   "replaced@example.com",
		"externalId": "ext-replace",
		"active":     true,
	}
	w := env.request("PUT", "/Users/"+userID, updated)
	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, "replaced@example.com", result["userName"])
}

func TestPatchUser_Deactivate(t *testing.T) {
	env := setupSCIM(t)

	// Create user
	user := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   "patch@example.com",
		"externalId": "ext-patch",
		"active":     true,
	}
	createResp := env.request("POST", "/Users", user)
	require.Equal(t, http.StatusCreated, createResp.Code)

	var created map[string]any
	json.Unmarshal(createResp.Body.Bytes(), &created)
	userID := created["id"].(string)

	// PATCH active=false
	patch := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{
				"op":    "replace",
				"path":  "active",
				"value": false,
			},
		},
	}
	w := env.request("PATCH", "/Users/"+userID, patch)
	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, false, result["active"])
}

func TestDeleteUser_Success(t *testing.T) {
	env := setupSCIM(t)

	// Create user
	user := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   "delete@example.com",
		"externalId": "ext-delete",
	}
	createResp := env.request("POST", "/Users", user)
	require.Equal(t, http.StatusCreated, createResp.Code)

	var created map[string]any
	json.Unmarshal(createResp.Body.Bytes(), &created)
	userID := created["id"].(string)

	// DELETE
	w := env.request("DELETE", "/Users/"+userID)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

// --- Group Tests ---

func TestCreateGroup_Success(t *testing.T) {
	env := setupSCIM(t)

	group := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Engineering",
		"externalId":  "grp-eng",
	}

	w := env.request("POST", "/Groups", group)
	assert.Equal(t, http.StatusCreated, w.Code)

	var created map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	assert.NotEmpty(t, created["id"])
	assert.Equal(t, "Engineering", created["displayName"])
	assert.Equal(t, "grp-eng", created["externalId"])
}

func TestGetGroup_Success(t *testing.T) {
	env := setupSCIM(t)

	// Create group
	group := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Design",
		"externalId":  "grp-design",
	}
	createResp := env.request("POST", "/Groups", group)
	require.Equal(t, http.StatusCreated, createResp.Code)

	var created map[string]any
	json.Unmarshal(createResp.Body.Bytes(), &created)
	groupID := created["id"].(string)

	// Get the group
	w := env.request("GET", "/Groups/"+groupID)
	assert.Equal(t, http.StatusOK, w.Code)

	var fetched map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &fetched))
	assert.Equal(t, groupID, fetched["id"])
	assert.Equal(t, "Design", fetched["displayName"])
}

func TestListGroups_Empty(t *testing.T) {
	env := setupSCIM(t)
	w := env.request("GET", "/Groups")
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(0), resp["totalResults"])
}

func TestPatchGroup_AddMember(t *testing.T) {
	env := setupSCIM(t)

	// Create a user to be a member
	userID := testutil.CreateTestUser(t, env.st, testutil.NewID()+"@example.com", "pass", "user")

	// Create group
	group := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Team",
		"externalId":  "grp-team",
	}
	createResp := env.request("POST", "/Groups", group)
	require.Equal(t, http.StatusCreated, createResp.Code)

	var created map[string]any
	json.Unmarshal(createResp.Body.Bytes(), &created)
	groupID := created["id"].(string)

	// PATCH: add member
	patch := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{
				"op":   "add",
				"path": "members",
				"value": []map[string]any{
					{"value": userID},
				},
			},
		},
	}
	w := env.request("PATCH", "/Groups/"+groupID, patch)
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify member is present
	getResp := env.request("GET", "/Groups/"+groupID)
	var fetched map[string]any
	json.Unmarshal(getResp.Body.Bytes(), &fetched)

	members, ok := fetched["members"].([]any)
	require.True(t, ok)
	assert.Len(t, members, 1)
}

func TestDeleteGroup_Success(t *testing.T) {
	env := setupSCIM(t)

	// Create group
	group := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Temp",
		"externalId":  "grp-temp",
	}
	createResp := env.request("POST", "/Groups", group)
	require.Equal(t, http.StatusCreated, createResp.Code)

	var created map[string]any
	json.Unmarshal(createResp.Body.Bytes(), &created)
	groupID := created["id"].(string)

	// DELETE (unmaps the SCIM mapping, keeps the user group)
	w := env.request("DELETE", "/Groups/"+groupID)
	assert.Equal(t, http.StatusNoContent, w.Code)

	// Group should no longer be found via SCIM
	getResp := env.request("GET", "/Groups/"+groupID)
	assert.Equal(t, http.StatusNotFound, getResp.Code)
}

func TestReplaceGroup_UpdateMembers(t *testing.T) {
	env := setupSCIM(t)

	// Create users
	user1ID := testutil.CreateTestUser(t, env.st, testutil.NewID()+"@example.com", "pass", "user")
	user2ID := testutil.CreateTestUser(t, env.st, testutil.NewID()+"@example.com", "pass", "user")

	// Create group with user1
	group := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Replace Group",
		"externalId":  "grp-replace",
		"members": []map[string]any{
			{"value": user1ID},
		},
	}
	createResp := env.request("POST", "/Groups", group)
	require.Equal(t, http.StatusCreated, createResp.Code)

	var created map[string]any
	json.Unmarshal(createResp.Body.Bytes(), &created)
	groupID := created["id"].(string)

	// PUT: replace members with user2 only
	updated := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Replace Group Updated",
		"externalId":  "grp-replace",
		"members": []map[string]any{
			{"value": user2ID},
		},
	}
	w := env.request("PUT", "/Groups/"+groupID, updated)
	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, "Replace Group Updated", result["displayName"])

	members, ok := result["members"].([]any)
	require.True(t, ok)
	assert.Len(t, members, 1)
	firstMember := members[0].(map[string]any)
	assert.Equal(t, user2ID, firstMember["value"])
}
