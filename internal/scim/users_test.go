package scim_test

// The user cluster: provisioning, idempotent re-assertion, PATCH
// semantics, deactivation, erasure, cross-directory isolation, and the
// audit evidence each of them writes.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/scim"
	"github.com/manchtools/power-manage/server/internal/store"
)

func scimUser(userName, externalID string) map[string]any {
	return map[string]any{
		"schemas":    []string{scim.UserSchema},
		"userName":   userName,
		"externalId": externalID,
		"active":     true,
	}
}

// createUser POSTs a subject and returns the id the directory got back.
func (f *fixture) createUser(p *provider, body map[string]any) string {
	f.t.Helper()
	resp := f.do(http.MethodPost, p.Slug, p.Token, "/Users", body)
	require.Equal(f.t, http.StatusCreated, resp.Code, "body: %s", resp)
	id, _ := resp.JSON()["id"].(string)
	require.NotEmpty(f.t, id)
	return id
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestUsers_CreateProvisionsSubject(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	resp := f.do(http.MethodPost, p.Slug, p.Token, "/Users", scimUser("new@example.com", "ext-1"))
	require.Equal(t, http.StatusCreated, resp.Code, "body: %s", resp)

	got := resp.JSON()
	assert.NotEmpty(t, got["id"])
	assert.Equal(t, "new@example.com", got["userName"])
	assert.Equal(t, "ext-1", got["externalId"])
	assert.Equal(t, true, got["active"])

	// The subject is provisionable on managed devices: an empty Linux
	// account name or a zero uid would be written to every device and
	// silently do nothing.
	row, err := f.store.GetUser(f.ctx(), got["id"].(string))
	require.NoError(t, err)
	assert.NotEmpty(t, row.LinuxUsername)
	assert.Greater(t, row.LinuxUid, int32(0))
}

func TestUsers_CreateAssignsDistinctLinuxUIDs(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	seen := map[int32]string{}
	for i := 0; i < 4; i++ {
		id := f.createUser(p, scimUser(newULID()[20:]+"@example.com", "ext-"+newULID()))
		row, err := f.store.GetUser(f.ctx(), id)
		require.NoError(t, err)
		prev, dup := seen[row.LinuxUid]
		assert.Falsef(t, dup, "linux uid %d shared by %s and %s", row.LinuxUid, prev, id)
		seen[row.LinuxUid] = id
	}
}

func TestUsers_CreateRequiresAnAddress(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	resp := f.do(http.MethodPost, p.Slug, p.Token, "/Users", map[string]any{
		"schemas": []string{scim.UserSchema},
	})
	assert.Equal(t, http.StatusBadRequest, resp.Code, "body: %s", resp)
}

func TestUsers_CreateFallsBackToPrimaryEmail(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	resp := f.do(http.MethodPost, p.Slug, p.Token, "/Users", map[string]any{
		"schemas":    []string{scim.UserSchema},
		"externalId": "ext-emails",
		"emails":     []map[string]any{{"value": "fallback@example.com", "primary": true}},
	})
	require.Equal(t, http.StatusCreated, resp.Code, "body: %s", resp)
	assert.Equal(t, "fallback@example.com", resp.JSON()["userName"])
}

// A directory that grants a default role at creation must produce a
// grant the authorizer can see, not a role name in a column.
func TestUsers_CreateAppliesTheProviderDefaultRole(t *testing.T) {
	f := newFixture(t)
	roleID := f.insertRole([]string{"ListDevices"})
	p := f.seedProvider(func(s *providerSeed) { s.DefaultRoleID = roleID })

	id := f.createUser(p, scimUser("default-role@example.com", "ext-role"))

	perms, err := f.store.ListUserPermissions(f.ctx(), id)
	require.NoError(t, err)
	assert.Contains(t, perms, "ListDevices")
}

// The create commits the subject, its key, its grant and its binding in
// ONE transaction with its evidence.
func TestUsers_CreateIsAuditedInOneOperation(t *testing.T) {
	f := newFixture(t)
	roleID := f.insertRole([]string{"ListDevices"})
	p := f.seedProvider(func(s *providerSeed) { s.DefaultRoleID = roleID })

	id := f.createUser(p, scimUser("audited@example.com", "ext-audit"))

	op := f.onlyOperationFor(scim.DescUsersCreate)
	assert.Equal(t, string(store.ClassBackgroundWriter), op.Class,
		"SCIM is a non-RPC writer, which is the class the audit log reserves for it")
	assert.Equal(t, p.ID, op.ActorID)

	effects := f.effectsOf(op.OperationID)
	created := f.effectWithAction(effects, "CREATE")
	assert.Equal(t, "user", created.ResourceType)
	assert.Equal(t, id, created.ResourceID)
	assert.Equal(t, sha256Hex("audited@example.com"), created.EvidenceFingerprint)
	assert.Equal(t, "email_sha256", created.EvidenceKind)

	// The address is personal data, so the readable form is sealed
	// under the subject's own key and dies with it.
	require.NotEmpty(t, created.SealedDetail)
	require.NotNil(t, created.SealedDetailSubject)
	assert.Equal(t, id, *created.SealedDetailSubject)
	opened, err := f.openSealedDetail(id, created.SealedDetail, "email")
	require.NoError(t, err)
	assert.Equal(t, "audited@example.com", opened)

	grant := f.effectWithAction(effects, "GRANT")
	assert.Equal(t, "user_role", grant.ResourceType)
	require.NotNil(t, grant.AfterRef)
	assert.Equal(t, roleID, *grant.AfterRef)

	link := f.effectWithAction(effects, "LINK")
	assert.Equal(t, "identity_link", link.ResourceType)
	require.NotNil(t, link.AfterRef)
	assert.Equal(t, id, *link.AfterRef)
}

// Re-POSTing the same externalId is a sync, not a conflict: directories
// re-assert their whole population on every cycle.
func TestUsers_RepostByExternalIDSyncsInsteadOfDuplicating(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	body := scimUser("original@example.com", "ext-sync")
	id := f.createUser(p, body)

	body["userName"] = "updated@example.com"
	body["active"] = false
	resp := f.do(http.MethodPost, p.Slug, p.Token, "/Users", body)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)

	got := resp.JSON()
	assert.Equal(t, id, got["id"], "the re-assertion must resolve to the same subject")
	assert.Equal(t, "updated@example.com", got["userName"])
	assert.Equal(t, false, got["active"])

	total, err := f.store.CountSCIMUsers(f.ctx(), p.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total, "a re-assertion must not mint a second subject")
}

// ---------------------------------------------------------------------------
// Auto-link by address
// ---------------------------------------------------------------------------

// A directory can assert any address. Binding one to an account that is
// ALREADY bound to some other directory would hand that account over,
// so it is refused unless the operator delegated identity explicitly.
func TestUsers_AutoLinkRefusesAnAlreadyBoundAccount(t *testing.T) {
	f := newFixture(t)
	other := f.seedProvider(nil)
	p := f.seedProvider(func(s *providerSeed) { s.AutoLinkByEmail = true })

	victim := f.createUser(other, scimUser("victim@example.com", "ext-victim"))

	resp := f.do(http.MethodPost, p.Slug, p.Token, "/Users", scimUser("victim@example.com", "ext-takeover"))
	assert.Equal(t, http.StatusConflict, resp.Code, "body: %s", resp)

	_, err := f.store.GetIdentityLinkByProviderAndUser(f.ctx(), p.ID, victim)
	assert.True(t, store.IsNotFound(err), "the account must not gain a binding to the asserting directory")
}

func TestUsers_AutoLinkAllowedWhenTheOperatorTrustsAssertions(t *testing.T) {
	f := newFixture(t)
	other := f.seedProvider(nil)
	p := f.seedProvider(func(s *providerSeed) {
		s.AutoLinkByEmail = true
		s.TrustEmailAssertions = true
	})

	existing := f.createUser(other, scimUser("trusted@example.com", "ext-existing"))

	resp := f.do(http.MethodPost, p.Slug, p.Token, "/Users", scimUser("trusted@example.com", "ext-trusted"))
	require.Equal(t, http.StatusCreated, resp.Code, "body: %s", resp)
	assert.Equal(t, existing, resp.JSON()["id"])

	_, err := f.store.GetIdentityLinkByProviderAndUser(f.ctx(), p.ID, existing)
	assert.NoError(t, err)
}

// An account with no binding at all is the ordinary invite flow.
func TestUsers_AutoLinkBindsAnUnboundAccount(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(func(s *providerSeed) { s.AutoLinkByEmail = true })

	unbound := newULID()
	f.insertUser(unbound, "unbound@example.com")

	resp := f.do(http.MethodPost, p.Slug, p.Token, "/Users", scimUser("unbound@example.com", "ext-unbound"))
	require.Equal(t, http.StatusCreated, resp.Code, "body: %s", resp)
	assert.Equal(t, unbound, resp.JSON()["id"])

	link, err := f.store.GetIdentityLinkByProviderAndUser(f.ctx(), p.ID, unbound)
	require.NoError(t, err)
	assert.Equal(t, "ext-unbound", link.ExternalID)
}

// With auto-link off, a matching address is not a match at all: a fresh
// subject is provisioned.
func TestUsers_AutoLinkOffCreatesASeparateSubject(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	unbound := newULID()
	f.insertUser(unbound, "separate@example.com")

	resp := f.do(http.MethodPost, p.Slug, p.Token, "/Users", scimUser("other@example.com", "ext-separate"))
	require.Equal(t, http.StatusCreated, resp.Code, "body: %s", resp)
	assert.NotEqual(t, unbound, resp.JSON()["id"])
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestUsers_GetReturnsTheSubject(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createUser(p, scimUser("get@example.com", "ext-get"))

	resp := f.do(http.MethodGet, p.Slug, p.Token, "/Users/"+id, nil)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	got := resp.JSON()
	assert.Equal(t, id, got["id"])
	assert.Equal(t, "get@example.com", got["userName"])
	assert.Equal(t, "ext-get", got["externalId"])
}

func TestUsers_GetUnknownSubjectIsNotFound(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	assert.Equal(t, http.StatusNotFound,
		f.do(http.MethodGet, p.Slug, p.Token, "/Users/"+newULID(), nil).Code)
}

func TestUsers_ListIsEmptyForAFreshDirectory(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	resp := f.do(http.MethodGet, p.Slug, p.Token, "/Users", nil)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	assert.Equal(t, float64(0), resp.JSON()["totalResults"])
}

func TestUsers_ListPagesAndCounts(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	for i := 0; i < 3; i++ {
		f.createUser(p, scimUser(newULID()[20:]+"@example.com", "ext-"+newULID()))
	}

	resp := f.do(http.MethodGet, p.Slug, p.Token, "/Users?startIndex=1&count=2", nil)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	got := resp.JSON()
	assert.Equal(t, float64(3), got["totalResults"])
	assert.Equal(t, float64(2), got["itemsPerPage"])
	assert.Len(t, got["Resources"], 2)

	second := f.do(http.MethodGet, p.Slug, p.Token, "/Users?startIndex=3&count=2", nil)
	require.Equal(t, http.StatusOK, second.Code, "body: %s", second)
	assert.Len(t, second.JSON()["Resources"], 1)
}

func TestUsers_ListFilters(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	f.createUser(p, scimUser("filtered@example.com", "ext-filter"))
	f.createUser(p, scimUser("other@example.com", "ext-other"))

	byName := f.do(http.MethodGet, p.Slug, p.Token, `/Users?filter=userName+eq+%22filtered%40example.com%22`, nil)
	require.Equal(t, http.StatusOK, byName.Code, "body: %s", byName)
	assert.Equal(t, float64(1), byName.JSON()["totalResults"])

	byExternal := f.do(http.MethodGet, p.Slug, p.Token, `/Users?filter=externalId+eq+%22ext-other%22`, nil)
	require.Equal(t, http.StatusOK, byExternal.Code, "body: %s", byExternal)
	assert.Equal(t, float64(1), byExternal.JSON()["totalResults"])

	missing := f.do(http.MethodGet, p.Slug, p.Token, `/Users?filter=userName+eq+%22nobody%40example.com%22`, nil)
	require.Equal(t, http.StatusOK, missing.Code, "body: %s", missing)
	assert.Equal(t, float64(0), missing.JSON()["totalResults"])

	bad := f.do(http.MethodGet, p.Slug, p.Token, `/Users?filter=userName+co+%22x%22`, nil)
	assert.Equal(t, http.StatusBadRequest, bad.Code, "body: %s", bad)
}

// Reading the directory's population is a bulk read of personal data,
// so it is recorded under the sensitive-read class with the volume it
// returned.
func TestUsers_ListIsAuditedAsASensitiveRead(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	f.createUser(p, scimUser("listed@example.com", "ext-listed"))

	require.Equal(t, http.StatusOK, f.do(http.MethodGet, p.Slug, p.Token, "/Users", nil).Code)

	op := f.onlyOperationFor(scim.DescUsersList)
	assert.Equal(t, string(store.ClassSensitiveRead), op.Class)
	effect := f.effectWithAction(f.effectsOf(op.OperationID), "LIST_USERS")
	assert.Equal(t, "identity_provider", effect.ResourceType)
	assert.Equal(t, p.ID, effect.ResourceID)
	require.NotNil(t, effect.AfterCount)
	assert.Equal(t, int64(1), *effect.AfterCount)
}

func TestUsers_GetIsAuditedAsASensitiveRead(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createUser(p, scimUser("read@example.com", "ext-read"))

	require.Equal(t, http.StatusOK, f.do(http.MethodGet, p.Slug, p.Token, "/Users/"+id, nil).Code)

	op := f.onlyOperationFor(scim.DescUsersGet)
	assert.Equal(t, string(store.ClassSensitiveRead), op.Class)
	effect := f.effectWithAction(f.effectsOf(op.OperationID), "READ")
	assert.Equal(t, "user", effect.ResourceType)
	assert.Equal(t, id, effect.ResourceID)
}

// ---------------------------------------------------------------------------
// Replace
// ---------------------------------------------------------------------------

func TestUsers_ReplaceUpdatesTheAddress(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createUser(p, scimUser("before@example.com", "ext-replace"))

	resp := f.do(http.MethodPut, p.Slug, p.Token, "/Users/"+id, scimUser("after@example.com", "ext-replace"))
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	assert.Equal(t, "after@example.com", resp.JSON()["userName"])

	row, err := f.store.GetUser(f.ctx(), id)
	require.NoError(t, err)
	assert.Equal(t, "after@example.com", row.Email)
}

// The directory is the source of truth for the profile, so an
// explicitly empty name object CLEARS it while an omitted one leaves it
// alone. Collapsing those two would make a deliberate clear impossible.
func TestUsers_ReplaceDistinguishesOmittedFromEmptyName(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	body := scimUser("names@example.com", "ext-names")
	body["name"] = map[string]any{"givenName": "Lou", "familyName": "Update"}
	id := f.createUser(p, body)

	seeded, err := f.store.GetUser(f.ctx(), id)
	require.NoError(t, err)
	require.Equal(t, "Lou", seeded.GivenName, "seed sanity")

	omitted := scimUser("names@example.com", "ext-names")
	require.Equal(t, http.StatusOK, f.do(http.MethodPut, p.Slug, p.Token, "/Users/"+id, omitted).Code)
	kept, err := f.store.GetUser(f.ctx(), id)
	require.NoError(t, err)
	assert.Equal(t, "Lou", kept.GivenName, "an omitted name object must not touch the profile")

	cleared := scimUser("names@example.com", "ext-names")
	cleared["name"] = map[string]any{}
	require.Equal(t, http.StatusOK, f.do(http.MethodPut, p.Slug, p.Token, "/Users/"+id, cleared).Code)
	after, err := f.store.GetUser(f.ctx(), id)
	require.NoError(t, err)
	assert.Empty(t, after.GivenName)
	assert.Empty(t, after.FamilyName)
	assert.Empty(t, after.DisplayName)
}

// Every field the PUT changed lands in one transaction with one
// operation row, so a partly-applied assertion is not representable.
func TestUsers_ReplaceIsAuditedInOneOperation(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createUser(p, scimUser("multi@example.com", "ext-multi"))

	body := scimUser("multi-new@example.com", "ext-multi")
	body["active"] = false
	body["name"] = map[string]any{"givenName": "Multi", "familyName": "Field"}
	require.Equal(t, http.StatusOK, f.do(http.MethodPut, p.Slug, p.Token, "/Users/"+id, body).Code)

	op := f.onlyOperationFor(scim.DescUsersReplace)
	assert.Equal(t, string(store.ClassBackgroundWriter), op.Class)
	effects := f.effectsOf(op.OperationID)

	email := f.effectWithAction(effects, "UPDATE_EMAIL")
	assert.Equal(t, sha256Hex("multi-new@example.com"), email.EvidenceFingerprint)
	opened, err := f.openSealedDetail(id, email.SealedDetail, "email")
	require.NoError(t, err)
	assert.Equal(t, "multi@example.com -> multi-new@example.com", opened)

	disabled := f.effectWithAction(effects, "SET_DISABLED")
	require.NotNil(t, disabled.AfterFlag)
	assert.True(t, *disabled.AfterFlag)

	f.effectWithAction(effects, "UPDATE_PROFILE")
	f.effectWithAction(effects, "SYNC_LINK")
}

// ---------------------------------------------------------------------------
// Patch
// ---------------------------------------------------------------------------

func patchOps(ops ...map[string]any) map[string]any {
	return map[string]any{
		"schemas":    []string{scim.PatchOpSchema},
		"Operations": ops,
	}
}

func TestUsers_PatchDeactivates(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createUser(p, scimUser("deactivate@example.com", "ext-deactivate"))

	resp := f.do(http.MethodPatch, p.Slug, p.Token, "/Users/"+id,
		patchOps(map[string]any{"op": "replace", "path": "active", "value": false}))
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	assert.Equal(t, false, resp.JSON()["active"])

	row, err := f.store.GetUser(f.ctx(), id)
	require.NoError(t, err)
	assert.True(t, row.Disabled)
}

// Deactivation retires the subject's authority, so every session minted
// under it stops validating.
func TestUsers_PatchDeactivationInvalidatesSessions(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createUser(p, scimUser("session@example.com", "ext-session"))

	before, err := f.store.GetUserSessionState(f.ctx(), id)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, f.do(http.MethodPatch, p.Slug, p.Token, "/Users/"+id,
		patchOps(map[string]any{"op": "replace", "path": "active", "value": false})).Code)

	after, err := f.store.GetUserSessionState(f.ctx(), id)
	require.NoError(t, err)
	assert.Greater(t, after.SessionVersion, before.SessionVersion)
}

// Deactivation is not erasure: the key that makes the subject's sealed
// evidence readable must survive.
func TestUsers_PatchDeactivationKeepsTheSubjectKey(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createUser(p, scimUser("keepkey@example.com", "ext-keepkey"))

	require.Equal(t, http.StatusOK, f.do(http.MethodPatch, p.Slug, p.Token, "/Users/"+id,
		patchOps(map[string]any{"op": "replace", "path": "active", "value": false})).Code)

	_, err := f.store.GetUserEncryptionKey(f.ctx(), id)
	assert.NoError(t, err, "a deactivated subject is not erased")
}

func TestUsers_PatchReactivates(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createUser(p, scimUser("reactivate@example.com", "ext-reactivate"))

	require.Equal(t, http.StatusOK, f.do(http.MethodPatch, p.Slug, p.Token, "/Users/"+id,
		patchOps(map[string]any{"op": "replace", "path": "active", "value": false})).Code)
	resp := f.do(http.MethodPatch, p.Slug, p.Token, "/Users/"+id,
		patchOps(map[string]any{"op": "replace", "path": "active", "value": true}))
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	assert.Equal(t, true, resp.JSON()["active"])
}

// Directories vary in how they spell the verb and the path; the
// vocabulary is matched case-insensitively per RFC 7644.
func TestUsers_PatchAcceptsMixedCaseVerbAndPath(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createUser(p, scimUser("mixedcase@example.com", "ext-mixedcase"))

	resp := f.do(http.MethodPatch, p.Slug, p.Token, "/Users/"+id,
		patchOps(map[string]any{"op": "Replace", "path": "Active", "value": false}))
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	assert.Equal(t, false, resp.JSON()["active"])
}

// Some directories send the flag as a string.
func TestUsers_PatchAcceptsStringActiveValue(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createUser(p, scimUser("stringactive@example.com", "ext-stringactive"))

	resp := f.do(http.MethodPatch, p.Slug, p.Token, "/Users/"+id,
		patchOps(map[string]any{"op": "replace", "path": "active", "value": "False"}))
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	assert.Equal(t, false, resp.JSON()["active"])
}

func TestUsers_PatchReplacesUserNameAndEmails(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	byUserName := f.createUser(p, scimUser("pu-before@example.com", "ext-pu"))
	resp := f.do(http.MethodPatch, p.Slug, p.Token, "/Users/"+byUserName,
		patchOps(map[string]any{"op": "replace", "path": "userName", "value": "pu-after@example.com"}))
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	assert.Equal(t, "pu-after@example.com", resp.JSON()["userName"])

	byEmails := f.createUser(p, scimUser("pe-before@example.com", "ext-pe"))
	resp = f.do(http.MethodPatch, p.Slug, p.Token, "/Users/"+byEmails,
		patchOps(map[string]any{
			"op":    "replace",
			"path":  "emails",
			"value": []map[string]any{{"value": "pe-after@example.com", "primary": true}},
		}))
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	assert.Equal(t, "pe-after@example.com", resp.JSON()["userName"])
}

func TestUsers_PatchReplacesNameObjectAndSubPaths(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	whole := f.createUser(p, scimUser("pname@example.com", "ext-pname"))
	require.Equal(t, http.StatusOK, f.do(http.MethodPatch, p.Slug, p.Token, "/Users/"+whole,
		patchOps(map[string]any{
			"op":    "replace",
			"path":  "name",
			"value": map[string]any{"givenName": "Ada", "familyName": "Lovelace"},
		})).Code)
	row, err := f.store.GetUser(f.ctx(), whole)
	require.NoError(t, err)
	assert.Equal(t, "Ada", row.GivenName)
	assert.Equal(t, "Lovelace", row.FamilyName)

	sub := f.createUser(p, scimUser("psub@example.com", "ext-psub"))
	require.Equal(t, http.StatusOK, f.do(http.MethodPatch, p.Slug, p.Token, "/Users/"+sub,
		patchOps(map[string]any{"op": "replace", "path": "name.givenName", "value": "Grace"})).Code)
	row, err = f.store.GetUser(f.ctx(), sub)
	require.NoError(t, err)
	assert.Equal(t, "Grace", row.GivenName)
}

// A replace with no path carries a map of attributes; each key is the
// path of an implied operation.
func TestUsers_PatchWithoutPathFansOutOverTheValueMap(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createUser(p, scimUser("nopath@example.com", "ext-nopath"))

	resp := f.do(http.MethodPatch, p.Slug, p.Token, "/Users/"+id, patchOps(map[string]any{
		"op": "replace",
		"value": map[string]any{
			"active":   false,
			"userName": "nopath-new@example.com",
		},
	}))
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	got := resp.JSON()
	assert.Equal(t, false, got["active"])
	assert.Equal(t, "nopath-new@example.com", got["userName"])
}

// A patch that changes several attributes commits them together, so a
// half-applied assertion cannot be observed.
func TestUsers_PatchIsAuditedInOneOperation(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createUser(p, scimUser("patchaudit@example.com", "ext-patchaudit"))

	require.Equal(t, http.StatusOK, f.do(http.MethodPatch, p.Slug, p.Token, "/Users/"+id, patchOps(
		map[string]any{"op": "replace", "path": "active", "value": false},
		map[string]any{"op": "replace", "path": "userName", "value": "patched@example.com"},
	)).Code)

	op := f.onlyOperationFor(scim.DescUsersPatch)
	assert.Equal(t, string(store.ClassBackgroundWriter), op.Class)
	effects := f.effectsOf(op.OperationID)
	f.effectWithAction(effects, "SET_DISABLED")
	f.effectWithAction(effects, "UPDATE_EMAIL")
	f.effectWithAction(effects, "SYNC_LINK")
}

// RFC 7644 defines exactly three verbs. An unknown one is a malformed
// request, not a silent no-op.
func TestUsers_PatchRejectsAnUnknownVerb(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createUser(p, scimUser("badverb@example.com", "ext-badverb"))

	resp := f.do(http.MethodPatch, p.Slug, p.Token, "/Users/"+id,
		patchOps(map[string]any{"op": "obliterate", "path": "active", "value": false}))
	assert.Equal(t, http.StatusBadRequest, resp.Code, "body: %s", resp)
}

// add and remove are valid SCIM verbs that this resource does not
// implement; they are refused explicitly rather than accepted and
// dropped.
func TestUsers_PatchRejectsUnsupportedVerbsOnUsers(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createUser(p, scimUser("addremove@example.com", "ext-addremove"))

	for _, verb := range []string{"add", "remove"} {
		t.Run(verb, func(t *testing.T) {
			resp := f.do(http.MethodPatch, p.Slug, p.Token, "/Users/"+id,
				patchOps(map[string]any{"op": verb, "path": "active", "value": false}))
			assert.Equal(t, http.StatusBadRequest, resp.Code, "body: %s", resp)
		})
	}
}

// A malformed value is the client's mistake. Reporting it as a server
// failure would make a directory retry forever.
func TestUsers_PatchRejectsAMalformedValue(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createUser(p, scimUser("badvalue@example.com", "ext-badvalue"))

	resp := f.do(http.MethodPatch, p.Slug, p.Token, "/Users/"+id,
		patchOps(map[string]any{"op": "replace", "path": "userName", "value": ""}))
	assert.Equal(t, http.StatusBadRequest, resp.Code, "body: %s", resp)
}

// A rejected patch writes nothing at all — not the change, and not an
// operation row claiming one happened.
func TestUsers_RejectedPatchLeavesNoStateAndNoOperation(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createUser(p, scimUser("noop@example.com", "ext-noop"))

	require.Equal(t, http.StatusBadRequest, f.do(http.MethodPatch, p.Slug, p.Token, "/Users/"+id,
		patchOps(map[string]any{"op": "obliterate", "path": "active", "value": false})).Code)

	row, err := f.store.GetUser(f.ctx(), id)
	require.NoError(t, err)
	assert.False(t, row.Disabled)
	assert.Empty(t, f.operationsFor(scim.DescUsersPatch))
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// The last binding is what keeps the subject reachable. Removing it
// erases the subject and destroys the key that made their sealed
// evidence readable.
func TestUsers_DeleteOfTheLastBindingErasesTheSubject(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createUser(p, scimUser("erase@example.com", "ext-erase"))

	_, err := f.store.GetUserEncryptionKey(f.ctx(), id)
	require.NoError(t, err, "seed sanity: a provisioned subject owns a key")

	resp := f.do(http.MethodDelete, p.Slug, p.Token, "/Users/"+id, nil)
	require.Equal(t, http.StatusNoContent, resp.Code, "body: %s", resp)

	_, err = f.store.GetUser(f.ctx(), id)
	assert.True(t, store.IsNotFound(err), "the subject row must be gone")
	_, err = f.store.GetUserEncryptionKey(f.ctx(), id)
	assert.True(t, store.IsNotFound(err), "erasure destroys the subject's key")
}

// A subject bound to a second directory is only unbound, never erased:
// the other directory still provisions them.
func TestUsers_DeleteWithAnotherBindingOnlyUnbinds(t *testing.T) {
	f := newFixture(t)
	a := f.seedProvider(nil)
	b := f.seedProvider(func(s *providerSeed) {
		s.AutoLinkByEmail = true
		s.TrustEmailAssertions = true
	})

	id := f.createUser(a, scimUser("shared@example.com", "ext-a"))
	require.Equal(t, http.StatusCreated,
		f.do(http.MethodPost, b.Slug, b.Token, "/Users", scimUser("shared@example.com", "ext-b")).Code)

	require.Equal(t, http.StatusNoContent, f.do(http.MethodDelete, b.Slug, b.Token, "/Users/"+id, nil).Code)

	_, err := f.store.GetUser(f.ctx(), id)
	assert.NoError(t, err, "the subject must survive while another directory still binds them")
	_, err = f.store.GetIdentityLinkByProviderAndUser(f.ctx(), b.ID, id)
	assert.True(t, store.IsNotFound(err), "the asking directory's binding must be gone")
	_, err = f.store.GetIdentityLinkByProviderAndUser(f.ctx(), a.ID, id)
	assert.NoError(t, err, "the other directory's binding must survive")
}

// The erasure record itself carries no sealed detail: it would be
// sealed under a key the same transaction destroys, and would be born
// unreadable.
func TestUsers_DeleteIsAuditedWithoutSealedDetail(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createUser(p, scimUser("eraseaudit@example.com", "ext-eraseaudit"))

	require.Equal(t, http.StatusNoContent, f.do(http.MethodDelete, p.Slug, p.Token, "/Users/"+id, nil).Code)

	op := f.onlyOperationFor(scim.DescUsersDelete)
	assert.Equal(t, string(store.ClassBackgroundWriter), op.Class)
	effects := f.effectsOf(op.OperationID)

	f.effectWithAction(effects, "UNLINK")
	erased := f.effectWithAction(effects, "ERASE")
	assert.Equal(t, id, erased.ResourceID)
	assert.Equal(t, sha256Hex("eraseaudit@example.com"), erased.EvidenceFingerprint)
	f.effectWithAction(effects, "DESTROY_KEY")

	for _, e := range effects {
		assert.Empty(t, e.SealedDetail,
			"an erasure must record no detail sealed under the key it destroys: %+v", e)
	}
}

// An unbind that is not an erasure records the unbind and nothing else.
func TestUsers_DeleteWithAnotherBindingRecordsNoErasure(t *testing.T) {
	f := newFixture(t)
	a := f.seedProvider(nil)
	b := f.seedProvider(func(s *providerSeed) {
		s.AutoLinkByEmail = true
		s.TrustEmailAssertions = true
	})
	id := f.createUser(a, scimUser("unbindaudit@example.com", "ext-ua"))
	require.Equal(t, http.StatusCreated,
		f.do(http.MethodPost, b.Slug, b.Token, "/Users", scimUser("unbindaudit@example.com", "ext-ub")).Code)

	require.Equal(t, http.StatusNoContent, f.do(http.MethodDelete, b.Slug, b.Token, "/Users/"+id, nil).Code)

	op := f.onlyOperationFor(scim.DescUsersDelete)
	effects := f.effectsOf(op.OperationID)
	f.effectWithAction(effects, "UNLINK")
	assert.False(t, f.hasEffectWithAction(effects, "ERASE"))
	assert.False(t, f.hasEffectWithAction(effects, "DESTROY_KEY"))
}

// ---------------------------------------------------------------------------
// Cross-directory isolation
// ---------------------------------------------------------------------------

// A directory addresses only the subjects bound to it. Another
// directory's subject reads as absent under every verb, so the id space
// cannot be probed.
func TestUsers_OtherDirectorysSubjectIsNotFoundUnderEveryVerb(t *testing.T) {
	f := newFixture(t)
	a := f.seedProvider(nil)
	b := f.seedProvider(nil)

	id := f.createUser(a, scimUser("isolated@example.com", "ext-isolated"))

	cases := []struct {
		verb string
		body any
	}{
		{http.MethodGet, nil},
		{http.MethodPut, scimUser("isolated@example.com", "ext-isolated")},
		{http.MethodPatch, patchOps(map[string]any{"op": "replace", "path": "active", "value": false})},
		{http.MethodDelete, nil},
	}
	for _, tc := range cases {
		t.Run(tc.verb, func(t *testing.T) {
			resp := f.do(tc.verb, b.Slug, b.Token, "/Users/"+id, tc.body)
			assert.Equal(t, http.StatusNotFound, resp.Code, "body: %s", resp)
		})
	}

	// Positive control: the owning directory reaches the same subject,
	// so the refusals above are scoping rather than a blanket failure.
	assert.Equal(t, http.StatusOK, f.do(http.MethodGet, a.Slug, a.Token, "/Users/"+id, nil).Code)
}

// One directory's list never contains another's subjects.
func TestUsers_ListIsConfinedToTheAskingDirectory(t *testing.T) {
	f := newFixture(t)
	a := f.seedProvider(nil)
	b := f.seedProvider(nil)

	f.createUser(a, scimUser("only-a@example.com", "ext-only-a"))

	resp := f.do(http.MethodGet, b.Slug, b.Token, "/Users", nil)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	assert.Equal(t, float64(0), resp.JSON()["totalResults"])
}
