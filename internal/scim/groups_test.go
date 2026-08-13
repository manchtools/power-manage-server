package scim_test

// The group cluster: mapping a directory group onto a local user group,
// reconciling its membership, the cross-directory guard on every
// member-add sink, and the authority a membership actually confers.

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/scim"
	"github.com/manchtools/power-manage/server/internal/store"
)

func scimGroup(displayName, externalID string, memberIDs ...string) map[string]any {
	body := map[string]any{
		"schemas":     []string{scim.GroupSchema},
		"displayName": displayName,
		"externalId":  externalID,
	}
	if memberIDs != nil {
		members := make([]map[string]any, 0, len(memberIDs))
		for _, id := range memberIDs {
			members = append(members, map[string]any{"value": id})
		}
		body["members"] = members
	}
	return body
}

// createGroup POSTs a group and returns the local user-group id.
func (f *fixture) createGroup(p *provider, body map[string]any) string {
	f.t.Helper()
	resp := f.do(http.MethodPost, p.Slug, p.Token, "/Groups", body)
	require.Equal(f.t, http.StatusCreated, resp.Code, "body: %s", resp)
	id, _ := resp.JSON()["id"].(string)
	require.NotEmpty(f.t, id)
	return id
}

func memberValues(t *testing.T, body map[string]any) []string {
	t.Helper()
	raw, _ := body["members"].([]any)
	out := make([]string, 0, len(raw))
	for _, m := range raw {
		entry, ok := m.(map[string]any)
		require.True(t, ok)
		out = append(out, entry["value"].(string))
	}
	return out
}

// ---------------------------------------------------------------------------
// Create and read
// ---------------------------------------------------------------------------

func TestGroups_CreateMapsADirectoryGroup(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	resp := f.do(http.MethodPost, p.Slug, p.Token, "/Groups", scimGroup("Engineering", "grp-eng"))
	require.Equal(t, http.StatusCreated, resp.Code, "body: %s", resp)
	got := resp.JSON()
	assert.NotEmpty(t, got["id"])
	assert.Equal(t, "Engineering", got["displayName"])
	assert.Equal(t, "grp-eng", got["externalId"])

	group, err := f.store.GetUserGroup(f.ctx(), got["id"].(string))
	require.NoError(t, err)
	assert.Equal(t, "Engineering", group.Name)
}

func TestGroups_CreateRequiresADisplayName(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	resp := f.do(http.MethodPost, p.Slug, p.Token, "/Groups", map[string]any{
		"schemas":    []string{scim.GroupSchema},
		"externalId": "grp-nameless",
	})
	assert.Equal(t, http.StatusBadRequest, resp.Code, "body: %s", resp)
}

func TestGroups_GetReturnsTheGroupAndItsMembers(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	member := f.createUser(p, scimUser("member@example.com", "ext-member"))
	id := f.createGroup(p, scimGroup("Design", "grp-design", member))

	resp := f.do(http.MethodGet, p.Slug, p.Token, "/Groups/"+id, nil)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	got := resp.JSON()
	assert.Equal(t, id, got["id"])
	assert.Equal(t, "Design", got["displayName"])
	assert.Equal(t, []string{member}, memberValues(t, got))
}

func TestGroups_GetUnknownGroupIsNotFound(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	assert.Equal(t, http.StatusNotFound,
		f.do(http.MethodGet, p.Slug, p.Token, "/Groups/"+newULID(), nil).Code)
}

func TestGroups_ListIsEmptyForAFreshDirectory(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	resp := f.do(http.MethodGet, p.Slug, p.Token, "/Groups", nil)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	assert.Equal(t, float64(0), resp.JSON()["totalResults"])
}

func TestGroups_ListFilters(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	f.createGroup(p, scimGroup("Alpha", "grp-alpha"))
	f.createGroup(p, scimGroup("Beta", "grp-beta"))

	byName := f.do(http.MethodGet, p.Slug, p.Token, `/Groups?filter=displayName+eq+%22Alpha%22`, nil)
	require.Equal(t, http.StatusOK, byName.Code, "body: %s", byName)
	assert.Equal(t, float64(1), byName.JSON()["totalResults"])

	byExternal := f.do(http.MethodGet, p.Slug, p.Token, `/Groups?filter=externalId+eq+%22grp-beta%22`, nil)
	require.Equal(t, http.StatusOK, byExternal.Code, "body: %s", byExternal)
	assert.Equal(t, float64(1), byExternal.JSON()["totalResults"])

	unsupported := f.do(http.MethodGet, p.Slug, p.Token, `/Groups?filter=userName+eq+%22x%22`, nil)
	assert.Equal(t, http.StatusBadRequest, unsupported.Code, "body: %s", unsupported)
}

func TestGroups_ListIsConfinedToTheAskingDirectory(t *testing.T) {
	f := newFixture(t)
	a := f.seedProvider(nil)
	b := f.seedProvider(nil)
	f.createGroup(a, scimGroup("Only A", "grp-only-a"))

	resp := f.do(http.MethodGet, b.Slug, b.Token, "/Groups", nil)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	assert.Equal(t, float64(0), resp.JSON()["totalResults"])
}

// Re-POSTing an already-mapped group renames it rather than minting a
// second local group; a directory re-asserts its whole population on
// every sync.
func TestGroups_RepostRenamesInsteadOfDuplicating(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createGroup(p, scimGroup("Before", "grp-rename"))

	resp := f.do(http.MethodPost, p.Slug, p.Token, "/Groups", scimGroup("After", "grp-rename"))
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	assert.Equal(t, id, resp.JSON()["id"])
	assert.Equal(t, "After", resp.JSON()["displayName"])

	group, err := f.store.GetUserGroup(f.ctx(), id)
	require.NoError(t, err)
	assert.Equal(t, "After", group.Name, "the local group must be renamed with its mapping")

	mappings, err := f.store.ListSCIMGroupMappings(f.ctx(), p.ID)
	require.NoError(t, err)
	assert.Len(t, mappings, 1, "a re-assertion must not mint a second mapping")
}

// ---------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------

func TestGroups_PatchAddsAndRemovesMembers(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	member := f.createUser(p, scimUser("patchmember@example.com", "ext-patchmember"))
	id := f.createGroup(p, scimGroup("Team", "grp-team"))

	add := f.do(http.MethodPatch, p.Slug, p.Token, "/Groups/"+id, patchOps(map[string]any{
		"op": "add", "path": "members", "value": []map[string]any{{"value": member}},
	}))
	require.Equal(t, http.StatusOK, add.Code, "body: %s", add)
	assert.Equal(t, []string{member}, memberValues(t, add.JSON()))

	remove := f.do(http.MethodPatch, p.Slug, p.Token, "/Groups/"+id, patchOps(map[string]any{
		"op": "remove", "path": `members[value eq "` + member + `"]`,
	}))
	require.Equal(t, http.StatusOK, remove.Code, "body: %s", remove)
	assert.Empty(t, memberValues(t, remove.JSON()))
}

func TestGroups_PatchReplacesTheWholeMemberSet(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	first := f.createUser(p, scimUser("first@example.com", "ext-first"))
	second := f.createUser(p, scimUser("second@example.com", "ext-second"))
	id := f.createGroup(p, scimGroup("Swap", "grp-swap", first))

	resp := f.do(http.MethodPatch, p.Slug, p.Token, "/Groups/"+id, patchOps(map[string]any{
		"op": "replace", "path": "members", "value": []map[string]any{{"value": second}},
	}))
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	assert.Equal(t, []string{second}, memberValues(t, resp.JSON()))
}

func TestGroups_PatchRenamesViaDisplayName(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createGroup(p, scimGroup("Old Name", "grp-patchname"))

	resp := f.do(http.MethodPatch, p.Slug, p.Token, "/Groups/"+id, patchOps(map[string]any{
		"op": "replace", "path": "displayName", "value": "New Name",
	}))
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	assert.Equal(t, "New Name", resp.JSON()["displayName"])

	group, err := f.store.GetUserGroup(f.ctx(), id)
	require.NoError(t, err)
	assert.Equal(t, "New Name", group.Name)
}

func TestGroups_PatchRejectsAnUnknownVerb(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createGroup(p, scimGroup("Verbs", "grp-verbs"))

	resp := f.do(http.MethodPatch, p.Slug, p.Token, "/Groups/"+id, patchOps(map[string]any{
		"op": "obliterate", "path": "members", "value": []map[string]any{},
	}))
	assert.Equal(t, http.StatusBadRequest, resp.Code, "body: %s", resp)
}

// A PUT that omits `members` is not asserting an empty membership: the
// field is absent, so the current set is left alone.
func TestGroups_ReplaceWithoutMembersPreservesThem(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	member := f.createUser(p, scimUser("preserved@example.com", "ext-preserved"))
	id := f.createGroup(p, scimGroup("Preserve", "grp-preserve", member))

	resp := f.do(http.MethodPut, p.Slug, p.Token, "/Groups/"+id, map[string]any{
		"schemas":     []string{scim.GroupSchema},
		"displayName": "Preserve Renamed",
	})
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	assert.Equal(t, "Preserve Renamed", resp.JSON()["displayName"])
	assert.Equal(t, []string{member}, memberValues(t, resp.JSON()))
}

// An explicitly empty member list IS an assertion: the group is emptied.
func TestGroups_ReplaceWithEmptyMembersEmptiesTheGroup(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	member := f.createUser(p, scimUser("emptied@example.com", "ext-emptied"))
	id := f.createGroup(p, scimGroup("Emptied", "grp-emptied", member))

	body := scimGroup("Emptied", "grp-emptied")
	body["members"] = []map[string]any{}
	resp := f.do(http.MethodPut, p.Slug, p.Token, "/Groups/"+id, body)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	assert.Empty(t, memberValues(t, resp.JSON()))
}

// The directory is the source of truth for membership, so a PUT
// re-adds a member that was removed server-side.
func TestGroups_ReplaceReconcilesAServerSideRemoval(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	member := f.createUser(p, scimUser("reconciled@example.com", "ext-reconciled"))
	id := f.createGroup(p, scimGroup("Reconcile", "grp-reconcile", member))

	_, err := f.raw.Exec(f.ctx(),
		`DELETE FROM user_group_members WHERE group_id = $1 AND user_id = $2`, id, member)
	require.NoError(t, err)

	resp := f.do(http.MethodPut, p.Slug, p.Token, "/Groups/"+id, scimGroup("Reconcile", "grp-reconcile", member))
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
	assert.Equal(t, []string{member}, memberValues(t, resp.JSON()))
}

// ---------------------------------------------------------------------------
// Cross-directory guard on every member-add sink
// ---------------------------------------------------------------------------

// Membership confers the group's role grants, so adding a subject a
// directory does not own would let it grant authority to somebody
// else's account. Every sink that can add a member refuses it.
func TestGroups_MemberAddRefusesAnotherDirectorysSubject(t *testing.T) {
	f := newFixture(t)
	a := f.seedProvider(nil)
	b := f.seedProvider(nil)

	foreign := f.createUser(a, scimUser("foreign@example.com", "ext-foreign"))
	own := f.createUser(b, scimUser("own@example.com", "ext-own"))

	t.Run("owned_subject_is_added", func(t *testing.T) {
		id := f.createGroup(b, scimGroup("Own", "grp-own"))
		resp := f.do(http.MethodPatch, b.Slug, b.Token, "/Groups/"+id, patchOps(map[string]any{
			"op": "add", "path": "members", "value": []map[string]any{{"value": own}},
		}))
		require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp)
		members, err := f.store.ListUserGroupMemberIDs(f.ctx(), id)
		require.NoError(t, err)
		assert.Contains(t, members, own)
	})

	t.Run("create_with_members", func(t *testing.T) {
		id := f.createGroup(b, scimGroup("Create", "grp-x-create", foreign))
		members, err := f.store.ListUserGroupMemberIDs(f.ctx(), id)
		require.NoError(t, err)
		assert.NotContains(t, members, foreign)
	})

	t.Run("patch_add", func(t *testing.T) {
		id := f.createGroup(b, scimGroup("PatchAdd", "grp-x-add"))
		f.do(http.MethodPatch, b.Slug, b.Token, "/Groups/"+id, patchOps(map[string]any{
			"op": "add", "path": "members", "value": []map[string]any{{"value": foreign}},
		}))
		members, err := f.store.ListUserGroupMemberIDs(f.ctx(), id)
		require.NoError(t, err)
		assert.NotContains(t, members, foreign)
	})

	t.Run("patch_replace_members", func(t *testing.T) {
		id := f.createGroup(b, scimGroup("PatchReplace", "grp-x-replace"))
		f.do(http.MethodPatch, b.Slug, b.Token, "/Groups/"+id, patchOps(map[string]any{
			"op": "replace", "path": "members", "value": []map[string]any{{"value": foreign}},
		}))
		members, err := f.store.ListUserGroupMemberIDs(f.ctx(), id)
		require.NoError(t, err)
		assert.NotContains(t, members, foreign)
	})

	t.Run("put_reconcile", func(t *testing.T) {
		id := f.createGroup(b, scimGroup("PutReconcile", "grp-x-put"))
		f.do(http.MethodPut, b.Slug, b.Token, "/Groups/"+id, scimGroup("PutReconcile", "grp-x-put", foreign))
		members, err := f.store.ListUserGroupMemberIDs(f.ctx(), id)
		require.NoError(t, err)
		assert.NotContains(t, members, foreign)
	})
}

// Another directory's group reads as absent under every verb.
func TestGroups_OtherDirectorysGroupIsNotFoundUnderEveryVerb(t *testing.T) {
	f := newFixture(t)
	a := f.seedProvider(nil)
	b := f.seedProvider(nil)
	id := f.createGroup(a, scimGroup("Isolated", "grp-isolated"))

	cases := []struct {
		verb string
		body any
	}{
		{http.MethodGet, nil},
		{http.MethodPut, scimGroup("Isolated", "grp-isolated")},
		{http.MethodPatch, patchOps(map[string]any{"op": "replace", "path": "displayName", "value": "x"})},
		{http.MethodDelete, nil},
	}
	for _, tc := range cases {
		t.Run(tc.verb, func(t *testing.T) {
			resp := f.do(tc.verb, b.Slug, b.Token, "/Groups/"+id, tc.body)
			assert.Equal(t, http.StatusNotFound, resp.Code, "body: %s", resp)
		})
	}

	assert.Equal(t, http.StatusOK, f.do(http.MethodGet, a.Slug, a.Token, "/Groups/"+id, nil).Code)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Deleting a directory group removes the mapping only. The local group
// may carry role grants an operator configured, so it is not destroyed
// because a directory stopped syncing it.
func TestGroups_DeleteUnmapsAndKeepsTheLocalGroup(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createGroup(p, scimGroup("Temp", "grp-temp"))

	require.Equal(t, http.StatusNoContent, f.do(http.MethodDelete, p.Slug, p.Token, "/Groups/"+id, nil).Code)
	assert.Equal(t, http.StatusNotFound, f.do(http.MethodGet, p.Slug, p.Token, "/Groups/"+id, nil).Code)

	group, err := f.store.GetUserGroup(f.ctx(), id)
	require.NoError(t, err, "the local group must survive an unmap")
	assert.Equal(t, "Temp", group.Name)
}

// searchDocumentFields reads one entity's search-document field map, which is
// exactly what a list page receives for that row.
func (f *fixture) searchDocumentFields(scope, entityID string) map[string]string {
	f.t.Helper()
	var raw []byte
	require.NoError(f.t, f.raw.QueryRow(f.ctx(),
		`SELECT fields FROM search_documents WHERE scope = $1 AND entity_id = $2`,
		scope, entityID).Scan(&raw))
	fields := map[string]string{}
	require.NoError(f.t, json.Unmarshal(raw, &fields))
	return fields
}

// Mapping and unmapping a directory group are the writes that change whether a
// local group is SCIM-managed, and the user-groups LIST renders that state
// from the search document — so both writes must refresh the group's document
// in their own transaction.
func TestGroups_MappingRefreshesTheScimManagedDocumentField(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createGroup(p, scimGroup("Engineering", "grp-eng"))

	assert.Equal(t, "true", f.searchDocumentFields("user_groups", id)["is_scim_managed"],
		"provisioning maps the group, so its document is SCIM-managed from birth")

	require.Equal(t, http.StatusNoContent, f.do(http.MethodDelete, p.Slug, p.Token, "/Groups/"+id, nil).Code)
	_, err := f.store.GetUserGroup(f.ctx(), id)
	require.NoError(t, err, "positive control: the local group survives the unmap")
	assert.Equal(t, "false", f.searchDocumentFields("user_groups", id)["is_scim_managed"],
		"unmapping must refresh the surviving group's document in the same transaction")
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

func TestGroups_CreateIsAuditedInOneOperation(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	member := f.createUser(p, scimUser("groupaudit@example.com", "ext-groupaudit"))

	id := f.createGroup(p, scimGroup("Audited", "grp-audited", member))

	op := f.onlyOperationFor(scim.DescGroupsCreate)
	assert.Equal(t, string(store.ClassBackgroundWriter), op.Class)
	assert.Equal(t, p.ID, op.ActorID)

	effects := f.effectsOf(op.OperationID)
	created := f.effectWithAction(effects, "CREATE")
	assert.Equal(t, "user_group", created.ResourceType)
	assert.Equal(t, id, created.ResourceID)

	mapped := f.effectWithAction(effects, "MAP")
	assert.Equal(t, "scim_group_mapping", mapped.ResourceType)
	require.NotNil(t, mapped.AfterRef)
	assert.Equal(t, id, *mapped.AfterRef)

	joined := f.effectWithAction(effects, "JOIN")
	assert.Equal(t, "user_group_member", joined.ResourceType)
	require.NotNil(t, joined.AfterRef)
	assert.Equal(t, member, *joined.AfterRef)
}

func TestGroups_MembershipChangeIsAudited(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	member := f.createUser(p, scimUser("joinleave@example.com", "ext-joinleave"))
	id := f.createGroup(p, scimGroup("JoinLeave", "grp-joinleave"))

	require.Equal(t, http.StatusOK, f.do(http.MethodPatch, p.Slug, p.Token, "/Groups/"+id, patchOps(map[string]any{
		"op": "add", "path": "members", "value": []map[string]any{{"value": member}},
	})).Code)
	require.Equal(t, http.StatusOK, f.do(http.MethodPatch, p.Slug, p.Token, "/Groups/"+id, patchOps(map[string]any{
		"op": "remove", "path": `members[value eq "` + member + `"]`,
	})).Code)

	ops := f.operationsFor(scim.DescGroupsPatch)
	require.Len(t, ops, 2)
	f.effectWithAction(f.effectsOf(ops[0].OperationID), "JOIN")
	f.effectWithAction(f.effectsOf(ops[1].OperationID), "LEAVE")
}

func TestGroups_DeleteIsAudited(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createGroup(p, scimGroup("Unmapped", "grp-unmapped"))

	require.Equal(t, http.StatusNoContent, f.do(http.MethodDelete, p.Slug, p.Token, "/Groups/"+id, nil).Code)

	op := f.onlyOperationFor(scim.DescGroupsDelete)
	effect := f.effectWithAction(f.effectsOf(op.OperationID), "UNMAP")
	assert.Equal(t, "scim_group_mapping", effect.ResourceType)
	require.NotNil(t, effect.BeforeRef)
	assert.Equal(t, id, *effect.BeforeRef)
}

func TestGroups_ReadsAreAuditedAsSensitiveReads(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	id := f.createGroup(p, scimGroup("Readable", "grp-readable"))

	require.Equal(t, http.StatusOK, f.do(http.MethodGet, p.Slug, p.Token, "/Groups", nil).Code)
	require.Equal(t, http.StatusOK, f.do(http.MethodGet, p.Slug, p.Token, "/Groups/"+id, nil).Code)

	list := f.onlyOperationFor(scim.DescGroupsList)
	assert.Equal(t, string(store.ClassSensitiveRead), list.Class)
	listed := f.effectWithAction(f.effectsOf(list.OperationID), "LIST_GROUPS")
	assert.Equal(t, p.ID, listed.ResourceID)

	get := f.onlyOperationFor(scim.DescGroupsGet)
	assert.Equal(t, string(store.ClassSensitiveRead), get.Class)
	read := f.effectWithAction(f.effectsOf(get.OperationID), "READ")
	assert.Equal(t, "user_group", read.ResourceType)
	assert.Equal(t, id, read.ResourceID)
}

// ---------------------------------------------------------------------------
// The authority a membership confers
// ---------------------------------------------------------------------------

// The end-to-end claim of the whole group surface: a subject the
// directory provisioned, added to a group an operator gave a role,
// holds that role's permission in the authorizer's evaluation — and
// loses it when the directory removes them.
func TestGroups_MembershipConfersTheGroupsRoleGrant(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	subject := f.createUser(p, scimUser("rbac@example.com", "ext-rbac"))
	groupID := f.createGroup(p, scimGroup("Operators", "grp-operators"))
	roleID := f.insertRole([]string{"ListDevices"})
	f.grantRoleToUserGroup(groupID, roleID)

	before, err := f.store.ListUserPermissions(f.ctx(), subject)
	require.NoError(t, err)
	require.NotContains(t, before, "ListDevices", "seed sanity: the subject starts with no authority")

	require.Equal(t, http.StatusOK, f.do(http.MethodPatch, p.Slug, p.Token, "/Groups/"+groupID, patchOps(map[string]any{
		"op": "add", "path": "members", "value": []map[string]any{{"value": subject}},
	})).Code)

	perms, err := f.store.ListUserPermissions(f.ctx(), subject)
	require.NoError(t, err)
	require.Contains(t, perms, "ListDevices",
		"membership of a role-bearing group must confer that role's permission")

	// The authorizer evaluates the same authority the store resolved.
	grants, err := f.store.ListUserScopedGrants(f.ctx(), subject)
	require.NoError(t, err)
	scoped := make([]auth.ScopedGrant, 0, len(grants))
	for _, g := range grants {
		sg := auth.ScopedGrant{Permission: g.Permission}
		if g.ScopeKind != nil {
			sg.ScopeKind = *g.ScopeKind
		}
		if g.ScopeID != nil {
			sg.ScopeID = *g.ScopeID
		}
		scoped = append(scoped, sg)
	}
	ctx := auth.WithUser(f.ctx(), &auth.UserContext{
		ID:           subject,
		Kind:         auth.PrincipalUser,
		Email:        "rbac@example.com",
		Permissions:  perms,
		ScopedGrants: scoped,
	})
	assert.True(t, auth.HasPermission(ctx, "ListDevices"),
		"the authorizer must see the authority the group conferred")

	// Removing the membership withdraws it again.
	require.Equal(t, http.StatusOK, f.do(http.MethodPatch, p.Slug, p.Token, "/Groups/"+groupID, patchOps(map[string]any{
		"op": "remove", "path": `members[value eq "` + subject + `"]`,
	})).Code)
	after, err := f.store.ListUserPermissions(f.ctx(), subject)
	require.NoError(t, err)
	assert.NotContains(t, after, "ListDevices")
}

// A membership change is an authorization change, so the sessions
// minted under the previous authority stop validating.
func TestGroups_MembershipChangeInvalidatesTheSubjectsSessions(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	subject := f.createUser(p, scimUser("bump@example.com", "ext-bump"))
	groupID := f.createGroup(p, scimGroup("Bump", "grp-bump"))

	before, err := f.store.GetUserSessionState(f.ctx(), subject)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, f.do(http.MethodPatch, p.Slug, p.Token, "/Groups/"+groupID, patchOps(map[string]any{
		"op": "add", "path": "members", "value": []map[string]any{{"value": subject}},
	})).Code)
	joined, err := f.store.GetUserSessionState(f.ctx(), subject)
	require.NoError(t, err)
	require.Greater(t, joined.SessionVersion, before.SessionVersion, "joining must invalidate prior sessions")

	require.Equal(t, http.StatusOK, f.do(http.MethodPatch, p.Slug, p.Token, "/Groups/"+groupID, patchOps(map[string]any{
		"op": "remove", "path": `members[value eq "` + subject + `"]`,
	})).Code)
	left, err := f.store.GetUserSessionState(f.ctx(), subject)
	require.NoError(t, err)
	assert.Greater(t, left.SessionVersion, joined.SessionVersion, "leaving must invalidate prior sessions")
}
