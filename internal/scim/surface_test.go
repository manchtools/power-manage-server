package scim_test

// The audit contract for a non-RPC writer made mechanical.
//
// The design enumerates writers such as SCIM from their writable
// surface and requires each to be tested through the real route. That
// only holds if the enumeration cannot drift from what is actually
// mounted, so the classification is checked against the mount table
// rather than trusted to review.

import (
	"net/http"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/scim"
)

func mountedDescriptors(t *testing.T) []string {
	t.Helper()
	h := scim.New(scim.Config{})
	t.Cleanup(h.Close)
	mounted := h.Mount(http.NewServeMux())
	// Matches-zero guard: an empty mount would make every assertion
	// below vacuously true.
	require.NotEmpty(t, mounted, "no SCIM routes were mounted; the mount table is mis-scoped")
	return mounted
}

// Every mounted route is classified exactly once. A route added to
// Mount without being classified fails here, before it has a caller.
func TestSurface_EveryMountedRouteIsClassified(t *testing.T) {
	classified := map[string]string{}
	add := func(kind string, routes []string) {
		for _, r := range routes {
			if prev, dup := classified[r]; dup {
				t.Errorf("%s is classified both as %s and as %s", r, prev, kind)
				continue
			}
			classified[r] = kind
		}
	}
	add("mutation", scim.MutationRoutes())
	add("sensitive read", scim.SensitiveReadRoutes())
	add("discovery", scim.DiscoveryRoutes())

	var unclassified []string
	for _, r := range mountedDescriptors(t) {
		if _, ok := classified[r]; !ok {
			unclassified = append(unclassified, r)
		}
	}
	sort.Strings(unclassified)
	assert.Empty(t, unclassified,
		"every mounted SCIM route must be classified as a mutation, a sensitive read or discovery: %v",
		unclassified)
}

// The classification is not allowed to drift out of existence either: a
// route named in it that is no longer mounted is a stale entry that
// would silently widen the check.
func TestSurface_ClassificationHasNoStaleEntries(t *testing.T) {
	mounted := map[string]bool{}
	for _, r := range mountedDescriptors(t) {
		mounted[r] = true
	}

	var stale []string
	for kind, routes := range map[string][]string{
		"MutationRoutes":      scim.MutationRoutes(),
		"SensitiveReadRoutes": scim.SensitiveReadRoutes(),
		"DiscoveryRoutes":     scim.DiscoveryRoutes(),
	} {
		for _, r := range routes {
			if !mounted[r] {
				stale = append(stale, kind+": "+r)
			}
		}
	}
	sort.Strings(stale)
	assert.Empty(t, stale, "the SCIM route classification names routes that are not mounted: %v", stale)
}

// Every route classified as a mutation writes an operation row of the
// non-RPC-writer class, with at least one effect, on a real request.
// This is the coverage claim itself: exercised through the real route,
// against a real database, for the exact enumerated set.
func TestSurface_EveryMutationRouteRecordsItsOperationAndEffects(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)

	subject := f.createUser(p, scimUser("surface@example.com", "ext-surface"))
	groupID := f.createGroup(p, scimGroup("Surface", "grp-surface"))

	// One request per mutation route, in an order where each one has
	// something to change.
	exercise := []struct {
		descriptor string
		run        func()
	}{
		{scim.DescUsersCreate, func() {
			f.createUser(p, scimUser("surface-create@example.com", "ext-surface-create"))
		}},
		{scim.DescUsersReplace, func() {
			body := scimUser("surface-replaced@example.com", "ext-surface")
			require.Equal(t, http.StatusOK, f.do(http.MethodPut, p.Slug, p.Token, "/Users/"+subject, body).Code)
		}},
		{scim.DescUsersPatch, func() {
			require.Equal(t, http.StatusOK, f.do(http.MethodPatch, p.Slug, p.Token, "/Users/"+subject,
				patchOps(map[string]any{"op": "replace", "path": "active", "value": false})).Code)
		}},
		{scim.DescGroupsCreate, func() {
			f.createGroup(p, scimGroup("Surface Two", "grp-surface-two"))
		}},
		{scim.DescGroupsReplace, func() {
			require.Equal(t, http.StatusOK, f.do(http.MethodPut, p.Slug, p.Token, "/Groups/"+groupID,
				scimGroup("Surface Renamed", "grp-surface")).Code)
		}},
		{scim.DescGroupsPatch, func() {
			require.Equal(t, http.StatusOK, f.do(http.MethodPatch, p.Slug, p.Token, "/Groups/"+groupID,
				patchOps(map[string]any{"op": "add", "path": "members", "value": []map[string]any{{"value": subject}}})).Code)
		}},
		{scim.DescGroupsDelete, func() {
			require.Equal(t, http.StatusNoContent, f.do(http.MethodDelete, p.Slug, p.Token, "/Groups/"+groupID, nil).Code)
		}},
		{scim.DescUsersDelete, func() {
			require.Equal(t, http.StatusNoContent, f.do(http.MethodDelete, p.Slug, p.Token, "/Users/"+subject, nil).Code)
		}},
	}

	covered := map[string]bool{}
	for _, e := range exercise {
		e.run()
		covered[e.descriptor] = true
	}

	// The exercise set must be the enumerated set, not a subset that
	// happens to pass.
	for _, descriptor := range scim.MutationRoutes() {
		assert.Truef(t, covered[descriptor], "mutation route %s is enumerated but never exercised", descriptor)
	}

	for _, descriptor := range scim.MutationRoutes() {
		ops := f.operationsFor(descriptor)
		require.NotEmptyf(t, ops, "mutation route %s recorded no audit operation", descriptor)
		for _, op := range ops {
			assert.Equalf(t, "BACKGROUND_WRITER", op.Class,
				"%s must record under the non-RPC-writer class", descriptor)
			assert.Equalf(t, scim.Origin, op.Origin, "%s must record its origin", descriptor)
			assert.Equalf(t, p.ID, op.ActorID, "%s must name the acting directory", descriptor)
			assert.NotEmptyf(t, f.effectsOf(op.OperationID),
				"%s recorded an operation with no effect", descriptor)
		}
	}
}

// Every route classified as a sensitive read records an operation of
// that class on a real request.
func TestSurface_EverySensitiveReadRouteRecordsItsOperation(t *testing.T) {
	f := newFixture(t)
	p := f.seedProvider(nil)
	subject := f.createUser(p, scimUser("readsurface@example.com", "ext-readsurface"))
	groupID := f.createGroup(p, scimGroup("Read Surface", "grp-read-surface"))

	exercise := map[string]func(){
		scim.DescUsersList: func() {
			require.Equal(t, http.StatusOK, f.do(http.MethodGet, p.Slug, p.Token, "/Users", nil).Code)
		},
		scim.DescUsersGet: func() {
			require.Equal(t, http.StatusOK, f.do(http.MethodGet, p.Slug, p.Token, "/Users/"+subject, nil).Code)
		},
		scim.DescGroupsList: func() {
			require.Equal(t, http.StatusOK, f.do(http.MethodGet, p.Slug, p.Token, "/Groups", nil).Code)
		},
		scim.DescGroupsGet: func() {
			require.Equal(t, http.StatusOK, f.do(http.MethodGet, p.Slug, p.Token, "/Groups/"+groupID, nil).Code)
		},
	}

	for _, descriptor := range scim.SensitiveReadRoutes() {
		run, ok := exercise[descriptor]
		require.Truef(t, ok, "sensitive-read route %s is enumerated but never exercised", descriptor)
		run()

		ops := f.operationsFor(descriptor)
		require.Lenf(t, ops, 1, "sensitive-read route %s recorded no audit operation", descriptor)
		assert.Equalf(t, "SENSITIVE_READ", ops[0].Class,
			"%s must record under the sensitive-read class", descriptor)
	}
}
