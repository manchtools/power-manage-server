package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/auth"
)

// TestSearchFacetsConfinedOrGated is the H4 confinement-parity guard. Every
// searchable facet MUST be either (a) scope-group-confined — it carries the
// scope_group_ids field, so scopeGroupClause narrows a restricted caller to
// their scope — OR (b) permission-gated — it's org-tier with no group scope, so
// facetListPermission requires the caller's dedicated List permission before the
// facet is queried. A facet that is NEITHER leaks fleet-wide to any Search
// holder (the H4 bug: executions/device_groups/user_groups had no field, and
// audit_events had no gate).
//
// Self-discovering: the facet set is searchScopeToIndex (exactly what the
// handler queries), the confined set is derived from the index schemas
// (scopesWithScopeGroupField), and the gated set is facetListPermission. Adding
// a new searchable facet with neither a scope_group_ids field nor a gate entry
// fails this test — it cannot ship as a silent fleet-wide leak.
func TestSearchFacetsConfinedOrGated(t *testing.T) {
	require.NotEmpty(t, searchScopeToIndex, "matches-zero: no searchable facets discovered — the guard would pass vacuously")

	for scope := range searchScopeToIndex {
		confined := scopesWithScopeGroupField[scope]
		_, gated := facetListPermission[scope]
		assert.Truef(t, confined || gated,
			"searchable facet %q is neither scope-confined (no scope_group_ids field) nor permission-gated (no facetListPermission entry) — it would leak fleet-wide to any Search holder. Add scope_group_ids to its index schema, or gate it on its dedicated List permission.", scope)
		assert.Falsef(t, confined && gated,
			"searchable facet %q is BOTH scope-confined and permission-gated — pick one: scope confinement for group-scopable facets, a permission gate only for org-tier facets that can't be group-scoped", scope)
	}

	// Every gated facet must be a real searchable facet (no stale entry), and its
	// permission must be a REAL, org-tier (TargetUnspecified) permission. This is
	// load-bearing, not cosmetic: a group-scopable permission here would admit a
	// scope-restricted caller to a facet Search can't confine — HasPermission(base)
	// is true for a group-scoped holder, so the gate would pass and the whole
	// (unconfined) facet would leak. A typo'd key would silently make the facet
	// unqueryable. TargetKindFor returns TargetUnspecified for BOTH org-tier and
	// unknown keys, so existence is asserted separately.
	validPerms := auth.ValidPermissionKeys()
	for scope, perm := range facetListPermission {
		_, searchable := searchScopeToIndex[scope]
		assert.Truef(t, searchable, "facetListPermission gates %q which is not a searchable facet", scope)
		assert.Truef(t, validPerms[perm],
			"facetListPermission[%q] = %q is not a real permission key (typo? renamed?) — the gate would make the facet permanently unqueryable", scope, perm)
		assert.Equalf(t, auth.TargetUnspecified, auth.TargetKindFor(perm),
			"facetListPermission[%q] = %q must be an org-tier (TargetUnspecified) permission — a group-scopable gate perm admits a scope-restricted caller to a facet Search cannot confine (HasPermission(base) is true for scoped holders), reopening the H4 leak", scope, perm)
	}
}

// TestSearchConfinedFacets_YieldNonEmptyClause is the behavioral half of the
// guard (audit wording: "every searchable scope with a scoped dedicated List RPC
// must yield a non-empty confining clause for a restricted caller"). For a caller
// restricted to one group, scopeGroupClause on EVERY confined facet must return a
// non-empty confining clause — never "" (which is fail-open to the whole
// catalog). This catches a facet that gains the scope_group_ids field but whose
// scopeGroupClause switch arm forgets to confine it.
func TestSearchConfinedFacets_YieldNonEmptyClause(t *testing.T) {
	require.NotEmpty(t, scopesWithScopeGroupField, "matches-zero: no confined facets discovered")

	// A caller restricted on all three axes (device-group, user-group, object
	// union) so every confined facet resolves to a real, non-empty clause.
	restricted := auth.WithUser(context.Background(), &auth.UserContext{
		ID:          "c",
		Permissions: []string{"ListDevices", "ListUsers"},
		ScopedGrants: []auth.ScopedGrant{
			{Permission: "ListDevices", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: "dg1"},
			{Permission: "ListUsers", ScopeKind: auth.ScopeKindUserGroup, ScopeID: "ug1"},
		},
	})

	for scope := range scopesWithScopeGroupField {
		clause := scopeGroupClause(restricted, scope)
		assert.NotEmptyf(t, clause,
			"confined facet %q yielded an EMPTY clause for a scope-restricted caller — fail-open leak. scopeGroupClause must confine every facet in scopesWithScopeGroupField.", scope)
	}
}
