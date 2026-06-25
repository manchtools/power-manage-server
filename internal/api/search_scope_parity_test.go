package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/search"
)

// TestScopeFilterFields_MirrorIndexSchemas is a self-discovering guard that the
// per-scope filter allow-list (scopeFilterFields) stays in lockstep with the
// RediSearch FT.CREATE schemas (search.IndexSchemas). The two MUST agree: a
// tag/range filter on a field an index never declared makes RediSearch reject
// the whole query with a SYNTAX error (server#158), and a declared TAG/NUMERIC
// field that's missing here is silently unfilterable. Both sides are derived
// from their sources — no hardcoded field list to fall stale — and the test
// fails if either gains a field the other lacks, or an index gains no entry.
func TestScopeFilterFields_MirrorIndexSchemas(t *testing.T) {
	require.NotEmpty(t, search.IndexSchemas, "no index schemas discovered — the parity check would vacuously pass")

	indexedScopes := map[string]bool{}
	for _, ix := range search.IndexSchemas {
		scope := ix.Scope()
		indexedScopes[scope] = true

		got, ok := scopeFilterFields[scope]
		assert.Truef(t, ok,
			"index %q (scope %q) has no scopeFilterFields entry — add one (an empty map if it declares no TAG/NUMERIC fields)", ix.Name, scope)

		want := ix.FilterableFields() // TAG/NUMERIC fields the index actually declares

		// Every declared filterable field must be advertised, else operators
		// can't filter on it — EXCEPT server-only scope fields (scope_group_ids),
		// which the server populates and filters on internally for RBAC scope and
		// intentionally never exposes as a client filter (#7 spec 14).
		for field := range want {
			if search.ServerScopeFields[field] {
				assert.Falsef(t, got[field],
					"scope %q: %q is a server-only scope field and must NOT be in scopeFilterFields (it would become a client filter)", scope, field)
				continue
			}
			assert.Truef(t, got[field],
				"scope %q: index %q declares filterable field %q (TAG/NUMERIC) but scopeFilterFields omits it", scope, ix.Name, field)
		}
		// Every advertised field must have a backing TAG/NUMERIC attribute, else
		// the filter the api accepts makes RediSearch reject the query.
		for field := range got {
			assert.Truef(t, want[field],
				"scope %q: scopeFilterFields lists %q but index %q has no TAG/NUMERIC attribute for it", scope, field, ix.Name)
		}
	}

	// Every scope the api advertises must map to a real index.
	for scope := range scopeFilterFields {
		assert.Truef(t, indexedScopes[scope],
			"scopeFilterFields advertises scope %q with no matching index schema", scope)
	}
}
