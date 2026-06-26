package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/auth"
)

// fakeObjectScopeGroups returns canned effective/direct groups (or an error) so
// the scope-enforcement DECISION logic is testable without a database.
type fakeObjectScopeGroups struct {
	eff, dir []string
	err      error
}

func (f fakeObjectScopeGroups) effective(context.Context, string, string) ([]string, error) {
	return f.eff, f.err
}
func (f fakeObjectScopeGroups) direct(context.Context, string, string) ([]string, error) {
	return f.dir, f.err
}

func ctxScoped(groupIDs ...string) context.Context {
	var grants []auth.ScopedGrant
	for _, id := range groupIDs {
		grants = append(grants, auth.ScopedGrant{Permission: "ListDevices", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: id})
	}
	return auth.WithUser(context.Background(), &auth.UserContext{ID: "caller", ScopedGrants: grants})
}

func ctxUnrestricted() context.Context {
	return auth.WithUser(context.Background(), &auth.UserContext{ID: "admin"})
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestEnforceObjectReadScope(t *testing.T) {
	log := discardLogger()

	t.Run("unrestricted caller is always allowed, even out of scope", func(t *testing.T) {
		err := enforceObjectReadScope(ctxUnrestricted(), fakeObjectScopeGroups{eff: nil}, log,
			"action_set", "as1", ErrActionSetNotFound, "action set not found")
		assert.NoError(t, err)
	})

	t.Run("scoped caller in effective scope is allowed", func(t *testing.T) {
		err := enforceObjectReadScope(ctxScoped("dg1"), fakeObjectScopeGroups{eff: []string{"dg9", "dg1"}}, log,
			"action_set", "as1", ErrActionSetNotFound, "action set not found")
		assert.NoError(t, err)
	})

	t.Run("scoped caller out of effective scope gets NotFound (no existence leak)", func(t *testing.T) {
		err := enforceObjectReadScope(ctxScoped("dg1"), fakeObjectScopeGroups{eff: []string{"dg9"}}, log,
			"action_set", "as1", ErrActionSetNotFound, "action set not found")
		require.Error(t, err)
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "must be NotFound, never PermissionDenied")
	})

	t.Run("scoped caller, unassigned object (no groups) gets NotFound", func(t *testing.T) {
		err := enforceObjectReadScope(ctxScoped("dg1"), fakeObjectScopeGroups{eff: nil}, log,
			"definition", "d1", ErrDefinitionNotFound, "definition not found")
		require.Error(t, err)
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	})

	t.Run("resolution error maps to Internal, not a silent allow", func(t *testing.T) {
		err := enforceObjectReadScope(ctxScoped("dg1"), fakeObjectScopeGroups{err: errors.New("db down")}, log,
			"action", "a1", ErrActionNotFound, "action not found")
		require.Error(t, err)
		assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
	})
}

func TestEnforceObjectWriteScope(t *testing.T) {
	log := discardLogger()

	t.Run("unrestricted caller is always allowed", func(t *testing.T) {
		err := enforceObjectWriteScope(ctxUnrestricted(), fakeObjectScopeGroups{dir: nil}, log, "action_set", "as1")
		assert.NoError(t, err)
	})

	t.Run("scoped caller directly in scope is allowed", func(t *testing.T) {
		err := enforceObjectWriteScope(ctxScoped("dg1"), fakeObjectScopeGroups{dir: []string{"dg1"}}, log, "action_set", "as1")
		assert.NoError(t, err)
	})

	t.Run("scoped caller out of DIRECT scope gets PermissionDenied", func(t *testing.T) {
		err := enforceObjectWriteScope(ctxScoped("dg1"), fakeObjectScopeGroups{dir: []string{"dg9"}}, log, "action_set", "as1")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})

	t.Run("transitive-only object (effective in scope, direct not) is NOT writable", func(t *testing.T) {
		// Direct groups are out of scope even though effective (a container) would
		// be in scope — write must key off DIRECT only.
		err := enforceObjectWriteScope(ctxScoped("dg1"), fakeObjectScopeGroups{dir: []string{"dg9"}, eff: []string{"dg1"}}, log, "action", "a1")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})

	t.Run("resolution error maps to Internal", func(t *testing.T) {
		err := enforceObjectWriteScope(ctxScoped("dg1"), fakeObjectScopeGroups{err: errors.New("db down")}, log, "action", "a1")
		require.Error(t, err)
		assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
	})
}
