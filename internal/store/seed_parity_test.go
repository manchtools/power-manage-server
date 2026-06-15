package store_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/auth"
)

// nonEmptyPermArrayRE matches a non-empty `'{Permission,…}'` literal in either
// INSERT (`…, '{GetUser,…}', …`) or UPDATE (`permissions = '{GetUser,…}'`)
// form — permission names start with a letter, so `'{` followed by a letter is
// a seeded list; the reconciler-owned empty array `'{}'` does not match. This
// is the drift-prone pattern WS17b #18 retires.
var nonEmptyPermArrayRE = regexp.MustCompile(`'\{[A-Za-z]`)

// TestSystemRolePermissionsAreReconcilerOwned pins that no migration leaves the
// Admin/User system roles seeded with a frozen SQL permission literal. Those
// literals duplicated the Go source of truth (auth.AdminPermissions /
// auth.DefaultUserPermissions, applied by auth.ReconcileSystemRoles on every
// boot) and silently drifted as permissions were added/renamed. Migration 014
// blanks them so the reconciler is the single source of truth; this test fails
// if a later migration re-introduces a non-empty literal for a system role.
func TestSystemRolePermissionsAreReconcilerOwned(t *testing.T) {
	files, err := filepath.Glob("migrations/*.sql")
	require.NoError(t, err)
	require.NotEmpty(t, files, "no migration files found")
	sort.Strings(files) // numeric prefixes → lexical order == apply order

	roleIDs := []string{auth.AdminRoleID, auth.UserRoleID}

	// Track, per role, the LAST migration that sets its permissions and whether
	// that final assignment is the reconciler-owned empty literal.
	lastFinalEmpty := map[string]bool{}
	lastFile := map[string]string{}
	sawSeed := false

	for _, f := range files {
		raw, err := os.ReadFile(f)
		require.NoError(t, err)
		// Scope the check to individual statements so a migration that mentions
		// a role ID in one statement and sets unrelated permissions in another
		// cannot produce a false classification. Splitting on ';' is sufficient
		// for these literal-only seed/update statements.
		for _, stmt := range strings.Split(string(raw), ";") {
			for _, roleID := range roleIDs {
				if !strings.Contains(stmt, roleID) {
					continue
				}
				// Only consider statements that actually set a permissions value.
				if !strings.Contains(stmt, "permissions") {
					continue
				}
				sawSeed = true
				// A non-empty literal here means this statement seeded a frozen
				// list; an empty '{}' (no match of the non-empty RE) means
				// reconciler-owned. Statements are visited in file order, so the
				// last one to set the role wins.
				lastFinalEmpty[roleID] = !nonEmptyPermArrayRE.MatchString(stmt)
				lastFile[roleID] = f
			}
		}
	}

	require.True(t, sawSeed, "expected at least one migration referencing the system role IDs")
	for _, roleID := range roleIDs {
		require.Contains(t, lastFile, roleID, "no migration sets permissions for system role %s", roleID)
		assert.Truef(t, lastFinalEmpty[roleID],
			"the last migration to set system role %s permissions (%s) seeds a frozen literal — "+
				"system-role permissions must be reconciler-owned (set to '{}') so they cannot drift from auth.AdminPermissions/DefaultUserPermissions",
			roleID, lastFile[roleID])
	}
}
