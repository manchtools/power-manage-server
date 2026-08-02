package store_test

// Schema integrity: what the grant tables must be able to represent,
// and which references the database enforces.

import (
	"context"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/server/internal/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func exec(t *testing.T, pool *testdb.DB, sql string, args ...any) {
	t.Helper()
	_, err := pool.Exec(context.Background(), sql, args...)
	require.NoError(t, err)
}

func execFails(t *testing.T, pool *testdb.DB, sql string, args ...any) error {
	t.Helper()
	_, err := pool.Exec(context.Background(), sql, args...)
	require.Error(t, err)
	return err
}

func seedUser(t *testing.T, pool *testdb.DB) string {
	t.Helper()
	id := newID()
	exec(t, pool, `INSERT INTO users (id, email) VALUES ($1, $2)`, id, id+"@example.test")
	return id
}

func seedRole(t *testing.T, pool *testdb.DB) string {
	t.Helper()
	id := newID()
	exec(t, pool, `INSERT INTO roles (id, name) VALUES ($1, $2)`, id, "role-"+id)
	return id
}

func seedUserGroup(t *testing.T, pool *testdb.DB) string {
	t.Helper()
	id := newID()
	exec(t, pool, `INSERT INTO user_groups (id, name) VALUES ($1, $2)`, id, "ug-"+id)
	return id
}

func seedDeviceGroup(t *testing.T, pool *testdb.DB) string {
	t.Helper()
	id := newID()
	exec(t, pool, `INSERT INTO device_groups (id, name) VALUES ($1, $2)`, id, "dg-"+id)
	return id
}

// A user carries no authorization of its own: what a subject may do
// comes from user_roles and user_group_roles. A scalar column beside
// them would be a second, conflicting answer to the same question.
func TestSchema_UsersCarryNoScalarRole(t *testing.T) {
	_, pool := setupSQLite(t)

	cols := scanStrings(t, pool, `
		SELECT name FROM pragma_table_xinfo('users')`)
	require.NotEmpty(t, cols, "matches-zero guard: the users table has no columns")
	assert.NotContains(t, cols, "role")
}

// A subject may hold one role globally AND at several distinct scopes
// at once, which a natural key of (subject, role) makes unrepresentable.
// Uniqueness is instead exactly one unscoped grant per subject and role,
// and one per subject, role and distinct scope.
func TestUserRoles_GrantsCoexistPerScopeAndRejectDuplicates(t *testing.T) {
	_, pool := setupSQLite(t)

	user := seedUser(t, pool)
	role := seedRole(t, pool)
	scopeA := seedDeviceGroup(t, pool)
	scopeB := seedDeviceGroup(t, pool)

	grant := `INSERT INTO user_roles (grant_id, user_id, role_id, scope_kind, scope_id)
	          VALUES ($1, $2, $3, $4, $5)`

	exec(t, pool, grant, newID(), user, role, nil, nil)
	exec(t, pool, grant, newID(), user, role, "device_group", scopeA)
	exec(t, pool, grant, newID(), user, role, "device_group", scopeB)

	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_roles WHERE user_id = $1 AND role_id = $2`, user, role).Scan(&n))
	assert.Equal(t, 3, n, "one global grant and two distinct scoped grants of the same role")

	err := execFails(t, pool, grant, newID(), user, role, nil, nil)
	assert.Contains(t, err.Error(), "UNIQUE constraint failed")

	err = execFails(t, pool, grant, newID(), user, role, "device_group", scopeA)
	assert.Contains(t, err.Error(), "UNIQUE constraint failed")
}

func TestUserGroupRoles_GrantsCoexistPerScopeAndRejectDuplicates(t *testing.T) {
	_, pool := setupSQLite(t)

	group := seedUserGroup(t, pool)
	role := seedRole(t, pool)
	scopeA := seedDeviceGroup(t, pool)
	scopeB := seedUserGroup(t, pool)

	grant := `INSERT INTO user_group_roles (grant_id, group_id, role_id, scope_kind, scope_id)
	          VALUES ($1, $2, $3, $4, $5)`

	exec(t, pool, grant, newID(), group, role, nil, nil)
	exec(t, pool, grant, newID(), group, role, "device_group", scopeA)
	exec(t, pool, grant, newID(), group, role, "user_group", scopeB)

	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_group_roles WHERE group_id = $1 AND role_id = $2`, group, role).Scan(&n))
	assert.Equal(t, 3, n)

	err := execFails(t, pool, grant, newID(), group, role, nil, nil)
	assert.Contains(t, err.Error(), "UNIQUE constraint failed")

	err = execFails(t, pool, grant, newID(), group, role, "device_group", scopeA)
	assert.Contains(t, err.Error(), "UNIQUE constraint failed")
}

// declaredForeignKeys returns "table.column -> parent" for every
// single-column foreign key in the schema.
func declaredForeignKeys(t *testing.T, pool *testdb.DB) []string {
	t.Helper()
	fks := scanStrings(t, pool, `
		SELECT m.name || '.' || fk."from" || ' -> ' || fk."table"
		FROM sqlite_schema AS m, pragma_foreign_key_list(m.name) AS fk
		WHERE m.type = 'table'`)
	require.NotEmpty(t, fks, "matches-zero guard: the catalog reports no foreign keys at all")
	return fks
}

// Naming the parent is the point. A link pointing at a plausible but
// wrong table still refuses orphans and still looks constrained; only
// the parent name catches that it enforces the wrong relationship.
// device_assigned_groups.group_id is a USER group — assigning a device
// hands it to people — while device_group_members is device membership.
var requiredForeignKeys = []string{
	"device_group_members.group_id -> device_groups",
	"device_group_members.device_id -> devices",
	"device_assigned_groups.device_id -> devices",
	"device_assigned_groups.group_id -> user_groups",
	"device_assigned_users.device_id -> devices",
	"device_assigned_users.user_id -> users",
	"user_group_members.group_id -> user_groups",
	"user_group_members.user_id -> users",

	"device_inventory.device_id -> devices",
	"osquery_results.device_id -> devices",
	"log_query_results.device_id -> devices",
	"security_alerts.device_id -> devices",
	"terminal_sessions.device_id -> devices",
	"terminal_sessions.user_id -> users",
	"user_selections.device_id -> devices",
	"executions.device_id -> devices",
	"executions.action_id -> actions",
	"device_labels.device_id -> devices",
	"devices.registration_token_id -> tokens",
	"deliveries.device_id -> devices",

	"lps_passwords.device_id -> devices",
	"lps_passwords.action_id -> actions",
	"luks_keys.device_id -> devices",
	"luks_keys.action_id -> actions",
	"luks_tokens.device_id -> devices",
	"luks_tokens.action_id -> actions",

	"action_set_members.set_id -> action_sets",
	"action_set_members.action_id -> actions",
	"definition_members.definition_id -> definitions",
	"definition_members.action_set_id -> action_sets",

	"compliance_policy_rules.policy_id -> compliance_policies",
	"compliance_policy_rules.action_id -> actions",
	"compliance_policy_evaluation.device_id -> devices",
	"compliance_policy_evaluation.policy_id -> compliance_policies",
	"compliance_policy_evaluation.action_id -> actions",
	"compliance_results.device_id -> devices",
	"compliance_results.action_id -> actions",

	"user_roles.user_id -> users",
	"user_roles.role_id -> roles",
	"user_group_roles.group_id -> user_groups",
	"user_group_roles.role_id -> roles",
	"user_ssh_keys.user_id -> users",
	"tokens.owner_id -> users",
	"identity_links.user_id -> users",
	"identity_links.provider_id -> identity_providers",
	"scim_group_mapping.provider_id -> identity_providers",
	"scim_group_mapping.user_group_id -> user_groups",
	"auth_states.provider_id -> identity_providers",
}

func TestForeignKeys_EveryDomainLinkIsDeclared(t *testing.T) {
	_, pool := setupSQLite(t)

	require.NotEmpty(t, requiredForeignKeys, "matches-zero guard: the required-link list is empty")
	declared := declaredForeignKeys(t, pool)

	for _, want := range requiredForeignKeys {
		assert.Contains(t, declared, want, "%s is not enforced by the database", want)
	}
}

// References that stay unconstrained on purpose, each for a reason a
// well-meaning future change would undo.
var unconstrainedReferences = map[string]string{
	"deliveries.operation_id": "the audit log is evidence, not state: retention must never be blocked by a delivery",

	"assignments.source_id":     "polymorphic: the parent table is chosen by a sibling column",
	"assignments.target_id":     "polymorphic: the parent table is chosen by a sibling column",
	"user_selections.source_id": "polymorphic: the parent table is chosen by a sibling column",

	"user_groups.dynamic_query":   "a query, not a reference",
	"device_groups.dynamic_query": "a query, not a reference",

	"executions.created_by_id":        "historical actor: constraining it would rewrite what happened",
	"security_alerts.acknowledged_by": "historical actor: constraining it would rewrite what happened",
	"terminal_sessions.terminated_by": "historical actor: constraining it would rewrite what happened",
	"user_roles.assigned_by":          "historical actor: constraining it would rewrite what happened",
	"user_group_members.added_by":     "historical actor: constraining it would rewrite what happened",
	"roles.created_by":                "historical actor: constraining it would rewrite what happened",
}

func TestForeignKeys_ExcludedReferencesStayUnconstrained(t *testing.T) {
	_, pool := setupSQLite(t)

	require.NotEmpty(t, unconstrainedReferences, "matches-zero guard: the excluded-reference list is empty")

	// "table.column -> parent"; the link identity is the left side.
	constrained := map[string]bool{}
	for _, fk := range declaredForeignKeys(t, pool) {
		ref, _, found := strings.Cut(fk, " -> ")
		require.True(t, found, "unexpected foreign-key rendering: %q", fk)
		constrained[ref] = true
	}

	for ref, why := range unconstrainedReferences {
		assert.False(t, constrained[ref], "%s must stay unconstrained: %s", ref, why)
	}
}

// Representative orphans, one per relationship shape: durable work for
// an unknown device, membership in an unknown group, stored key
// material for an unknown device, and a grant naming an unknown subject
// or role. Each insert supplies real values for every parent except the
// one under test, so the constraint that fires is unambiguous.
func TestForeignKeys_RejectOrphanRows(t *testing.T) {
	_, pool := setupSQLite(t)

	deviceID := newID()
	exec(t, pool, `INSERT INTO devices (id, hostname, agent_sealing_public_key)
		VALUES ($1, 'orphan.example.test', $2)`, deviceID, make([]byte, 32))
	actionID := newID()
	exec(t, pool, `INSERT INTO actions (id, name, action_type) VALUES ($1, 'rotate', 1)`, actionID)
	user := seedUser(t, pool)
	role := seedRole(t, pool)

	t.Run("delivery for an unknown device", func(t *testing.T) {
		err := execFails(t, pool, `INSERT INTO deliveries
			(delivery_id, device_id, manifest_id, manifest, state)
			VALUES ($1, $2, $3, '{}', 'PENDING')`, newID(), newID(), newID())
		assert.Contains(t, err.Error(), "FOREIGN KEY constraint failed")
	})

	t.Run("membership in an unknown group", func(t *testing.T) {
		err := execFails(t, pool,
			`INSERT INTO device_group_members (group_id, device_id) VALUES ($1, $2)`,
			newID(), deviceID)
		assert.Contains(t, err.Error(), "FOREIGN KEY constraint failed")
	})

	t.Run("key material for an unknown device", func(t *testing.T) {
		err := execFails(t, pool, `INSERT INTO luks_keys
			(id, device_id, action_id, device_path, passphrase, rotated_at)
			VALUES ($1, $2, $3, '/dev/sda1', 'enc:v1:ciphertext', CURRENT_TIMESTAMP)`, newID(), newID(), actionID)
		assert.Contains(t, err.Error(), "FOREIGN KEY constraint failed")
	})

	t.Run("grant to an unknown subject", func(t *testing.T) {
		err := execFails(t, pool,
			`INSERT INTO user_roles (grant_id, user_id, role_id) VALUES ($1, $2, $3)`,
			newID(), newID(), role)
		assert.Contains(t, err.Error(), "FOREIGN KEY constraint failed")
	})

	t.Run("grant of an unknown role", func(t *testing.T) {
		err := execFails(t, pool,
			`INSERT INTO user_roles (grant_id, user_id, role_id) VALUES ($1, $2, $3)`,
			newID(), user, newID())
		assert.Contains(t, err.Error(), "FOREIGN KEY constraint failed")
	})
}
