package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
)

func TestSQLiteSearch_CoversEveryFacetWithPrefixAndCurrentJoins(t *testing.T) {
	st, raw := setupSQLite(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	actionID, actionSS, setID, definitionID, policyID := newID(), newID(), newID(), newID(), newID()
	deviceID, deviceGroupID := newID(), newID()
	userID, roleID, grantID, userGroupID := newID(), newID(), newID(), newID()
	executionID := newID()
	deliveryID := newID()

	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO actions (id, name, description, action_type, params, created_at, updated_at) VALUES
			($1, 'Straßenprüfung München', 'DACH baseline', 100, '{}', $3, $3),
			($2, 'Strassenprüfung Berlin', 'ss remains distinct', 100, '{}', $3, $3)`, []any{actionID, actionSS, now}},
		{`INSERT INTO action_sets (id, name, description, created_at, updated_at)
			VALUES ($1, 'Workstation baseline', 'member names are searchable', $2, $2)`, []any{setID, now}},
		{`INSERT INTO action_set_members (set_id, action_id, sort_order, added_at) VALUES ($1, $2, 0, $3)`, []any{setID, actionID, now}},
		{`INSERT INTO definitions (id, name, description, created_at, updated_at)
			VALUES ($1, 'Munich definition', 'set and action names are searchable', $2, $2)`, []any{definitionID, now}},
		{`INSERT INTO definition_members (definition_id, action_set_id, sort_order, added_at) VALUES ($1, $2, 0, $3)`, []any{definitionID, setID, now}},
		{`INSERT INTO compliance_policies (id, name, description, created_at)
			VALUES ($1, 'Street compliance', 'rule action names are searchable', $2)`, []any{policyID, now}},
		{`INSERT INTO compliance_policy_rules (policy_id, action_id, action_name, added_at)
			VALUES ($1, $2, 'Straßenprüfung München', $3)`, []any{policyID, actionID, now}},
		{`INSERT INTO devices (id, hostname, agent_version, agent_sealing_public_key, registered_at, last_seen_at)
			VALUES ($1, 'db-01.eu.example', '2.4.0', zeroblob(32), $2, $2)`, []any{deviceID, now}},
		{`INSERT INTO deliveries
			(delivery_id, device_id, manifest_id, manifest, state, created_at, available_at)
			VALUES ($1, $2, $3, '{}', 'PENDING', $4, $4)`, []any{deliveryID, deviceID, newID(), now}},
		{`INSERT INTO device_labels (device_id, key, value) VALUES ($1, 'environment', 'production')`, []any{deviceID}},
		{`INSERT INTO device_inventory (device_id, table_name, rows, collected_at)
			VALUES ($1, 'os_version', '[{"name":"Ubuntu","version":"26.04","arch":"amd64"}]', $2)`, []any{deviceID, now}},
		{`INSERT INTO device_inventory (device_id, table_name, rows, collected_at)
			VALUES ($1, 'system_info', '[{"cpu_brand":"PhoenixTechnologies"}]', $2)`, []any{deviceID, now}},
		{`INSERT INTO device_groups (id, name, description, created_at) VALUES ($1, 'München devices', 'DACH fleet', $2)`, []any{deviceGroupID, now}},
		{`INSERT INTO device_group_members (group_id, device_id, added_at) VALUES ($1, $2, $3)`, []any{deviceGroupID, deviceID, now}},
		{`INSERT INTO users (id, email, display_name, given_name, linux_username, linux_uid, created_at, updated_at)
			VALUES ($1, 'ops@example.test', 'Night Operator', 'Annalena', 'night-operator', 210001, $2, $2)`, []any{userID, now}},
		{`INSERT INTO roles (id, name, description, created_at) VALUES ($1, 'Fleet Observer', 'read only', $2)`, []any{roleID, now}},
		{`INSERT INTO user_roles (grant_id, user_id, role_id, assigned_at) VALUES ($1, $2, $3, $4)`, []any{grantID, userID, roleID, now}},
		{`INSERT INTO user_groups (id, name, description, created_at, updated_at) VALUES ($1, 'München operators', 'night shift', $2, $2)`, []any{userGroupID, now}},
		{`INSERT INTO user_group_members (group_id, user_id, added_at) VALUES ($1, $2, $3)`, []any{userGroupID, userID, now}},
		{`INSERT INTO executions (id, delivery_id, device_id, action_id, action_type, desired_state, params, timeout_seconds, status, created_at)
			VALUES ($1, $2, $3, $4, 100, 1, '{}', 90, 'pending', $5)`, []any{executionID, deliveryID, deviceID, actionID, now}},
	}
	for _, statement := range statements {
		_, err := raw.Exec(ctx, statement.query, statement.args...)
		require.NoError(t, err)
	}

	_, err := raw.Exec(ctx, `
		INSERT INTO assignments
			(id, source_type, source_id, target_type, target_id, mode, created_at, created_by)
		VALUES ($1, 'action', $2, 'device_group', $3, 0, $10, $11),
		       ($4, 'action_set', $5, 'device_group', $3, 0, $10, $11),
		       ($6, 'definition', $7, 'device_group', $3, 0, $10, $11),
		       ($8, 'compliance_policy', $9, 'device_group', $3, 0, $10, $11)`,
		newID(), actionID, deviceGroupID, newID(), setID, newID(), definitionID,
		newID(), policyID, now, userID)
	require.NoError(t, err)
	rebuildSearchFixture(t, st)

	auditRecord, err := st.RecordOperation(ctx, store.AuditOperation{
		Class: store.ClassMutation, ActorType: "user", ActorID: userID,
		Origin: "control_rpc", RequestDescriptor: "/powermanage.v1.ControlService/DispatchAction",
		AuthorizationOutcome: store.AuthorizationAllowed, AuthorizationDetail: "DispatchAction",
		Result: store.ResultSuccess, ResultCode: "OK",
	}, store.AuditEffect{
		ResourceType: "action", ResourceID: actionID, Action: "DISPATCH", Outcome: store.EffectApplied,
	})
	require.NoError(t, err)
	var auditOccurredAt time.Time
	require.NoError(t, raw.QueryRow(ctx,
		`SELECT occurred_at FROM audit_operations WHERE operation_id = $1`, auditRecord.OperationID,
	).Scan(&auditOccurredAt))

	search := func(scope, query string) []store.SearchRow {
		t.Helper()
		rows, total, err := st.Search(ctx, store.SearchParams{
			Scope: scope, Query: query, Limit: 50, OnlineSince: now.Add(-5 * time.Minute),
		})
		require.NoError(t, err, scope)
		assert.Equal(t, int64(len(rows)), total, scope)
		return rows
	}

	require.Len(t, search("actions", "Straße"), 1, "ß and ss retain their existing distinct lexemes")
	require.Len(t, search("actions", "Strasse"), 1)
	require.Len(t, search("actions", "M"), 1, "one-character prefixes are searchable")
	setRow := requireOneSearchRow(t, search("action_sets", "Straße"))
	assert.Equal(t, setID, setRow.ID)
	assert.Contains(t, setRow.Fields["action_names"], "Straßenprüfung")
	definitionRow := requireOneSearchRow(t, search("definitions", "Straße"))
	assert.Equal(t, definitionID, definitionRow.ID)
	assert.Contains(t, definitionRow.Fields["set_names"], "Workstation baseline")
	policyRow := requireOneSearchRow(t, search("compliance_policies", "Straße"))
	assert.Equal(t, policyID, policyRow.ID)
	assert.Contains(t, policyRow.Fields["action_names"], "Straßenprüfung")
	deviceRow := requireOneSearchRow(t, search("devices", "Ubuntu"))
	assert.Equal(t, deviceID, deviceRow.ID)
	assert.Equal(t, "environment=production", deviceRow.Fields["labels"])
	assert.Equal(t, deviceID, requireOneSearchRow(t, search("devices", "db-01")).ID)
	assert.Equal(t, userID, requireOneSearchRow(t, search("users", "Fleet")).ID)
	assert.Equal(t, deviceGroupID, requireOneSearchRow(t, search("device_groups", "Mün")).ID)
	assert.Equal(t, userGroupID, requireOneSearchRow(t, search("user_groups", "Mün")).ID)
	executionRow := requireOneSearchRow(t, search("executions", "Straße"))
	assert.Equal(t, executionID, executionRow.ID)
	assert.Equal(t, actionID, executionRow.Fields["action_id"])
	auditRow := requireOneSearchRow(t, search("audit_events", "DispatchAction"))
	assert.Equal(t, actionID, auditRow.Fields["stream_id"])
	assert.Equal(t, userID, requireOneSearchRow(t, search("users", "ops@example")).ID)
	assert.Equal(t, deviceID, requireOneSearchRow(t, search("devices", deviceID[:8])).ID)
	assert.Equal(t, deviceID, requireOneSearchRow(t, search("devices", "PhoenixTechnlogies")).ID,
		"fuzzy matching includes inventory fields that are not copied into the public result map")
	assert.Empty(t, search("devices", deviceID[:2]+"_"+deviceID[3:8]), "LIKE metacharacters in an ID prefix are literals")
	assert.Equal(t, userID, requireOneSearchRow(t, search("users", "Annalna")).ID,
		"fuzzy matching includes profile fields that are not copied into the public result map")
	assert.Equal(t, setID, requireOneSearchRow(t, search("action_sets", "basline")).ID)
	assert.Equal(t, definitionID, requireOneSearchRow(t, search("definitions", "basline")).ID)
	assert.Equal(t, policyID, requireOneSearchRow(t, search("compliance_policies", "basline")).ID)
	assert.Equal(t, actionID, requireOneSearchRow(t, search("audit_events", "contorl_rpc")).Fields["stream_id"],
		"fuzzy matching includes private audit operation metadata")

	filterCases := []struct {
		scope, field string
		values       []string
		want         int64
	}{
		{"actions", "type", []string{"100"}, 2},
		{"actions", "is_compliance", []string{"true"}, 1},
		{"actions", "is_compliance", []string{"false"}, 1},
		{"actions", "assigned", []string{"true"}, 1},
		{"action_sets", "member_count", []string{"1"}, 1},
		{"action_sets", "assigned", []string{"true"}, 1},
		{"definitions", "member_count", []string{"1"}, 1},
		{"definitions", "assigned", []string{"true"}, 1},
		{"compliance_policies", "rule_count", []string{"1"}, 1},
		{"devices", "agent_version", []string{"2.4.0"}, 1},
		{"devices", "os_name", []string{"Ubuntu"}, 1},
		{"devices", "os_arch", []string{"amd64"}, 1},
		{"devices", "compliance_status", []string{"0"}, 1},
		{"devices", "status", []string{"online"}, 1},
		{"users", "disabled", []string{"false"}, 1},
		{"users", "role", []string{"Fleet Observer"}, 1},
		{"device_groups", "is_dynamic", []string{"false"}, 1},
		{"device_groups", "member_count", []string{"1"}, 1},
		{"user_groups", "is_dynamic", []string{"false"}, 1},
		{"user_groups", "member_count", []string{"1"}, 1},
		{"executions", "status", []string{"pending"}, 1},
		{"executions", "action_type", []string{"100"}, 1},
		{"executions", "device_id", []string{deviceID}, 1},
		{"audit_events", "stream_type", []string{"action"}, 1},
		{"audit_events", "actor_type", []string{"user"}, 1},
		{"audit_events", "actor_id", []string{userID}, 1},
	}
	for _, tc := range filterCases {
		rows, total, err := st.Search(ctx, store.SearchParams{
			Scope: tc.scope, Limit: 50, OnlineSince: now.Add(-5 * time.Minute),
			TagFilters: map[string][]string{tc.field: tc.values},
		})
		require.NoErrorf(t, err, "%s filter %s", tc.scope, tc.field)
		assert.Equalf(t, tc.want, total, "%s filter %s", tc.scope, tc.field)
		assert.Lenf(t, rows, int(tc.want), "%s filter %s", tc.scope, tc.field)
	}

	sortCases := map[string][]string{
		"actions":             {"name", "type", "created_at", "updated_at"},
		"action_sets":         {"name", "member_count", "created_at", "updated_at"},
		"definitions":         {"name", "member_count", "created_at", "updated_at"},
		"compliance_policies": {"name", "rule_count", "created_at"},
		"devices":             {"hostname", "compliance_status", "registered_at", "last_seen_at"},
		"users":               {"email", "display_name", "disabled", "last_login_at", "created_at"},
		"device_groups":       {"name", "member_count", "created_at"},
		"user_groups":         {"name", "member_count", "created_at"},
		"executions":          {"device_hostname", "status", "action_type", "created_at"},
		"audit_events":        {"event_type", "stream_type", "actor_type", "occurred_at"},
	}
	for scope, fields := range sortCases {
		for _, field := range fields {
			_, _, err := st.Search(ctx, store.SearchParams{Scope: scope, Limit: 50, SortField: field})
			require.NoErrorf(t, err, "%s sort %s", scope, field)
		}
	}

	dateCases := map[string][]string{
		"actions": {"created_at", "updated_at"}, "action_sets": {"created_at", "updated_at"},
		"definitions": {"created_at", "updated_at"}, "compliance_policies": {"created_at"},
		"devices": {"registered_at", "last_seen_at"}, "users": {"created_at"},
		"device_groups": {"created_at"}, "user_groups": {"created_at"},
		"executions": {"created_at"}, "audit_events": {"occurred_at"},
	}
	for scope, fields := range dateCases {
		for _, field := range fields {
			center := now
			if scope == "audit_events" {
				center = auditOccurredAt
			}
			_, total, err := st.Search(ctx, store.SearchParams{
				Scope: scope, Limit: 50,
				DateRanges: []store.SearchDateRange{{Field: field, Start: center.Add(-24 * time.Hour).Unix(), End: center.Add(24 * time.Hour).Unix()}},
			})
			require.NoErrorf(t, err, "%s date %s", scope, field)
			assert.Positivef(t, total, "%s date %s", scope, field)
		}
	}

	scopeCases := []struct {
		scope string
		group string
	}{
		{"actions", deviceGroupID}, {"action_sets", deviceGroupID}, {"definitions", deviceGroupID},
		{"compliance_policies", deviceGroupID}, {"devices", deviceGroupID}, {"device_groups", deviceGroupID},
		{"users", userGroupID}, {"user_groups", userGroupID}, {"executions", deviceGroupID},
	}
	for _, tc := range scopeCases {
		_, total, err := st.Search(ctx, store.SearchParams{
			Scope: tc.scope, Limit: 50, ScopeRestricted: true, ScopeGroupIDs: []string{tc.group},
		})
		require.NoError(t, err, tc.scope)
		assert.Positive(t, total, tc.scope)
	}
}

func TestSQLiteSearch_FiltersScopesSortsAndPagesDeterministically(t *testing.T) {
	st, raw := setupSQLite(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	groupID := newID()
	_, err := raw.Exec(ctx, `INSERT INTO device_groups (id, name, created_at) VALUES ($1, 'scope', $2)`, groupID, now)
	require.NoError(t, err)

	ids := []string{newID(), newID(), newID()}
	for i, name := range []string{"Pager Charlie", "Pager Alpha", "Pager Bravo"} {
		_, err := raw.Exec(ctx, `INSERT INTO actions
			(id, name, action_type, params, created_at, updated_at)
			VALUES ($1, $2, 100, '{}', $3, $3)`, ids[i], name, now.Add(time.Duration(i)*time.Minute))
		require.NoError(t, err)
	}
	_, err = raw.Exec(ctx, `INSERT INTO assignments
		(id, source_type, source_id, target_type, target_id, mode, created_at, created_by)
		VALUES ($1, 'action', $2, 'device_group', $3, 0, $4, $5)`, newID(), ids[0], groupID, now, newID())
	require.NoError(t, err)
	rebuildSearchFixture(t, st)

	page, total, err := st.Search(ctx, store.SearchParams{
		Scope: "actions", Query: "Pager", Limit: 2, SortField: "name",
	})
	require.NoError(t, err)
	require.Len(t, page, 2)
	assert.Equal(t, int64(3), total)
	assert.Equal(t, []string{"Pager Alpha", "Pager Bravo"}, []string{page[0].Name, page[1].Name})

	last, total, err := st.Search(ctx, store.SearchParams{
		Scope: "actions", Query: "Pager", Offset: 2, Limit: 2, SortField: "name",
	})
	require.NoError(t, err)
	require.Len(t, last, 1)
	assert.Equal(t, int64(3), total)
	assert.Equal(t, "Pager Charlie", last[0].Name)

	restricted, total, err := st.Search(ctx, store.SearchParams{
		Scope: "actions", Query: "Pager", Limit: 50,
		ScopeRestricted: true, ScopeGroupIDs: []string{groupID},
		TagFilters: map[string][]string{"assigned": {"true"}},
	})
	require.NoError(t, err)
	require.Len(t, restricted, 1)
	assert.Equal(t, ids[0], restricted[0].ID)
	assert.Equal(t, int64(1), total)

	_, _, err = st.Search(ctx, store.SearchParams{
		Scope: "actions", Limit: 50, TagFilters: map[string][]string{"status": {"pending"}},
	})
	assert.ErrorIs(t, err, store.ErrInvalidSearch)
}

func TestSQLiteSearch_RebuildRemovesErasedPII(t *testing.T) {
	st, raw := setupSQLite(t)
	ctx := context.Background()
	id := newID()
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	_, err := raw.Exec(ctx, `INSERT INTO users
		(id, email, display_name, given_name, family_name, preferred_username, linux_username, linux_uid, created_at, updated_at)
		VALUES ($1, 'erasable@example.test', 'Erasable Person', 'Erasable', 'Person', 'erasable', 'erasable', 210001, $2, $2)`, id, now)
	require.NoError(t, err)
	rebuildSearchFixture(t, st)

	rows, total, err := st.Search(ctx, store.SearchParams{Scope: "users", Query: "erasable", Limit: 50})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, int64(1), total)

	_, err = raw.Exec(ctx, `UPDATE users SET
		email = $2, display_name = '', given_name = '', family_name = '', preferred_username = '',
		linux_username = '', is_deleted = TRUE, updated_at = $3 WHERE id = $1`, id, "erased-"+id+"@invalid", now)
	require.NoError(t, err)
	rebuildSearchFixture(t, st)

	rows, total, err = st.Search(ctx, store.SearchParams{Scope: "users", Query: "erasable", Limit: 50})
	require.NoError(t, err)
	assert.Empty(t, rows)
	assert.Zero(t, total)
	var retainsPII bool
	err = raw.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM search_documents d JOIN search_fts f ON f.rowid = d.rowid
		WHERE d.scope = 'users' AND d.entity_id = $1 AND search_fts MATCH 'erasable*'
	)`, id).Scan(&retainsPII)
	require.NoError(t, err)
	assert.False(t, retainsPII, "rebuilding derived documents cannot restore erased PII")
}

func TestSQLiteSearch_CombinesPrefixAndFuzzyResultsDeterministically(t *testing.T) {
	st, raw := setupSQLite(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	exactID, primaryID, descriptionID := newID(), newID(), newID()

	_, err := raw.Exec(ctx, `INSERT INTO actions
		(id, name, description, action_type, params, created_at, updated_at) VALUES
		($1, 'Workstation exact', '', 100, '{}', $4, $4),
		($2, 'Workstaiton primary', '', 100, '{}', $4, $4),
		($3, 'Secondary field', 'workstaiton recovery', 100, '{}', $4, $4)`,
		exactID, primaryID, descriptionID, now)
	require.NoError(t, err)
	rebuildSearchFixture(t, st)

	first, total, err := st.Search(ctx, store.SearchParams{
		Scope: "actions", Query: "workstation", Limit: 2, SortField: "name",
	})
	require.NoError(t, err)
	require.Equal(t, int64(3), total)
	require.Len(t, first, 2)
	assert.Equal(t, exactID, first[0].ID, "ordinary prefix hits always precede fuzzy-only hits")
	assert.Equal(t, primaryID, first[1].ID, "a primary-field typo ranks ahead of the same typo in a description")

	second, total, err := st.Search(ctx, store.SearchParams{
		Scope: "actions", Query: "workstation", Offset: 2, Limit: 2, SortField: "name",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(3), total)
	require.Len(t, second, 1)
	assert.Equal(t, descriptionID, second[0].ID)
}

func TestSQLiteSearch_FuzzyRequiresEveryTokenAndFourCharacterMinimum(t *testing.T) {
	st, raw := setupSQLite(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	id := newID()
	_, err := raw.Exec(ctx, `INSERT INTO actions
		(id, name, description, action_type, params, created_at, updated_at)
		VALUES ($1, 'Münchn abc baseline', '', 100, '{}', $2, $2)`, id, now)
	require.NoError(t, err)
	rebuildSearchFixture(t, st)

	rows, total, err := st.Search(ctx, store.SearchParams{Scope: "actions", Query: "münchen", Limit: 50})
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Len(t, rows, 1)
	assert.Equal(t, id, rows[0].ID)

	rows, total, err = st.Search(ctx, store.SearchParams{Scope: "actions", Query: "münchen secure", Limit: 50})
	require.NoError(t, err)
	assert.Zero(t, total, "one fuzzy token cannot hide a missing query token")
	assert.Empty(t, rows)

	rows, total, err = st.Search(ctx, store.SearchParams{Scope: "actions", Query: "acb", Limit: 50})
	require.NoError(t, err)
	assert.Zero(t, total, "tokens shorter than four characters are prefix-only")
	assert.Empty(t, rows)
}

func TestSQLiteSearch_FuzzyCandidateCorpus(t *testing.T) {
	st, raw := setupSQLite(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name, document, query string
		want                  bool
	}{
		{name: "four-character transposition", document: "abcd", query: "acbd", want: true},
		{name: "two edits at eight characters", document: "abcdefgh", query: "abcxefyh", want: true},
		{name: "DACH umlaut deletion", document: "Server-Härtung München", query: "server härtng", want: true},
		{name: "dotted hostname transposition", document: "db-01.eu.example", query: "db-01.eu.examlpe", want: true},
		{name: "email transposition", document: "ops@example.test", query: "ops@exmaple.test", want: true},
		{name: "short sharp-s spelling remains distinct", document: "Straße", query: "Strasse", want: false},
	}

	ids := make([]string, len(tests))
	for i, tc := range tests {
		ids[i] = newID()
		_, err := raw.Exec(ctx, `INSERT INTO actions
			(id, name, description, action_type, params, created_at, updated_at)
			VALUES ($1, $2, '', 100, '{}', $3, $3)`, ids[i], tc.document, now)
		require.NoError(t, err)
	}
	rebuildSearchFixture(t, st)

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows, _, err := st.Search(ctx, store.SearchParams{Scope: "actions", Query: tc.query, Limit: 50})
			require.NoError(t, err)
			found := false
			for _, row := range rows {
				found = found || row.ID == ids[i]
			}
			assert.Equal(t, tc.want, found)
		})
	}
}

func rebuildSearchFixture(t *testing.T, st *store.Store) {
	t.Helper()
	require.NoError(t, st.RebuildSearchIndexes(context.Background(), store.AuditOperation{
		Class: store.ClassBackgroundWriter, ActorType: "system", Origin: "test_fixture",
		RequestDescriptor: "search.fixture/rebuild", AuthorizationOutcome: store.AuthorizationNotApplicable,
		Result: store.ResultSuccess, ResultCode: "OK",
	}))
}

func requireOneSearchRow(t *testing.T, rows []store.SearchRow) store.SearchRow {
	t.Helper()
	require.Len(t, rows, 1)
	return rows[0]
}
