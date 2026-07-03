package store_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// This file is part C of the #495 guard family: TOTAL classification of the
// live Postgres schema. The contract (ADR 0028 amendment): all Postgres state
// is event-sourced (a projection replay reproduces it) or explicitly
// classified — operational-by-design or a tracked replay gap. A new table
// that is none of these fails here, so divergence from the event-sourcing
// contract is unmergeable rather than grep-dependent.
//
// Classification precedence (first match wins; registries below must not
// shadow an earlier rule — the stale/overlap checks enforce it):
//
//  1. the event store itself + goose bookkeeping;
//  2. explicit rebuild-target tables (store.AllRebuildTargets — replay
//     reproduces them, proven by the rebuild round-trip tests);
//  3. cascadeRederivedTables — wiped transitively by a CASCADE rebuild
//     TRUNCATE (mechanically cross-checked against the live FK graph) and
//     re-derived by the replayed streams / reconcilers named per entry;
//  4. operationalTables — by-design non-event-sourced operational state,
//     each entry carrying its why-it-lives-in-Postgres;
//  5. knownUnreplayableTables — HONEST GAPS: projections of event streams
//     that no rebuild target replays (tracked per entry; fixing one forces
//     its removal here via the overlap check when a target is added).

// operationalTables is registry 4: by-design non-event-sourced operational
// state. Ephemeral or primary-operational; a replay neither wipes nor needs
// to reproduce them (no rebuild target touches them).
var operationalTables = map[string]string{
	"auth_states":       "short-lived OIDC flow rows (state/nonce/PKCE), consumed on first read; in PG so ANY control replica can complete the callback (no sticky sessions); loss = user redoes login",
	"revoked_tokens":    "JWT refresh-token denylist, TTL-bounded by token expiry; primary operational security state — becomes a projection once #496 adds logout/refresh events",
	"luks_tokens":       "hashed one-time LUKS enrollment tokens (WS10); single-use by design, loss = operator re-issues; deliberately not replayable",
	"osquery_results":   "transient result staging for DispatchOSQuery — agent reply fills, reads expire; loss = re-run the query",
	"log_query_results": "transient result staging for QueryDeviceLogs — same lifecycle as osquery_results",
	"terminal_sessions": "live-session inventory; the audit trail is the TerminalSession* events, the row is liveness state reconciled against the gateway",
	"device_inventory":  "agent-reported osquery snapshot cache; the device is the source of truth, RefreshDeviceInventory re-populates",
}

// cascadeRederivedTables is registry 3. Every entry is mechanically verified
// to sit in the FK closure of a Cascade rebuild target (so a rebuild DOES
// wipe it); the value documents what re-derives its content afterwards.
var cascadeRederivedTables = map[string]string{
	"device_labels":                       "CASCADE child of devices_projection; re-derived by DeviceLabelSet/Removed/LabelsUpdated replay (ApplyDevice)",
	"user_ssh_keys":                       "CASCADE child of users_projection; re-derived by UserSshKeyAdded/Removed replay (ApplyUser)",
	"user_group_members_projection":       "CASCADE child of user_groups_projection; re-derived by UserGroupMemberAdded/Removed/MembersRebuilt replay (ApplyUserGroup)",
	"user_group_roles_projection":         "CASCADE child of user_groups_projection; re-derived by UserGroupRoleAssigned/Revoked replay (ApplyUserGroup)",
	"dynamic_user_group_evaluation_queue": "CASCADE child of user_groups_projection; transient work queue re-populated by UserGroupQueryUpdated replay and the periodic dynamic-group evaluator",
}

// knownUnreplayableTables is registry 5: tables whose content comes from the
// event stream but which NO rebuild target replays — replay-coverage gaps,
// not sanctioned designs (#497). Each fix (adding the rebuild target) makes
// the overlap check above fail until the entry is removed.
var knownUnreplayableTables = map[string]string{
	"user_roles_projection":                   "#497 — grants ride the user_role stream, which no target replays; a replay into an empty schema loses every post-creation grant (no FK, so an in-place rebuild merely leaves the rows untouched)",
	"server_settings_projection":              "#497 — ServerSettingUpdated has a listener but no rebuild target (singleton seeded by migration)",
	"totp_projection":                         "#497 — FK child of users_projection: a users rebuild CASCADE-WIPES all TOTP enrollments and nothing replays the totp stream",
	"security_alerts_projection":              "#497 — security_alert stream has a listener but no rebuild target",
	"lps_passwords_projection":                "#497 — no target replays the lps_password stream; a replay into an empty schema loses the (encrypted) password history the events carry",
	"luks_keys_projection":                    "#497 — same exposure as lps_passwords_projection for the luks_key stream",
	"identity_providers_projection":           "#497 — identity_provider stream has a listener but no rebuild target",
	"identity_links_projection":               "#497 — FK child of users_projection: a users rebuild CASCADE-WIPES all SSO identity links and nothing replays the identity_link stream",
	"compliance_policies_projection":          "#497 — ApplyCompliancePolicy exists but is not registered for rebuild",
	"compliance_policy_rules_projection":      "#497 — ApplyCompliancePolicy exists but is not registered for rebuild",
	"compliance_policy_evaluation_projection": "#497 — compliance evaluation stream not replayed by any target",
	"compliance_results_projection":           "#497 — ApplyCompliance exists but is not registered for rebuild",
}

// TestSchemaTotallyClassified enumerates every base table in the live test
// schema and forces it into exactly one classification. Includes its own
// red-phase (AC4): a probe table is created and must be flagged before the
// real assertion runs, proving the discovery cannot pass vacuously.
func TestSchemaTotallyClassified(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	tables := listBaseTables(t, ctx, st)
	require.Greater(t, len(tables), 30,
		"expected the full schema (>30 tables), got %d — discovery is broken", len(tables))

	explicit := map[string]bool{}
	cascadeSeeds := []string{}
	for _, target := range store.AllRebuildTargets {
		for _, tbl := range target.Tables {
			explicit[tbl] = true
			if target.Cascade {
				cascadeSeeds = append(cascadeSeeds, tbl)
			}
		}
	}
	require.NotEmpty(t, explicit, "AllRebuildTargets yielded zero tables — discovery is broken")

	closure := fkCascadeClosure(t, ctx, st, cascadeSeeds)

	// Registry hygiene: every entry names a live table; no entry shadows an
	// earlier classification rule.
	for tbl := range operationalTables {
		require.Containsf(t, tables, tbl, "operationalTables names %q but no such table — stale entry", tbl)
		require.Falsef(t, explicit[tbl], "%q is a rebuild-target table — remove it from operationalTables", tbl)
	}
	for tbl := range cascadeRederivedTables {
		require.Containsf(t, tables, tbl, "cascadeRederivedTables names %q but no such table — stale entry", tbl)
		require.Falsef(t, explicit[tbl], "%q is an explicit rebuild-target table — remove it from cascadeRederivedTables", tbl)
		require.Truef(t, closure[tbl],
			"%q is registered as cascade-rederived but is NOT in the FK closure of any Cascade rebuild target — a rebuild would not wipe it; reclassify it", tbl)
	}
	for tbl := range knownUnreplayableTables {
		require.Containsf(t, tables, tbl, "knownUnreplayableTables names %q but no such table — stale entry", tbl)
		require.Falsef(t, explicit[tbl],
			"%q now has a rebuild target — the replay gap is closed, remove it from knownUnreplayableTables", tbl)
	}

	classify := func(tbl string) string {
		switch {
		case tbl == "events":
			return "event store"
		case tbl == "goose_db_version":
			return "migration bookkeeping"
		case explicit[tbl]:
			return "rebuild target"
		case cascadeRederivedTables[tbl] != "":
			return "cascade-rederived"
		case operationalTables[tbl] != "":
			return "operational"
		case knownUnreplayableTables[tbl] != "":
			return "known gap"
		}
		return ""
	}

	// Red phase (AC4): an unclassified probe table MUST be flagged, or the
	// discovery is broken and the real assertion below would pass vacuously.
	const probe = "zz_495_unclassified_probe"
	_, err := st.TestingPool().Exec(ctx, "CREATE TABLE "+probe+" (id INT)")
	require.NoError(t, err)
	probeTables := listBaseTables(t, ctx, st)
	require.Contains(t, probeTables, probe, "probe table must be discovered")
	require.Empty(t, classify(probe), "probe table must be UNclassified — the guard would never fire")
	_, err = st.TestingPool().Exec(ctx, "DROP TABLE "+probe)
	require.NoError(t, err)

	var unclassified []string
	for _, tbl := range tables {
		if classify(tbl) == "" {
			unclassified = append(unclassified, tbl)
		}
	}
	sort.Strings(unclassified)
	require.Emptyf(t, unclassified,
		"tables violating the #495 total-classification contract (all Postgres state is event-sourced or explicitly classified):\n  %s\n"+
			"Each must become a projection with a rebuild target, or be justified in cascadeRederivedTables / operationalTables, "+
			"or be tracked as a replay gap in knownUnreplayableTables.",
		strings.Join(unclassified, "\n  "))
}

// listBaseTables enumerates public base tables from the live schema.
func listBaseTables(t *testing.T, ctx context.Context, st *store.Store) []string {
	t.Helper()
	rows, err := st.TestingPool().Query(ctx,
		`SELECT table_name FROM information_schema.tables
		 WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`)
	require.NoError(t, err)
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		tables = append(tables, name)
	}
	require.NoError(t, rows.Err())
	return tables
}

// fkCascadeClosure computes the set of tables a `TRUNCATE <seeds> CASCADE`
// would wipe: seeds plus, transitively, every table holding a foreign key
// that references a table already in the closure — read from the live FK
// graph so the guard tracks schema reality, not a hand-list.
func fkCascadeClosure(t *testing.T, ctx context.Context, st *store.Store, seeds []string) map[string]bool {
	t.Helper()
	rows, err := st.TestingPool().Query(ctx, `
		SELECT DISTINCT child.relname AS child_table, parent.relname AS parent_table
		FROM pg_constraint c
		JOIN pg_class child  ON child.oid  = c.conrelid
		JOIN pg_class parent ON parent.oid = c.confrelid
		JOIN pg_namespace n  ON n.oid = child.relnamespace
		WHERE c.contype = 'f' AND n.nspname = 'public'`)
	require.NoError(t, err)
	defer rows.Close()
	childrenOf := map[string][]string{}
	for rows.Next() {
		var child, parent string
		require.NoError(t, rows.Scan(&child, &parent))
		childrenOf[parent] = append(childrenOf[parent], child)
	}
	require.NoError(t, rows.Err())

	closure := map[string]bool{}
	queue := append([]string(nil), seeds...)
	for len(queue) > 0 {
		tbl := queue[0]
		queue = queue[1:]
		if closure[tbl] {
			continue
		}
		closure[tbl] = true
		queue = append(queue, childrenOf[tbl]...)
	}
	return closure
}
