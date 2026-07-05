// Package store, file rebuild.go — Go-side replacement for the
// rebuild_*_projection() PL/pgSQL family. The PL/pgSQL functions
// retired in migration 015; the per-stream PL/pgSQL projector
// dispatcher itself was dropped in migration 041 once every domain
// projector had been ported to a Go applier under
// internal/projectors/.
//
// The function set this file replaces was operator-only (run via psql
// for emergency rebuild from the event store), not invoked by any
// runtime code path. Moving it to Go gives operators a single
// well-typed entry point and removes ~650 lines of nearly-duplicate
// PL/pgSQL whose only difference between targets was the table name
// and the WHERE filter.
//
// Performance posture: events are loaded into Go in sequence_num
// order and replayed one at a time through the Go applier registered
// for the target via projectors.WireAll -> Store.RegisterRebuildApply.
// The whole rebuild runs inside one transaction so a failed projector
// cannot leave the projection half-replayed against a TRUNCATE'd table.
//
// Refs manchtools/power-manage-server#94, manchtools/power-manage-server#107,
// manchtools/power-manage-server#184 (PL/pgSQL dispatcher dropped).
package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// rebuildBatchSize bounds how many events dispatchViaGoApplier holds in memory
// at once (WS13 #14): the replay is keyset-paginated by sequence_num in batches
// of this size instead of buffering the entire matching event stream. A package
// var (not const) so tests can lower it to exercise the batch boundary cheaply.
var rebuildBatchSize = 1000

// SetRebuildBatchSizeForTest lowers rebuildBatchSize and returns a restore func.
// Test-only seam: the rebuild round-trip lives in package store_test (it needs
// testutil, which imports store), so the batch boundary can't be exercised via
// the unexported var directly.
func SetRebuildBatchSizeForTest(n int) (restore func()) {
	prev := rebuildBatchSize
	rebuildBatchSize = n
	return func() { rebuildBatchSize = prev }
}

// RebuildResult reports per-target outcome of RebuildAll. Operators
// running an emergency replay want to see exactly which projections
// were touched and how many events were replayed for each.
type RebuildResult struct {
	// Targets in the order they ran (canonical AllRebuildTargets
	// order; deterministic for log readability).
	Targets []TargetResult
	// TotalDuration measures wall time across the whole replay,
	// including TRUNCATE + dispatch + commit. Useful for operators
	// gauging when a maintenance window will end.
	TotalDuration time.Duration
}

// TargetResult is the per-target outcome.
type TargetResult struct {
	Name          string
	EventsApplied int64
	// Skipped counts events the applier reported unprojectable via
	// ErrSkipEvent (malformed historical payloads). Surfaced separately
	// from EventsApplied (F-14 / spec 21 AC 7) so an operator can see
	// that N events were NOT reproduced rather than reading a total
	// that silently conflates applied and skipped.
	Skipped  int64
	Duration time.Duration
}

// rebuildTarget is the in-Go replacement for one PL/pgSQL
// rebuild_<X>_projection() function.
//
// Tables are TRUNCATE'd inside the rebuild transaction. CASCADE
// matters for projections whose foreign keys reference other tables
// (users_projection's roles map, devices_projection's group
// memberships, etc.) — without it the TRUNCATE fails. The boolean
// mirrors the original PL/pgSQL function's CASCADE clause
// one-for-one so behaviour is bit-identical.
//
// StreamTypes is the SQL `WHERE stream_type = ANY($1)` filter. Some
// targets reach into multiple stream types because their projector
// applies cross-stream effects (the actions projector handles both
// 'action' and 'definition' events because compliance-policy
// definitions create derived action rows).
//
// Every target dispatches through the Go applier registered for it
// via projectors.WireAll -> Store.RegisterRebuildApply. A target with
// no registered applier is rejected by runOneTarget so an operator
// never silently rebuilds a projection against a no-op dispatcher.
type rebuildTarget struct {
	Name        string
	Tables      []string
	Cascade     bool
	StreamTypes []string
	// SeedSQL re-applies migration-seeded rows after the TRUNCATE and
	// before the replay. Some projection tables carry rows that exist
	// only as migration seeds, not as events (the system roles, the
	// server-settings 'global' row) — without re-seeding, a rebuild
	// silently destroys them (found by the full-fidelity round-trip,
	// spec 21 AC 6). Each statement MIRRORS its migration seed
	// byte-for-byte (fixed timestamps, no NOW()); the round-trip test
	// fails if the two drift.
	SeedSQL []string
}

// Rebuild seeds — mirrors of the POST-migration seeded state (see
// SeedSQL above for why these exist twice). The system roles are
// seeded by 008_seeds.sql and their permission arrays deliberately
// BLANKED by 009 ("reconciler-owned": auth.ReconcileSystemRoles
// refreshes them from the Go registry on every boot and after a CLI
// rebuild), so the faithful re-seed is empty permissions with the
// fixed seed timestamps.
const (
	seedServerSettingsSQL = `INSERT INTO server_settings_projection (id, updated_at)
VALUES ('global', '2026-01-01 00:00:00+00')
ON CONFLICT (id) DO NOTHING`

	seedAdminRoleSQL = `INSERT INTO roles_projection (id, name, description, permissions, is_system, created_at, updated_at, projection_version)
VALUES ('00000000000000000000000001', 'Admin', 'Full system access', '{}',
        TRUE, '2026-01-01 00:00:00+00', '2026-01-01 00:00:00+00', 0)
ON CONFLICT (id) DO NOTHING`

	seedUserRoleSQL = `INSERT INTO roles_projection (id, name, description, permissions, is_system, created_at, updated_at, projection_version)
VALUES ('00000000000000000000000002', 'User', 'Basic user access', '{}',
        TRUE, '2026-01-01 00:00:00+00', '2026-01-01 00:00:00+00', 0)
ON CONFLICT (id) DO NOTHING`
)

// AllRebuildTargets enumerates every replay-able projection.
//
// Order matters: targets are rebuilt in declaration order so that
// projections with foreign-key dependencies on other projections
// (e.g. action_sets reference actions; assignments reference both)
// rebuild after their parents. Reorder only with the dependency
// graph in mind.
//
// Drift contract: when a new stream type is added, append it here
// and register a Go applier for it via projectors.WireAll ->
// Store.RegisterRebuildApply. Operator visibility into "what can be
// rebuilt?" lives entirely in this slice; if you forget to add a
// target, RebuildAll won't touch the projection during emergency
// replay and the projection will stay stale.
var AllRebuildTargets = []rebuildTarget{
	{
		// Applied by projectors.ApplyUserWithRoles via projectors.WireAll.
		// NOTE (#497): TRUNCATE users_projection CASCADE wipes its FK
		// children totp_projection and identity_links_projection. Their
		// own targets below (declared AFTER users) re-derive them from the
		// totp / identity_provider streams — order is load-bearing.
		//
		// user_roles_projection is co-owned by this target (spec 21 /
		// AC 6 finding): it has TWO writers — ApplyUser inserts the
		// creation-time role_ids from UserCreatedWithRoles (user
		// stream), ApplyUserRole applies post-creation grants
		// (user_role stream). As separate targets, whichever TRUNCATEd
		// second wiped the other's replay. One target over both tables
		// and both streams replays everything in true sequence order.
		Name:        "users",
		Tables:      []string{"users_projection", "user_roles_projection"},
		Cascade:     true,
		StreamTypes: []string{"user", "user_role"},
	},
	{
		// Applied by projectors.ApplyTotp via projectors.WireAll (#497).
		// totp_projection is an FK child of users_projection, so the users
		// CASCADE above wiped it; this target (running AFTER users) replays
		// the totp stream so 2FA enrollments survive a full rebuild.
		Name:        "totp",
		Tables:      []string{"totp_projection"},
		StreamTypes: []string{"totp"},
	},
	{
		// Applied by projectors.ApplyToken via projectors.WireAll.
		Name:        "tokens",
		Tables:      []string{"tokens_projection"},
		StreamTypes: []string{"token"},
	},
	{
		// Applied by projectors.ApplyDevice via projectors.WireAll.
		// device_assigned_users_projection / device_assigned_groups_
		// projection are listed EXPLICITLY (#495): they carry no FK to
		// devices_projection, so the CASCADE never reaches them — the
		// applier re-derives both from DeviceAssigned/Unassigned and
		// DeviceGroupAssigned/Unassigned replay, and without the
		// TRUNCATE pre-rebuild rows would leak through its upserts
		// (same clean-slate rationale as action_set_members_projection).
		Name:        "devices",
		Tables:      []string{"devices_projection", "device_assigned_users_projection", "device_assigned_groups_projection"},
		Cascade:     true,
		StreamTypes: []string{"device"},
	},
	{
		// Applied by projectors.ApplyAction via projectors.WireAll.
		// Same combined ('action' + 'definition') filter as the legacy
		// rebuild_actions_projection — the action projector owns both
		// because some definition events synthesise action rows
		// (compliance-policy definitions specifically). The per-event
		// StreamType gate inside ApplyAction picks the correct branch
		// for each event during replay.
		Name:        "actions",
		Tables:      []string{"actions_projection"},
		StreamTypes: []string{"action", "definition"},
	},
	{
		// Applied by projectors.ApplyExecution via projectors.WireAll.
		Name:        "executions",
		Tables:      []string{"executions_projection"},
		StreamTypes: []string{"execution"},
	},
	{
		// Applied by projectors.ApplyActionSet via projectors.WireAll.
		// Both action_sets_projection AND action_set_members_projection
		// must be TRUNCATEd so the applier can replay from a clean
		// starting state (otherwise pre-rebuild member rows leak
		// through ON CONFLICT DO NOTHING and the recounted member_count
		// + sort_orders end up echoing a hybrid of pre- and
		// post-rebuild state). Listed in declaration order; CASCADE on
		// the parent isn't strictly required since there's no FK
		// linking the tables, but it's kept for symmetry with the
		// historical truncate semantics.
		Name:        "action_sets",
		Tables:      []string{"action_sets_projection", "action_set_members_projection"},
		Cascade:     true,
		StreamTypes: []string{"action_set"},
	},
	{
		// Applied by projectors.ApplyDefinition (a thin alias to
		// ApplyAction) via projectors.WireAll.
		// definition_members_projection is listed EXPLICITLY (#495): it
		// carries no FK to definitions_projection (composite PK only),
		// so the CASCADE never reached it — the previous comment
		// claiming it did was wrong against the live schema. Same
		// clean-slate rationale as action_set_members_projection above:
		// without the TRUNCATE, pre-rebuild member rows would leak
		// through the applier's upserts.
		Name:        "definitions",
		Tables:      []string{"definitions_projection", "definition_members_projection"},
		Cascade:     true,
		StreamTypes: []string{"definition"},
	},
	{
		// Applied by projectors.ApplyDeviceGroup via projectors.WireAll.
		// Both device_group_members_projection AND
		// dynamic_group_evaluation_queue must end up empty for the
		// applier to re-derive them from the event stream; explicit
		// TRUNCATE here keeps the post-rebuild state deterministic
		// regardless of FK drift in future migrations.
		Name:        "device_groups",
		Tables:      []string{"device_groups_projection", "device_group_members_projection", "dynamic_group_evaluation_queue"},
		Cascade:     true,
		StreamTypes: []string{"device_group"},
	},
	{
		// Applied by projectors.ApplyAssignment via projectors.WireAll.
		Name:        "assignments",
		Tables:      []string{"assignments_projection"},
		StreamTypes: []string{"assignment"},
	},
	{
		// Applied by projectors.ApplyUserSelection via projectors.WireAll.
		Name:        "user_selections",
		Tables:      []string{"user_selections_projection"},
		StreamTypes: []string{"user_selection"},
	},
	{
		// Applied by projectors.ApplyRole via projectors.WireAll. The
		// system Admin/User roles exist only as migration seeds (no
		// RoleCreated events), so they are re-seeded post-TRUNCATE;
		// auth.ReconcileSystemRoles then refreshes their permission
		// arrays from the code registry (boot and the rebuild CLI both
		// run it).
		Name:        "roles",
		Tables:      []string{"roles_projection"},
		Cascade:     true,
		StreamTypes: []string{"role"},
		SeedSQL:     []string{seedAdminRoleSQL, seedUserRoleSQL},
	},
	{
		// Applied by projectors.ApplyIdentityProvider via projectors.WireAll
		// (#497). The identity_provider stream drives BOTH
		// identity_providers_projection and its FK child
		// identity_links_projection (links reference provider_id AND
		// user_id). One target, both tables: replaying in sequence order
		// writes providers before the links that reference them.
		//
		// Ordering is load-bearing: TRUNCATE identity_providers_projection
		// CASCADE also wipes scim_group_mapping_projection and auth_states
		// (both FK-reference the provider). So this target MUST run BEFORE
		// scim_group_mappings (declared below) — otherwise it would wipe
		// the freshly-rebuilt SCIM mappings. auth_states is transient OIDC
		// flow state (operational); losing it in a rebuild is expected.
		// identity_links also FK-references users_projection, replayed
		// above — so those references resolve too.
		Name:        "identity_providers",
		Tables:      []string{"identity_providers_projection", "identity_links_projection"},
		Cascade:     true,
		StreamTypes: []string{"identity_provider"},
	},
	{
		// Applied by projectors.ApplyUserGroup via projectors.WireAll.
		// `TRUNCATE user_groups_projection CASCADE` walks the FK graph
		// and truncates every table that references
		// user_groups_projection — user_group_members_projection,
		// user_group_roles_projection,
		// dynamic_user_group_evaluation_queue, AND
		// scim_group_mapping_projection.
		//
		// The scim_group_mapping_projection wipe used to be terminal:
		// only user_group events were replayed, so SCIM mappings
		// stayed empty after the rebuild. The follow-up
		// scim_group_mappings target (declared immediately below)
		// re-replays them. Order matters — scim_group_mappings runs
		// AFTER user_groups so the FK references it depends on are
		// restored first. See manchtools/power-manage-server#175.
		Name:        "user_groups",
		Tables:      []string{"user_groups_projection"},
		Cascade:     true,
		StreamTypes: []string{"user_group"},
	},
	{
		// Applied by projectors.ApplySCIMGroupMapping via
		// projectors.WireAll. user_groups' TRUNCATE CASCADE wipes
		// scim_group_mapping_projection (FK reference); this target
		// replays the scim_group_mapping stream so the table is
		// non-empty again after the rebuild. Listed after user_groups
		// in declaration order — RebuildAll runs targets in slice
		// order when called with the default (full) set, so the FK
		// references the scim_group_mapping upserts need are present
		// by the time this target runs.
		//
		// Operators rebuilding a single target via
		// RebuildAll("scim_group_mappings", ...) get the right
		// behaviour too: the TRUNCATE clears the table, the replay
		// re-derives every row from events.
		Name:        "scim_group_mappings",
		Tables:      []string{"scim_group_mapping_projection"},
		StreamTypes: []string{"scim_group_mapping"},
	},
	{
		// Applied by projectors.ApplyLpsKeypair via projectors.WireAll.
		// Singleton projection of the control server's LPS sealing
		// keypair (#495) — one LpsKeypairGenerated event, one row.
		// No FK dependencies; order-independent.
		Name:        "lps_keypair",
		Tables:      []string{"lps_keypair"},
		StreamTypes: []string{"lps_keypair"},
	},
	// ---- #497 replay-gap closures ----
	{
		// Applied by projectors.ApplySecurityAlert via projectors.WireAll.
		// Security alerts ride the DEVICE stream (SecurityAlert /
		// SecurityAlertAcknowledged). No FK to devices_projection, so the
		// devices CASCADE never wiped it and no target replayed it — this
		// target TRUNCATEs + replays. event_id FK-references events, which
		// always exist. Runs after devices for locality; order-independent
		// (no projection FK).
		Name:        "security_alerts",
		Tables:      []string{"security_alerts_projection"},
		StreamTypes: []string{"device"},
	},
	{
		// Applied by projectors.ApplyLpsPassword via projectors.WireAll.
		// Replays the lps_password stream so the encrypted rotated-password
		// HISTORY survives a full rebuild (the payload ciphertexts carry
		// it). No projection FK; order-independent.
		Name:        "lps_passwords",
		Tables:      []string{"lps_passwords_projection"},
		StreamTypes: []string{"lps_password"},
	},
	{
		// Applied by projectors.ApplyLuksKey via projectors.WireAll.
		// Replays the luks_key stream — encrypted LUKS key history +
		// revocation lifecycle. No projection FK; order-independent.
		Name:        "luks_keys",
		Tables:      []string{"luks_keys_projection"},
		StreamTypes: []string{"luks_key"},
	},
	{
		// Applied by projectors.ApplyServerSettingsRebuild via
		// projectors.WireAll. server_settings_projection is a SINGLETON
		// seeded by migration 008; a plain TRUNCATE would drop the row and
		// the UPDATE-only projector would then no-op. The rebuild applier
		// re-seeds the 'global' row before applying, then replays
		// ServerSettingUpdated events so current settings are reproduced.
		// SeedSQL covers the ZERO-event case: without it a rebuild of a
		// deployment that never changed a setting deletes the 'global'
		// row entirely (the applier's per-event seed never fires) and
		// every settings read starts failing.
		Name:        "server_settings",
		Tables:      []string{"server_settings_projection"},
		StreamTypes: []string{"server_settings"},
		SeedSQL:     []string{seedServerSettingsSQL},
	},
	{
		// Applied by projectors.ApplyCompliancePolicy via projectors.WireAll.
		// Replays the compliance_policy stream into the policy + rules
		// projections (the applier's per-event branch writes both, and
		// re-derives compliance_policy_evaluation_projection via the
		// in-tx reevaluator). CASCADE so the rules/eval children start
		// clean; policy row is written before the rules that reference it.
		Name:        "compliance_policies",
		Tables:      []string{"compliance_policies_projection", "compliance_policy_rules_projection", "compliance_policy_evaluation_projection"},
		Cascade:     true,
		StreamTypes: []string{"compliance_policy"},
	},
	{
		// Applied by projectors.ApplyCompliance via projectors.WireAll.
		// Replays the compliance stream (device-reported results). No
		// projection FK; order-independent.
		Name:        "compliance_results",
		Tables:      []string{"compliance_results_projection"},
		StreamTypes: []string{"compliance"},
	},
}

// ErrUnknownTarget is returned when RebuildAll is called with a
// target name that does not exist in AllRebuildTargets.
var ErrUnknownTarget = errors.New("unknown rebuild target")

// ErrHistoryPruned is returned when RebuildAll runs against a log whose
// history has been pruned (an EventLogPruned marker exists): a plain
// TRUNCATE-and-replay of the surviving events would silently reproduce
// projections missing all state ≤ N (spec 19 AC 21). Recovery must go
// through the archive-restore path (RebuildAllFromArchive fed by the
// marker chain's sealed archives) instead.
var ErrHistoryPruned = errors.New("event history has been pruned: a plain rebuild would lose all state up to the prune checkpoint; restore from the retention archives instead (rebuild-projections --archive-dir)")

// ErrSkipEvent lets a projector's apply function report an event it
// cannot project (e.g. a malformed historical payload) as skippable
// rather than fatal: the live listener logs-and-swallows it like any
// error, and RebuildAll skips it and continues instead of aborting the
// whole rebuild on one bad historical row. Return it wrapped for
// context; the rebuild dispatcher matches it with errors.Is.
var ErrSkipEvent = errors.New("projector: event skipped (unprojectable)")

// RebuildAll truncates and re-applies the named projection targets
// from the event store. An empty targets slice rebuilds every
// registered target in dependency order.
//
// Runs inside a single transaction: every TRUNCATE and every event
// dispatch share one DB transaction so a failure mid-replay rolls
// back to the pre-rebuild state rather than leaving truncated
// projections half-populated. This is load-bearing for emergency
// rebuilds during incident response — operators must be able to run
// it and either succeed completely or no-op completely.
//
// The replay invokes the existing project_<stream>_event() PL/pgSQL
// projector for each event matching the target's stream types. As
// projectors are ported to Go (#96–#106), the per-target Function
// field gets swapped to a Go dispatcher and this same RebuildAll
// keeps working without operator-facing changes.
func (s *Store) RebuildAll(ctx context.Context, targetNames ...string) (RebuildResult, error) {
	targets, err := selectTargets(targetNames)
	if err != nil {
		return RebuildResult{}, err
	}

	start := s.now()
	result := RebuildResult{Targets: make([]TargetResult, 0, len(targets))}

	// REPEATABLE READ: the pruned-history guard below and every per-target
	// replay read must share ONE snapshot. Under READ COMMITTED each
	// statement sees a fresh snapshot, so a prune committing between the
	// guard and a later target's read would silently delete events
	// mid-replay — reproducing the data-loss class the guard closes
	// (proven by TestRebuildAll_ConsistentSnapshotUnderConcurrentPrune).
	// Writes don't overlap a prune's (projections vs events), so no
	// serialization failures are introduced.
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		// Fail closed on pruned history (spec 19 AC 21): if any
		// EventLogPruned marker exists, events ≤ its checkpoint are gone
		// from the live log — a TRUNCATE-and-replay here would silently
		// rebuild projections missing all of that state. Checked inside
		// the transaction, BEFORE any TRUNCATE, so the refusal leaves the
		// live projection untouched.
		var pruned bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM events WHERE event_type = $1)`,
			EventLogPrunedType).Scan(&pruned); err != nil {
			return fmt.Errorf("check for pruned history: %w", err)
		}
		if pruned {
			return ErrHistoryPruned
		}

		// Cascade safety (spec 21 AC 4 / F-03): a partial selection is
		// widened so no TRUNCATE ... CASCADE wipes a table whose
		// replaying target is missing from the run. Computed inside the
		// rebuild transaction so the FK graph read and the TRUNCATEs
		// see one consistent schema snapshot.
		expanded, expErr := expandCascadeClosure(ctx, tx, targets)
		if expErr != nil {
			return expErr
		}
		for _, t := range expanded {
			tStart := s.now()
			applied, skipped, runErr := s.runOneTarget(ctx, tx, t, 0) // 0 = unbounded (full rebuild)
			if runErr != nil {
				return fmt.Errorf("rebuild target %q: %w", t.Name, runErr)
			}
			result.Targets = append(result.Targets, TargetResult{
				Name:          t.Name,
				EventsApplied: applied,
				Skipped:       skipped,
				Duration:      s.now().Sub(tStart),
			})
		}
		return nil
	})
	if err != nil {
		return RebuildResult{}, err
	}

	result.TotalDuration = s.now().Sub(start)
	return result, nil
}

// runOneTarget truncates a target's projection tables then dispatches
// every matching event through the target's Go applier in strict
// sequence_num order. The applier lookup is resolved BEFORE any
// TRUNCATE so a miswired target (no Go applier registered) fails
// before holding ACCESS EXCLUSIVE on the projection tables — this
// turns the #125 footgun (silent no-op against a freshly truncated
// projection) into a clear error.
func (s *Store) runOneTarget(ctx context.Context, tx pgx.Tx, t rebuildTarget, upToSeq int64) (applied, skipped int64, err error) {
	apply := s.rebuildApplyFor(t.Name)
	if apply == nil {
		return 0, 0, fmt.Errorf("rebuild target %q has no Go applier registered (projectors.WireAll wiring may have drifted)", t.Name)
	}
	if err := s.truncateAndSeed(ctx, tx, t); err != nil {
		return 0, 0, err
	}
	return s.dispatchViaGoApplier(ctx, tx, t, apply, 0, upToSeq)
}

// truncateAndSeed clears a target's projection tables and re-applies its
// migration-seeded rows — the clean-slate prelude to a replay. Shared by
// the full rebuild (runOneTarget) and the snapshot-restore rebuild
// (restoreOneTarget). The applier lookup is done by the caller BEFORE
// this runs so a miswired target fails before it holds ACCESS EXCLUSIVE
// on the tables (the #125 footgun).
func (s *Store) truncateAndSeed(ctx context.Context, tx pgx.Tx, t rebuildTarget) error {
	for _, table := range t.Tables {
		stmt := "TRUNCATE TABLE " + table
		if t.Cascade {
			stmt += " CASCADE"
		}
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("truncate %s: %w", table, err)
		}
	}
	// Re-apply migration-seeded rows BEFORE the replay: seeded rows are
	// not event-sourced, and replayed events may legitimately UPDATE
	// them (ServerSettingUpdated mutates the seeded 'global' row).
	for _, seed := range t.SeedSQL {
		if _, err := tx.Exec(ctx, seed); err != nil {
			return fmt.Errorf("re-seed %s: %w", t.Name, err)
		}
	}
	return nil
}

// applyEvents replays a caller-supplied, sequence-ordered slice of events
// through the target's applier — the archived events ≤ N leg of a
// snapshot-restore rebuild (spec 19 AC 21), where the pruned history is
// no longer in the live `events` table. Only events matching the
// target's stream types are applied; the rest are the other targets'
// concern. Same ErrSkipEvent tolerance as the live-table replay.
func (s *Store) applyEvents(ctx context.Context, tx pgx.Tx, t rebuildTarget, apply RebuildApply, events []PersistedEvent) (applied, skipped int64, err error) {
	q := s.queries.WithTx(tx)
	streams := make(map[string]bool, len(t.StreamTypes))
	for _, st := range t.StreamTypes {
		streams[st] = true
	}
	for _, ev := range events {
		if !streams[ev.StreamType] {
			continue
		}
		if err := apply(ctx, q, ev); err != nil {
			if errors.Is(err, ErrSkipEvent) {
				if s.logger != nil {
					s.logger.Warn("restore: skipping unprojectable archived event",
						"target", t.Name, "event_id", ev.ID, "event_type", ev.EventType, "error", err)
				}
				skipped++
				continue
			}
			return 0, 0, fmt.Errorf("apply archived event %s for %s: %w", ev.ID, t.Name, err)
		}
		applied++
	}
	return applied, skipped, nil
}

// dispatchViaGoApplier replays every event matching the target's
// stream types through the registered Go applier. Loads the full
// event row into Go (the applier needs the payload, actor, and
// occurred_at, not just the row composite). Each apply runs against
// tx-bound queries so writes share atomicity with the outer rebuild
// transaction.
//
// Refs manchtools/power-manage-server#125.
func (s *Store) dispatchViaGoApplier(ctx context.Context, tx pgx.Tx, t rebuildTarget, apply RebuildApply, fromSeq, upToSeq int64) (applied, skipped int64, err error) {
	q := s.queries.WithTx(tx)

	// Stream in keyset-paginated batches rather than buffering the entire
	// matching event stream in memory (WS13 #14): a large event store could
	// otherwise materialise millions of rows at once. We cannot apply inside an
	// open rows iteration because pgx forbids a second query on a connection
	// with a live result set, and `apply` issues projection writes on this same
	// tx — so each batch is fully scanned and its rows closed BEFORE applying,
	// then the cursor (sequence_num, which is monotonic and unique) advances.
	// Memory is bounded to one batch; order and the snapshot are preserved
	// because the events table is append-only and read within this tx.
	// lastSeq is the keyset cursor: the query fetches sequence_num > lastSeq.
	// Seeding it with fromSeq skips events already replayed from a restored
	// snapshot's archived range — the restore path replays archived events
	// ≤ N and then this replays only the live events > N (fromSeq = N). A
	// full rebuild passes 0, which precedes every positive bigserial
	// sequence_num.
	lastSeq := fromSeq
	for {
		rows, err := tx.Query(ctx,
			`SELECT id, sequence_num, stream_type, stream_id, stream_version,
			        event_type, data, metadata, actor_type, actor_id, occurred_at
			   FROM events
			  WHERE stream_type = ANY($1) AND sequence_num > $2
			    AND ($4 = 0 OR sequence_num <= $4)
			  ORDER BY sequence_num
			  LIMIT $3`,
			t.StreamTypes, lastSeq, rebuildBatchSize, upToSeq,
		)
		if err != nil {
			return 0, 0, fmt.Errorf("load events for %s: %w", t.Name, err)
		}
		batch := make([]PersistedEvent, 0, rebuildBatchSize)
		for rows.Next() {
			var ev PersistedEvent
			if err := rows.Scan(
				&ev.ID, &ev.SequenceNum, &ev.StreamType, &ev.StreamID, &ev.StreamVersion,
				&ev.EventType, &ev.Data, &ev.Metadata, &ev.ActorType, &ev.ActorID, &ev.OccurredAt,
			); err != nil {
				rows.Close()
				return 0, 0, fmt.Errorf("scan event row for %s: %w", t.Name, err)
			}
			batch = append(batch, ev)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, 0, fmt.Errorf("iterate events for %s: %w", t.Name, err)
		}
		if len(batch) == 0 {
			break
		}
		for _, ev := range batch {
			if err := apply(ctx, q, ev); err != nil {
				if errors.Is(err, ErrSkipEvent) {
					// A malformed historical event must not abort the
					// rebuild; log it and move on (unlike the fatal path,
					// which rolls back the whole target). Counted as
					// Skipped, NOT applied (F-14 / spec 21 AC 7).
					if s.logger != nil {
						s.logger.Warn("rebuild: skipping unprojectable event",
							"target", t.Name, "event_id", ev.ID, "event_type", ev.EventType, "error", err)
					}
					lastSeq = ev.SequenceNum
					skipped++
					continue
				}
				return 0, 0, fmt.Errorf("apply event %s for %s: %w", ev.ID, t.Name, err)
			}
			lastSeq = ev.SequenceNum
			applied++
		}
		if len(batch) < rebuildBatchSize {
			break
		}
	}
	return applied, skipped, nil
}

// selectTargets resolves operator-supplied names to their
// rebuildTarget definitions, preserving canonical order. Empty input
// returns every target. Unknown names produce ErrUnknownTarget so the
// CLI / API caller surfaces a clear validation message instead of a
// confusing "target not run" no-op.
func selectTargets(names []string) ([]rebuildTarget, error) {
	if len(names) == 0 {
		return AllRebuildTargets, nil
	}

	wanted := make(map[string]struct{}, len(names))
	for _, n := range names {
		wanted[strings.ToLower(strings.TrimSpace(n))] = struct{}{}
	}

	out := make([]rebuildTarget, 0, len(names))
	for _, t := range AllRebuildTargets {
		if _, ok := wanted[t.Name]; ok {
			out = append(out, t)
			delete(wanted, t.Name)
		}
	}

	if len(wanted) > 0 {
		// Sort to keep error message deterministic across map iteration.
		unknown := make([]string, 0, len(wanted))
		for n := range wanted {
			unknown = append(unknown, n)
		}
		sort.Strings(unknown)
		return nil, fmt.Errorf("%w: %s", ErrUnknownTarget, strings.Join(unknown, ", "))
	}
	return out, nil
}

// ResolveTargets reports the exact target set a RebuildAll with the same
// names would run — the named targets plus every target auto-included
// for cascade safety — in canonical order, without touching any data.
// The rebuild-projections CLI calls it to print the plan before running;
// RebuildAll recomputes the same expansion inside its transaction.
func (s *Store) ResolveTargets(ctx context.Context, targetNames ...string) ([]string, error) {
	targets, err := selectTargets(targetNames)
	if err != nil {
		return nil, err
	}
	expanded, err := expandCascadeClosure(ctx, s.pool, targets)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(expanded))
	for i, t := range expanded {
		names[i] = t.Name
	}
	return names, nil
}

// pgxQuerier is the read surface expandCascadeClosure needs — satisfied
// by both *pgxpool.Pool (ResolveTargets preview) and pgx.Tx (the rebuild
// transaction itself).
type pgxQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// expandCascadeClosure widens a partial target selection until no
// `TRUNCATE ... CASCADE` in the run can wipe a table whose content will
// not be replayed (spec 21 AC 4 / F-03 — the #497 data-loss class via
// the partial path). The FK graph is read live from pg_constraint, so
// the expansion tracks schema reality rather than a hand-list.
//
// Rules, iterated to a fixpoint (an auto-included target can itself
// cascade further):
//
//   - a cascade-closure table owned by a target (listed in its Tables)
//     pulls that target into the run — it gets truncated, so it must be
//     replayed;
//   - a closure table owned by NO target is a cascade-rederived child
//     (schema_classification_test.go registry 3): its rows come back
//     when its FK parents' appliers replay, so every owned parent's
//     target is pulled in instead. This is what catches the
//     second-order case — user_group_members_projection is wiped via
//     its users_projection FK but re-derived by the user_groups target;
//   - a closure table with no owner and no owned FK parent cannot be
//     re-derived by any replay: refuse rather than truncate it.
//
// A full (no-arg) rebuild already selects every target, so the
// expansion is a no-op there.
func expandCascadeClosure(ctx context.Context, q pgxQuerier, selected []rebuildTarget) ([]rebuildTarget, error) {
	rows, err := q.Query(ctx, `
		SELECT DISTINCT child.relname, parent.relname
		FROM pg_constraint c
		JOIN pg_class child  ON child.oid  = c.conrelid
		JOIN pg_class parent ON parent.oid = c.confrelid
		JOIN pg_namespace n  ON n.oid = child.relnamespace
		WHERE c.contype = 'f' AND n.nspname = 'public'`)
	if err != nil {
		return nil, fmt.Errorf("read FK graph for cascade-safe rebuild: %w", err)
	}
	childrenOf := map[string][]string{}
	parentsOf := map[string][]string{}
	for rows.Next() {
		var child, parent string
		if err := rows.Scan(&child, &parent); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan FK edge: %w", err)
		}
		childrenOf[parent] = append(childrenOf[parent], child)
		parentsOf[child] = append(parentsOf[child], parent)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate FK edges: %w", err)
	}

	ownerIdx := map[string]int{} // table -> AllRebuildTargets index
	for i, t := range AllRebuildTargets {
		for _, tbl := range t.Tables {
			ownerIdx[tbl] = i
		}
	}

	inRun := map[string]bool{}
	for _, t := range selected {
		inRun[t.Name] = true
	}

	include := func(idx int) bool {
		name := AllRebuildTargets[idx].Name
		if inRun[name] {
			return false
		}
		inRun[name] = true
		return true
	}

	for grew := true; grew; {
		grew = false

		// Cascade closure of the current run's CASCADE-truncated tables.
		var queue []string
		for _, t := range AllRebuildTargets {
			if inRun[t.Name] && t.Cascade {
				queue = append(queue, t.Tables...)
			}
		}
		closure := map[string]bool{}
		for len(queue) > 0 {
			tbl := queue[0]
			queue = queue[1:]
			if closure[tbl] {
				continue
			}
			closure[tbl] = true
			queue = append(queue, childrenOf[tbl]...)
		}

		for tbl := range closure {
			if idx, owned := ownerIdx[tbl]; owned {
				if include(idx) {
					grew = true
				}
				continue
			}
			ownedParent := false
			for _, parent := range parentsOf[tbl] {
				if idx, owned := ownerIdx[parent]; owned {
					ownedParent = true
					if include(idx) {
						grew = true
					}
				}
			}
			if !ownedParent {
				return nil, fmt.Errorf("rebuild: TRUNCATE ... CASCADE would wipe %q, which no rebuild target replays and whose FK parents own no target either — refusing to destroy unreplayable state", tbl)
			}
		}
	}

	out := make([]rebuildTarget, 0, len(inRun))
	for _, t := range AllRebuildTargets {
		if inRun[t.Name] {
			out = append(out, t)
		}
	}
	return out, nil
}
