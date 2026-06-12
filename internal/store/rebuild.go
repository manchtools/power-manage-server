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
	Duration      time.Duration
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
}

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
		// Applied by projectors.ApplyUser via projectors.WireAll.
		Name:        "users",
		Tables:      []string{"users_projection"},
		Cascade:     true,
		StreamTypes: []string{"user"},
	},
	{
		// Applied by projectors.ApplyToken via projectors.WireAll.
		Name:        "tokens",
		Tables:      []string{"tokens_projection"},
		StreamTypes: []string{"token"},
	},
	{
		// Applied by projectors.ApplyDevice via projectors.WireAll.
		Name:        "devices",
		Tables:      []string{"devices_projection"},
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
		// ApplyAction) via projectors.WireAll. `TRUNCATE
		// definitions_projection CASCADE` wipes
		// definition_members_projection (FK reference), which the
		// applier then re-derives from DefinitionMember* events.
		Name:        "definitions",
		Tables:      []string{"definitions_projection"},
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
		// Applied by projectors.ApplyRole via projectors.WireAll.
		Name:        "roles",
		Tables:      []string{"roles_projection"},
		Cascade:     true,
		StreamTypes: []string{"role"},
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
}

// ErrUnknownTarget is returned when RebuildAll is called with a
// target name that does not exist in AllRebuildTargets.
var ErrUnknownTarget = errors.New("unknown rebuild target")

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

	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		for _, t := range targets {
			tStart := s.now()
			applied, runErr := s.runOneTarget(ctx, tx, t)
			if runErr != nil {
				return fmt.Errorf("rebuild target %q: %w", t.Name, runErr)
			}
			result.Targets = append(result.Targets, TargetResult{
				Name:          t.Name,
				EventsApplied: applied,
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
func (s *Store) runOneTarget(ctx context.Context, tx pgx.Tx, t rebuildTarget) (int64, error) {
	apply := s.rebuildApplyFor(t.Name)
	if apply == nil {
		return 0, fmt.Errorf("rebuild target %q has no Go applier registered (projectors.WireAll wiring may have drifted)", t.Name)
	}

	for _, table := range t.Tables {
		stmt := "TRUNCATE TABLE " + table
		if t.Cascade {
			stmt += " CASCADE"
		}
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return 0, fmt.Errorf("truncate %s: %w", table, err)
		}
	}

	return s.dispatchViaGoApplier(ctx, tx, t, apply)
}

// dispatchViaGoApplier replays every event matching the target's
// stream types through the registered Go applier. Loads the full
// event row into Go (the applier needs the payload, actor, and
// occurred_at, not just the row composite). Each apply runs against
// tx-bound queries so writes share atomicity with the outer rebuild
// transaction.
//
// Refs manchtools/power-manage-server#125.
func (s *Store) dispatchViaGoApplier(ctx context.Context, tx pgx.Tx, t rebuildTarget, apply RebuildApply) (int64, error) {
	q := s.queries.WithTx(tx)
	rows, err := tx.Query(ctx,
		`SELECT id, sequence_num, stream_type, stream_id, stream_version,
		        event_type, data, metadata, actor_type, actor_id, occurred_at
		   FROM events
		  WHERE stream_type = ANY($1)
		  ORDER BY sequence_num`,
		t.StreamTypes,
	)
	if err != nil {
		return 0, fmt.Errorf("load events for %s: %w", t.Name, err)
	}
	events := make([]PersistedEvent, 0, 256)
	for rows.Next() {
		var ev PersistedEvent
		if err := rows.Scan(
			&ev.ID, &ev.SequenceNum, &ev.StreamType, &ev.StreamID, &ev.StreamVersion,
			&ev.EventType, &ev.Data, &ev.Metadata, &ev.ActorType, &ev.ActorID, &ev.OccurredAt,
		); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan event row for %s: %w", t.Name, err)
		}
		events = append(events, ev)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate events for %s: %w", t.Name, err)
	}

	for _, ev := range events {
		if err := apply(ctx, q, ev); err != nil {
			return 0, fmt.Errorf("apply event %s for %s: %w", ev.ID, t.Name, err)
		}
	}
	return int64(len(events)), nil
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
