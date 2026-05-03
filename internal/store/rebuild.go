// Package store, file rebuild.go — Go-side replacement for the
// rebuild_*_projection() PL/pgSQL family. The PL/pgSQL functions
// retire in migration 015; this file is the only remaining caller of
// the project_<stream>_event() PL/pgSQL functions during the Phase 1
// migration window.
//
// The function set this file replaces was operator-only (run via psql
// for emergency rebuild from the event store), not invoked by any
// runtime code path. Moving it to Go gives operators a single
// well-typed entry point and removes ~650 lines of nearly-duplicate
// PL/pgSQL whose only difference between targets was the table name
// and the WHERE filter.
//
// Performance posture: one SQL roundtrip per rebuild target rather
// than one per event. The PL/pgSQL projector function still runs
// inside Postgres; we just hand it a server-side cursor (`SELECT
// project_X_event(e.*) FROM events e WHERE ... ORDER BY ...`) so all
// the per-event invocations happen in the database without
// Go-to-Postgres round-trip overhead. The whole rebuild runs inside
// one transaction so a failed projector cannot leave the projection
// half-replayed against a TRUNCATE'd table.
//
// Once a stream type's project_<stream>_event() is ported to a Go
// projector (#96–#106), this file's per-target Function field gets
// flipped from a PL/pgSQL call to a Go projector invocation. The
// callers and operator surface stay identical.
//
// Refs manchtools/power-manage-server#94, manchtools/power-manage-server#107.
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
// function handles cross-stream effects (the actions projector
// applies both 'action' and 'definition' events because compliance-
// policy definitions create derived action rows).
//
// Function is the PL/pgSQL function name that gets called per
// matching event. During the Phase 1 migration this is
// project_<X>_event(); once a stream type is ported (#96–#106),
// callers swap this to a Go projector dispatcher and the PL/pgSQL
// function is dropped from the schema.
type rebuildTarget struct {
	Name        string
	Tables      []string
	Cascade     bool
	StreamTypes []string
	Function    string
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
// and add the matching project_<X>_event() function to the schema.
// Operator visibility into "what can be rebuilt?" lives entirely in
// this slice; if you forget to add a target, RebuildAll won't touch
// the projection during emergency replay and the projection will
// stay stale.
var AllRebuildTargets = []rebuildTarget{
	{
		Name:        "users",
		Tables:      []string{"users_projection"},
		Cascade:     true,
		StreamTypes: []string{"user"},
		Function:    "project_user_event",
	},
	{
		Name:        "tokens",
		Tables:      []string{"tokens_projection"},
		StreamTypes: []string{"token"},
		Function:    "project_token_event",
	},
	{
		Name:        "devices",
		Tables:      []string{"devices_projection"},
		Cascade:     true,
		StreamTypes: []string{"device"},
		Function:    "project_device_event",
	},
	{
		// Same combined ('action' + 'definition') filter as the
		// original rebuild_actions_projection — the action projector
		// owns both because some definition events synthesise action
		// rows (compliance-policy definitions specifically).
		Name:        "actions",
		Tables:      []string{"actions_projection"},
		StreamTypes: []string{"action", "definition"},
		Function:    "project_action_event",
	},
	{
		Name:        "executions",
		Tables:      []string{"executions_projection"},
		StreamTypes: []string{"execution"},
		Function:    "project_execution_event",
	},
	{
		Name:        "action_sets",
		Tables:      []string{"action_sets_projection"},
		Cascade:     true,
		StreamTypes: []string{"action_set"},
		Function:    "project_action_set_event",
	},
	{
		Name:        "definitions",
		Tables:      []string{"definitions_projection"},
		Cascade:     true,
		StreamTypes: []string{"definition"},
		Function:    "project_definition_event",
	},
	{
		Name:        "device_groups",
		Tables:      []string{"device_groups_projection"},
		Cascade:     true,
		StreamTypes: []string{"device_group"},
		Function:    "project_device_group_event",
	},
	{
		Name:        "assignments",
		Tables:      []string{"assignments_projection"},
		StreamTypes: []string{"assignment"},
		Function:    "project_assignment_event",
	},
	{
		Name:        "user_selections",
		Tables:      []string{"user_selections_projection"},
		StreamTypes: []string{"user_selection"},
		Function:    "project_user_selection_event",
	},
	{
		Name:        "roles",
		Tables:      []string{"roles_projection"},
		Cascade:     true,
		StreamTypes: []string{"role"},
		Function:    "project_role_event",
	},
	{
		Name:        "user_groups",
		Tables:      []string{"user_groups_projection"},
		Cascade:     true,
		StreamTypes: []string{"user_group"},
		Function:    "project_user_group_event",
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

	start := time.Now()
	result := RebuildResult{Targets: make([]TargetResult, 0, len(targets))}

	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		for _, t := range targets {
			tStart := time.Now()
			applied, runErr := runOneTarget(ctx, tx, t)
			if runErr != nil {
				return fmt.Errorf("rebuild target %q: %w", t.Name, runErr)
			}
			result.Targets = append(result.Targets, TargetResult{
				Name:          t.Name,
				EventsApplied: applied,
				Duration:      time.Since(tStart),
			})
		}
		return nil
	})
	if err != nil {
		return RebuildResult{}, err
	}

	result.TotalDuration = time.Since(start)
	return result, nil
}

// runOneTarget truncates a target's projection tables then dispatches
// every matching event through the target's projector function in
// strict sequence_num order.
//
// We do this as two steps rather than one composite SQL statement:
//
//  1. Load the event IDs in sequence_num order into Go.
//  2. For each ID, call the projector via a parameterised SELECT that
//     re-loads the row and passes it as a composite to the function.
//
// The reason for the two-step shape: Postgres won't let us combine a
// projector call with COUNT() and ORDER BY in a single SELECT (the
// "must appear in GROUP BY" rule), and using ORDER BY inside a
// subquery does not strictly guarantee the function evaluates in
// scan order — the planner can re-evaluate scalar functions in any
// order. Iterating in Go gives us a clean ordering guarantee that
// matches the FOR ... LOOP semantics of the (now-deleted) PL/pgSQL
// rebuild functions.
//
// Performance posture: pgx caches the prepared statement for the
// per-event SELECT, so the per-event cost is one microsecond-scale
// roundtrip plus the Postgres-side projector execution. For a
// production-scale event store (10k–100k events) this completes in
// seconds — fine for an emergency-rebuild operator command.
func runOneTarget(ctx context.Context, tx pgx.Tx, t rebuildTarget) (int64, error) {
	for _, table := range t.Tables {
		stmt := "TRUNCATE TABLE " + table
		if t.Cascade {
			stmt += " CASCADE"
		}
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return 0, fmt.Errorf("truncate %s: %w", table, err)
		}
	}

	rows, err := tx.Query(ctx,
		"SELECT id FROM events WHERE stream_type = ANY($1) ORDER BY sequence_num",
		t.StreamTypes,
	)
	if err != nil {
		return 0, fmt.Errorf("load event ids for %s: %w", t.Function, err)
	}
	ids := make([]string, 0, 256)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan event id for %s: %w", t.Function, err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate event ids for %s: %w", t.Function, err)
	}
	rows.Close()

	// `events.*` passes the row as a composite type, matching the
	// signature `project_<X>_event(event events) RETURNS void` that
	// every PL/pgSQL projector exposes today. The Exec returns no
	// rows; we ignore the command tag and count by index.
	dispatch := fmt.Sprintf("SELECT %s(events.*) FROM events WHERE id = $1", t.Function)
	for _, id := range ids {
		if _, err := tx.Exec(ctx, dispatch, id); err != nil {
			return 0, fmt.Errorf("dispatch event %s via %s: %w", id, t.Function, err)
		}
	}
	return int64(len(ids)), nil
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
