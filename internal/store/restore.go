package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// RebuildAllFromSnapshot restores a captured projection snapshot (state @
// snap.UpToSeq) and then replays only events with sequence_num > N on top
// (spec 19 AC 21). This is the recovery path after a retention prune has
// deleted events ≤ N from the live log: the pruned history is no longer
// replayable, so the snapshot stands in for it and the appliers carry the
// projections forward from N exactly as the live listeners did.
//
// The whole operation runs in one transaction, so a mid-restore failure
// rolls back to the pre-restore projection state rather than leaving it
// half-loaded. Contrast RebuildAll, which truncates and replays the
// FULL history from an empty projection (only valid when no history has
// been pruned).
//
// Full-fidelity contract (AC 17): for any checkpoint N, restore(snapshot@N)
// + replay(>N) reproduces byte-identical projection state to a RebuildAll
// run before the prune — proven by the full-row round-trip test.
func (s *Store) RebuildAllFromSnapshot(ctx context.Context, snap Snapshot) (RebuildResult, error) {
	if snap.UpToSeq <= 0 {
		return RebuildResult{}, fmt.Errorf("rebuild-from-snapshot: snapshot upToSeq must be positive, got %d", snap.UpToSeq)
	}

	start := s.now()
	result := RebuildResult{Targets: make([]TargetResult, 0, len(AllRebuildTargets))}

	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.restoreProjectionSnapshot(ctx, tx, snap); err != nil {
			return err
		}
		// Replay events > N (no truncate — the snapshot IS the state ≤ N).
		for _, t := range AllRebuildTargets {
			tStart := s.now()
			applied, skipped, runErr := s.replayTargetAfter(ctx, tx, t, snap.UpToSeq)
			if runErr != nil {
				return fmt.Errorf("replay target %q after snapshot: %w", t.Name, runErr)
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

// restoreProjectionSnapshot replaces the live projection tables with a
// captured snapshot. Inside tx it TRUNCATEs every snapshot table (CASCADE
// — the same blast radius a full RebuildAll already has; only transient
// operational children like auth_states are collaterally cleared) then
// repopulates them from the snapshot's JSONB rows in FK-parent-before-
// child order.
//
// Column-agnostic by construction: rows were serialized column-complete
// with to_jsonb at capture and are reloaded with jsonb_populate_recordset,
// so a new projection column round-trips without a code change (symmetric
// with CaptureProjectionSnapshot).
func (s *Store) restoreProjectionSnapshot(ctx context.Context, tx pgx.Tx, snap Snapshot) error {
	tables := make([]string, 0, len(snap.Data))
	for t := range snap.Data {
		tables = append(tables, t)
	}
	if len(tables) == 0 {
		return fmt.Errorf("restore: snapshot holds no tables")
	}
	sort.Strings(tables)

	// One TRUNCATE clears the whole set. CASCADE is required because the
	// set contains FK-linked parents and children (users_projection ←
	// totp_projection, …); it reaches no table a full RebuildAll would not.
	quoted := make([]string, len(tables))
	for i, t := range tables {
		quoted[i] = pgx.Identifier{t}.Sanitize()
	}
	if _, err := tx.Exec(ctx, "TRUNCATE TABLE "+strings.Join(quoted, ", ")+" CASCADE"); err != nil {
		return fmt.Errorf("restore: truncate projections: %w", err)
	}

	order, err := topoOrderTables(ctx, tx, tables)
	if err != nil {
		return err
	}

	// Load parents before children so every FK reference resolves.
	for _, tbl := range order {
		rows := snap.Data[tbl]
		if len(rows) == 0 {
			continue
		}
		arr, err := json.Marshal(rows)
		if err != nil {
			return fmt.Errorf("restore: encode %s rows: %w", tbl, err)
		}
		if _, err := tx.Exec(ctx,
			fmt.Sprintf(`INSERT INTO %s SELECT * FROM jsonb_populate_recordset(NULL::%s, $1::jsonb)`, tbl, tbl),
			arr); err != nil {
			return fmt.Errorf("restore: load %s (%d rows): %w", tbl, len(rows), err)
		}
	}
	return nil
}

// topoOrderTables returns the given tables in FK-parent-before-child
// order, considering only edges WITHIN the set (a child references a
// parent, so the parent must be inserted first). The FK graph is read
// live from pg_constraint, so the ordering tracks schema reality rather
// than a hand-maintained list. A cycle among the set's constraints is a
// hard error — restore cannot satisfy the FKs by ordering alone and must
// not silently load a subset.
func topoOrderTables(ctx context.Context, q pgxQuerier, tables []string) ([]string, error) {
	inSet := make(map[string]bool, len(tables))
	for _, t := range tables {
		inSet[t] = true
	}

	rows, err := q.Query(ctx, `
		SELECT DISTINCT child.relname, parent.relname
		FROM pg_constraint c
		JOIN pg_class child  ON child.oid  = c.conrelid
		JOIN pg_class parent ON parent.oid = c.confrelid
		JOIN pg_namespace n  ON n.oid = child.relnamespace
		WHERE c.contype = 'f' AND n.nspname = 'public'`)
	if err != nil {
		return nil, fmt.Errorf("restore: read FK graph: %w", err)
	}
	childrenOf := map[string][]string{}
	indeg := make(map[string]int, len(tables))
	for _, t := range tables {
		indeg[t] = 0
	}
	seen := map[[2]string]bool{}
	for rows.Next() {
		var child, parent string
		if err := rows.Scan(&child, &parent); err != nil {
			rows.Close()
			return nil, fmt.Errorf("restore: scan FK edge: %w", err)
		}
		// Self-referential FKs impose no cross-table ordering; edges to
		// tables outside the set don't constrain the set's load order
		// (those rows are never truncated, so they already exist).
		if child == parent || !inSet[child] || !inSet[parent] {
			continue
		}
		if seen[[2]string{parent, child}] {
			continue
		}
		seen[[2]string{parent, child}] = true
		childrenOf[parent] = append(childrenOf[parent], child)
		indeg[child]++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("restore: iterate FK edges: %w", err)
	}

	// Kahn's algorithm, processing ready nodes in sorted order for a
	// deterministic load sequence.
	ready := make([]string, 0, len(tables))
	for _, t := range tables {
		if indeg[t] == 0 {
			ready = append(ready, t)
		}
	}
	sort.Strings(ready)

	out := make([]string, 0, len(tables))
	for len(ready) > 0 {
		n := ready[0]
		ready = ready[1:]
		out = append(out, n)
		children := childrenOf[n]
		sort.Strings(children)
		for _, c := range children {
			indeg[c]--
			if indeg[c] == 0 {
				ready = append(ready, c)
			}
		}
		sort.Strings(ready)
	}
	if len(out) != len(tables) {
		return nil, fmt.Errorf("restore: FK cycle among snapshot tables — cannot order %d of %d for load", len(tables)-len(out), len(tables))
	}
	return out, nil
}
