package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
)

// Snapshot is a captured projection state @ a checkpoint N (spec 19).
// Each table maps to its rows serialized as JSONB (column-complete via
// to_jsonb), so restore is column-agnostic and a new projection column
// is covered without a code change.
type Snapshot struct {
	UpToSeq int64                        `json:"up_to_seq"`
	Data    map[string][]json.RawMessage `json:"data"`
}

// Tables returns the per-table row sets.
func (s Snapshot) Tables() map[string][]json.RawMessage { return s.Data }

// Rows returns the captured rows for one table (nil if absent).
func (s Snapshot) Rows(table string) []json.RawMessage { return s.Data[table] }

// snapshotTables is the set of tables a projection applier writes —
// every rebuild-target table PLUS the cascade-rederived children and
// evaluation queues an applier touches during replay. They are shadowed
// by TEMP tables during a snapshot capture so the bounded replay never
// mutates live state. Discovered at runtime (every base table matching
// the projection/queue shape) so a new projection table is covered
// automatically; a matches-zero guard in the test keeps it honest.
//
// Deliberately NOT the operational tables (auth_states, revoked_tokens,
// luks_tokens, *_results, terminal_sessions, device_inventory,
// user_encryption_keys, lps_keypair) — appliers never write those
// during replay, and user_encryption_keys must never be shadowed (the
// DEK lookup during PII decrypt must hit the live table).
func snapshotTables(ctx context.Context, q pgxQuerier) ([]string, error) {
	set := map[string]bool{}
	// Authoritative: every rebuild-target table (covers non-projection
	// targets like lps_keypair). AllRebuildTargets is the source of
	// truth for "what appliers rebuild".
	for _, t := range AllRebuildTargets {
		for _, tbl := range t.Tables {
			set[tbl] = true
		}
	}
	// Plus the projection children + evaluation queues an applier
	// touches during replay that are NOT their own rebuild target
	// (device_labels, user_ssh_keys, user_group_*_projection, the
	// dynamic eval queues). Pattern-discovered so a new projection
	// child is shadowed automatically.
	rows, err := q.Query(ctx, `
		SELECT tablename FROM pg_tables
		WHERE schemaname = 'public'
		  AND (tablename LIKE '%\_projection'
		       OR tablename IN ('device_labels', 'user_ssh_keys',
		                        'dynamic_group_evaluation_queue',
		                        'dynamic_user_group_evaluation_queue'))`)
	if err != nil {
		return nil, fmt.Errorf("snapshot: discover tables: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		set[t] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out, nil
}

// CaptureProjectionSnapshot captures state @ upToSeq — the deterministic
// replay of events ≤ upToSeq — WITHOUT touching the live projection
// (spec 19 AC 16). Mechanism: inside one transaction, create a TEMP
// table shadow (LIKE public.<t>) for every projection table. pg_temp is
// implicitly first in search_path, so the rebuild appliers' unqualified
// reads and writes transparently hit the shadows; the live public.*
// tables are never read or written. The bounded replay (≤ upToSeq)
// then reproduces state @ N into the shadows, which are serialized and
// dropped at commit.
func (s *Store) CaptureProjectionSnapshot(ctx context.Context, upToSeq int64) (Snapshot, error) {
	if upToSeq <= 0 {
		return Snapshot{}, fmt.Errorf("snapshot: upToSeq must be positive, got %d", upToSeq)
	}
	snap := Snapshot{UpToSeq: upToSeq, Data: map[string][]json.RawMessage{}}

	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tables, err := snapshotTables(ctx, tx)
		if err != nil {
			return err
		}
		if len(tables) == 0 {
			return fmt.Errorf("snapshot: discovered zero projection tables — mis-scoped")
		}

		// Shadow every projection table with a TEMP table of the same
		// name. pg_temp precedes public in the search path, so every
		// unqualified applier statement resolves to the shadow. LIKE
		// INCLUDING ALL copies column shape + defaults + the PK/unique
		// INDEXES the appliers' ON CONFLICT clauses need (it never
		// copies FK constraints — temp tables can't reference permanent
		// ones, and a snapshot needs none). ON COMMIT DROP so they
		// vanish with the tx.
		for _, tbl := range tables {
			if _, err := tx.Exec(ctx,
				fmt.Sprintf(`CREATE TEMP TABLE %s (LIKE public.%s INCLUDING ALL) ON COMMIT DROP`, tbl, tbl)); err != nil {
				return fmt.Errorf("snapshot: shadow %s: %w", tbl, err)
			}
		}

		// Replay events ≤ N through the SAME rebuild machinery. Every
		// applier write/TRUNCATE resolves to the shadow (pg_temp), so
		// the live projection is untouched. Cascade-expand the full
		// target set (the closure logic reads the live FK graph, which
		// is fine — it only informs which targets to run).
		expanded, err := expandCascadeClosure(ctx, tx, AllRebuildTargets)
		if err != nil {
			return err
		}
		for _, t := range expanded {
			if _, _, err := s.runOneTarget(ctx, tx, t, upToSeq); err != nil {
				return fmt.Errorf("snapshot: replay target %q: %w", t.Name, err)
			}
		}

		// Serialize each shadow table, column-complete, as JSONB rows.
		for _, tbl := range tables {
			rows, err := tx.Query(ctx, fmt.Sprintf(`SELECT to_jsonb(t) FROM %s t`, tbl))
			if err != nil {
				return fmt.Errorf("snapshot: read shadow %s: %w", tbl, err)
			}
			var out []json.RawMessage
			for rows.Next() {
				var raw []byte
				if err := rows.Scan(&raw); err != nil {
					rows.Close()
					return fmt.Errorf("snapshot: scan %s: %w", tbl, err)
				}
				out = append(out, json.RawMessage(append([]byte(nil), raw...)))
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return fmt.Errorf("snapshot: iterate %s: %w", tbl, err)
			}
			snap.Data[tbl] = out
		}
		return nil
	})
	if err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}
