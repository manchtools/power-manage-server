package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// This file hosts read-only integrity queries the operator surfaces
// (`control doctor`, spec 19 D-phase) run over the event store and
// projections. They live here — not in the doctor package — because they
// depend on projection schema and the AllRebuildTargets registry, which
// are store-internal; the doctor consumes them through its DB probe.
//
// All take a raw pool so both the doctor probe (its own pool) and the
// store test harness (TestingPool) can call them without constructing a
// full Store.

// UserDEK pairs a live user's id with its wrapped DEK (empty when the
// user has no user_encryption_keys row — the missing-key case).
type UserDEK struct {
	UserID  string
	Wrapped string // "" when no DEK row exists
}

// LiveUserWrappedDEKs returns, for every NON-deleted user, its wrapped
// DEK (or empty when absent). The caller attempts an unwrap with the KEK
// to distinguish a usable key from a missing/unwrappable one (spec 19
// AC 30) — the wrapped bytes never leave this process, and this function
// deliberately does not hold the KEK.
//
// ponytail: loads every live user's wrapped DEK in one pass. This is an
// operator-invoked, read-only doctor probe (rare, not a request path); a
// keyset-paginated scan is the upgrade path if a deployment's live-user
// count ever makes one pass too large to hold.
func LiveUserWrappedDEKs(ctx context.Context, pool *pgxpool.Pool) ([]UserDEK, error) {
	rows, err := pool.Query(ctx, `
		SELECT u.id, COALESCE(k.wrapped_dek, '')
		FROM users_projection u
		LEFT JOIN user_encryption_keys k ON k.user_id = u.id
		WHERE NOT u.is_deleted
		ORDER BY u.id`)
	if err != nil {
		return nil, fmt.Errorf("observability: list live user DEKs: %w", err)
	}
	defer rows.Close()
	var out []UserDEK
	for rows.Next() {
		var d UserDEK
		if err := rows.Scan(&d.UserID, &d.Wrapped); err != nil {
			return nil, fmt.Errorf("observability: scan live user DEK: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeletedUsersWithDEK returns the ids of users that are erased
// (is_deleted) yet still hold a user_encryption_keys row — the
// resurrected-shredded-DEK anomaly (spec 19 AC 31), e.g. a backup restore
// that brought a deleted user's key back. is_deleted (the durable
// projection flag) is used rather than the UserDeleted event so the check
// still holds after that event has itself been pruned.
func DeletedUsersWithDEK(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	rows, err := pool.Query(ctx, `
		SELECT k.user_id
		FROM user_encryption_keys k
		JOIN users_projection u ON u.id = k.user_id
		WHERE u.is_deleted
		ORDER BY k.user_id`)
	if err != nil {
		return nil, fmt.Errorf("observability: list deleted users with DEK: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("observability: scan deleted user with DEK: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// TargetDrift is one rebuild target's projection-freshness comparison.
type TargetDrift struct {
	Target string
	// StreamMax is the highest sequence_num of any event in the target's
	// stream types — reported for context (a shared stream carries events
	// for other targets too, so StreamMax alone is NOT the drift verdict).
	StreamMax int64
	// ProjMax is the highest projection_version across the target's
	// version-bearing projection tables — the newest event it applied.
	// Context only: with several tables a fresh sibling can exceed the
	// lagging one, so the drift REPORT uses LaggingTable/LaggingMax.
	ProjMax int64
	// Behind is the drift verdict: some version-bearing table of this
	// target has a newer applicable event past its own high-water.
	Behind bool
	// LaggingTable / LaggingMax name the (first) table that made Behind
	// true and ITS high-water — the actionable pair for the operator
	// (empty/zero when not Behind).
	LaggingTable string
	LaggingMax   int64
}

// Drifted reports whether the projection has fallen behind the event log.
func (d TargetDrift) Drifted() bool { return d.Behind }

// ComputeProjectionDrift detects, per rebuild target, a projection that
// has stopped applying events it should (spec 19 AC 31a — a silently
// dropped post-commit projection write with no other signal).
//
// Naive "max stream sequence_num > max projection_version" is unsound: a
// stream is shared (security_alerts and devices both ride the device
// stream; actions and definitions share action/definition), so a stream
// advancing for ANOTHER target would false-flag an idle one, and a
// legitimately empty projection would always look behind.
//
// Instead each version-bearing table is evaluated INDEPENDENTLY and a
// target is Behind iff ANY of its tables is: a target-wide MAX would let
// a fresh sibling table mask a stale one (CR). A table is behind iff there
// exists an event in the target's streams, past THAT TABLE's high-water,
// whose event_type is one the table has DEMONSTRABLY applied before —
// derived self-discoveringly as the distinct event_types of the events
// that wrote the table's existing rows (projection_version ==
// events.sequence_num). An empty/seed-only table has no handled types, so
// it is correctly never Behind, and a co-tenant event of a shared stream
// (a type this table never wrote) does not flag it.
//
// Accepted limitation: the handled-type set is sampled from CURRENT rows,
// so a type whose rows have all since been replaced/deleted — or one
// NEVER yet applied — drops out of detection. A contract-free, replay-free
// live check cannot close that gap; the robust upgrade is a per-projection
// applied-sequence cursor (future work), which would make this exact.
func ComputeProjectionDrift(ctx context.Context, pool *pgxpool.Pool) ([]TargetDrift, error) {
	// Which projection tables carry projection_version (children like
	// device_labels and the eval queues do not) — read once from the live
	// catalog so the per-target queries only touch version-bearing tables.
	hasVersion, err := tablesWithProjectionVersion(ctx, pool)
	if err != nil {
		return nil, err
	}

	out := make([]TargetDrift, 0, len(AllRebuildTargets))
	for _, t := range AllRebuildTargets {
		var streamMax int64
		if err := pool.QueryRow(ctx,
			`SELECT COALESCE(MAX(sequence_num), 0) FROM events WHERE stream_type = ANY($1)`,
			t.StreamTypes).Scan(&streamMax); err != nil {
			return nil, fmt.Errorf("observability: stream max for %s: %w", t.Name, err)
		}
		td := TargetDrift{Target: t.Name, StreamMax: streamMax}

		for _, tbl := range t.Tables {
			if !hasVersion[tbl] {
				continue
			}
			// Per-table high-water + per-table drift probe (handled types =
			// event types that wrote THIS table's rows). tbl is a
			// registry-owned identifier filtered by the live catalog scan
			// above — never request input; a table identifier cannot be
			// bound as a parameter.
			var tableMax int64
			var behind bool
			if err := pool.QueryRow(ctx, fmt.Sprintf(`
				WITH hw AS (SELECT COALESCE(MAX(projection_version), 0) AS v FROM %[1]s)
				SELECT
					(SELECT v FROM hw),
					EXISTS (
						SELECT 1 FROM events e
						WHERE e.stream_type = ANY($1)
						  AND e.sequence_num > (SELECT v FROM hw)
						  AND e.event_type IN (
						      SELECT DISTINCT h.event_type FROM events h
						      WHERE h.sequence_num IN (SELECT projection_version FROM %[1]s)
						  )
					)`, tbl), t.StreamTypes).Scan(&tableMax, &behind); err != nil {
				return nil, fmt.Errorf("observability: drift probe for %s.%s: %w", t.Name, tbl, err)
			}
			if tableMax > td.ProjMax {
				td.ProjMax = tableMax
			}
			if behind && !td.Behind {
				td.Behind = true
				td.LaggingTable = tbl
				td.LaggingMax = tableMax
			}
		}
		out = append(out, td)
	}
	return out, nil
}

// tablesWithProjectionVersion returns the set of public base tables that
// have a projection_version column.
func tablesWithProjectionVersion(ctx context.Context, pool *pgxpool.Pool) (map[string]bool, error) {
	rows, err := pool.Query(ctx, `
		SELECT table_name FROM information_schema.columns
		WHERE table_schema = 'public' AND column_name = 'projection_version'`)
	if err != nil {
		return nil, fmt.Errorf("observability: discover projection_version tables: %w", err)
	}
	defer rows.Close()
	set := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("observability: scan projection_version table: %w", err)
		}
		set[n] = true
	}
	return set, rows.Err()
}
