package store_test

// Schema invariants, asserted against the live catalog rather than
// against a list someone maintained by hand. Each check discovers the
// tables and columns it inspects, and each carries a matches-zero
// guard: a query that returns nothing must fail the test rather than
// pass it vacuously.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func scanStrings(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(), sql, args...)
	require.NoError(t, err)
	defer rows.Close()

	var out []string
	for rows.Next() {
		var v string
		require.NoError(t, rows.Scan(&v))
		out = append(out, v)
	}
	require.NoError(t, rows.Err())
	return out
}

func publicTables(t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	tables := scanStrings(t, pool, `
		SELECT table_name FROM information_schema.tables
		WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
		ORDER BY table_name`)
	require.NotEmpty(t, tables, "matches-zero guard: the catalog returned no tables")
	return tables
}

// State is held in ordinary CRUD tables. Nothing carries a projection
// suffix or a projection version, and there is no event table for
// anything to be replayed from.
func TestSchema_HoldsNoProjectionArtifacts(t *testing.T) {
	_, pool := setupPostgres(t)

	tables := publicTables(t, pool)
	for _, name := range tables {
		assert.NotContains(t, name, "_projection", "table %s carries a projection suffix", name)
	}
	assert.NotContains(t, tables, "events", "there is no event table to replay from")

	versioned := scanStrings(t, pool, `
		SELECT table_name || '.' || column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND column_name = 'projection_version'`)
	assert.Empty(t, versioned, "no table may carry a projection version: %v", versioned)
}

// Human identity is OIDC plus SCIM. There is no column anywhere that
// could hold a local password, a TOTP secret or a backup code.
func TestSchema_HoldsNoLocalAuthenticationSecrets(t *testing.T) {
	_, pool := setupPostgres(t)

	// Discovered from the catalog, not from a list: a new column named
	// after any of these fails the day it is added.
	found := scanStrings(t, pool, `
		SELECT table_name || '.' || column_name FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND (   column_name LIKE '%password_hash%'
		       OR column_name LIKE '%totp%'
		       OR column_name LIKE '%backup_code%'
		       OR column_name LIKE '%mfa%'
		       OR column_name LIKE '%webauthn%'
		       OR column_name = 'has_password')`)
	assert.Empty(t, found, "local authentication state must not exist: %v", found)

	tables := publicTables(t, pool)
	for _, forbidden := range []string{"totp", "totp_projection", "webauthn_credentials"} {
		assert.NotContains(t, tables, forbidden)
	}
}

// Every identifier column is a text ULID. Nothing is a uuid, so the
// two identifier schemes cannot start to mix.
func TestSchema_UsesTextULIDsAndNoUUIDs(t *testing.T) {
	_, pool := setupPostgres(t)

	uuids := scanStrings(t, pool, `
		SELECT table_name || '.' || column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND data_type = 'uuid'`)
	assert.Empty(t, uuids, "identifiers are ULIDs; these columns are uuid: %v", uuids)

	// The primary keys of the tables whose ids this package mints are
	// text, and the audit tables enforce the ULID form outright.
	idTypes := scanStrings(t, pool, `
		SELECT c.table_name || ' ' || c.data_type
		FROM information_schema.columns c
		WHERE c.table_schema = 'public'
		  AND c.table_name <> 'goose_db_version'
		  AND c.column_name IN ('id', 'operation_id', 'effect_id', 'delivery_id', 'job_id', 'anchor_id', 'checkpoint_id')`)
	require.NotEmpty(t, idTypes, "matches-zero guard: no identifier columns were found")
	for _, entry := range idTypes {
		assert.Contains(t, entry, " text", "identifier column is not text: %s", entry)
	}
}

// Searchable entities carry a same-row generated vector and a GIN
// index over it. The entity list is the product's search facets plus
// the audit stream; the columns and indexes are discovered.
func TestSchema_SearchVectorsAreGeneratedAndIndexed(t *testing.T) {
	_, pool := setupPostgres(t)

	searchable := []string{
		"actions", "action_sets", "definitions", "compliance_policies",
		"devices", "users", "device_groups", "user_groups", "executions",
		"audit_operations",
	}
	require.NotEmpty(t, searchable, "matches-zero guard: the searchable-entity list is empty")

	generatedCols := scanStrings(t, pool, `
		SELECT table_name FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND column_name = 'search_tsv'
		  AND udt_name = 'tsvector'
		  AND is_generated = 'ALWAYS'`)
	require.NotEmpty(t, generatedCols, "matches-zero guard: no generated search columns were found")

	ginIndexed := scanStrings(t, pool, `
		SELECT t.relname
		FROM pg_index i
		JOIN pg_class ix ON ix.oid = i.indexrelid
		JOIN pg_class t  ON t.oid  = i.indrelid
		JOIN pg_am am    ON am.oid = ix.relam
		WHERE am.amname = 'gin'`)
	require.NotEmpty(t, ginIndexed, "matches-zero guard: no GIN indexes were found")

	for _, table := range searchable {
		assert.Contains(t, generatedCols, table,
			"%s must derive its search vector from its own row, in the same statement that writes it", table)
		assert.Contains(t, ginIndexed, table, "%s must have a GIN index over its search vector", table)
	}
}

// Search derivation is same-row only. A trigger on a searchable table
// would be cross-row denormalisation moving into SQL, which is
// application logic's job.
func TestSchema_SearchInstallsNoTriggers(t *testing.T) {
	_, pool := setupPostgres(t)

	triggers := scanStrings(t, pool, `
		SELECT tgrelid::regclass::text || '.' || tgname
		FROM pg_trigger
		WHERE NOT tgisinternal`)
	require.NotEmpty(t, triggers, "matches-zero guard: no user triggers were found, so this check proves nothing")

	for _, trig := range triggers {
		assert.Contains(t, trig, "audit_",
			"the only user triggers in this schema are the audit append-only guards; %s is something else", trig)
	}
}

// The search vectors must not become a side channel around the audit
// field classification: no fingerprint and no sealed detail feeds the
// audit stream's vector.
func TestSchema_AuditSearchVectorExcludesEvidenceAndSealedDetail(t *testing.T) {
	_, pool := setupPostgres(t)

	definition := scanStrings(t, pool, `
		SELECT generation_expression FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'audit_operations' AND column_name = 'search_tsv'`)
	require.Len(t, definition, 1, "matches-zero guard: the audit search column was not found")

	for _, forbidden := range []string{"fingerprint", "sealed_detail"} {
		assert.NotContains(t, definition[0], forbidden,
			"the audit search vector must not be derived from %s", forbidden)
	}
	assert.Contains(t, definition[0], "request_descriptor")
}

// The audit tables reject mutation. Discovered from the catalog so a
// new audit table without a guard fails here.
func TestSchema_EveryAuditTableHasAppendOnlyGuards(t *testing.T) {
	_, pool := setupPostgres(t)

	auditTables := scanStrings(t, pool, `
		SELECT table_name FROM information_schema.tables
		WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
		  AND table_name LIKE 'audit\_%'
		  AND table_name <> 'audit_chain_head'
		ORDER BY table_name`)
	require.NotEmpty(t, auditTables, "matches-zero guard: no audit tables were found")

	for _, table := range auditTables {
		guards := scanStrings(t, pool, `
			SELECT tgname FROM pg_trigger
			WHERE NOT tgisinternal AND tgrelid = ('public.' || $1)::regclass`, table)
		assert.Len(t, guards, 2,
			"%s needs a row-level guard for UPDATE/DELETE and a statement-level guard for TRUNCATE, has %v", table, guards)
	}
}

// The chain head is deliberately NOT append-only: it is ordinary
// mutable state that every append advances. Asserting it explicitly
// keeps a future "guard everything named audit_*" change from
// deadlocking the write path.
func TestSchema_ChainHeadIsMutable(t *testing.T) {
	_, pool := setupPostgres(t)

	guards := scanStrings(t, pool, `
		SELECT tgname FROM pg_trigger
		WHERE NOT tgisinternal AND tgrelid = 'public.audit_chain_head'::regclass`)
	assert.Empty(t, guards, "the chain head must stay updatable; every append advances it")
}
