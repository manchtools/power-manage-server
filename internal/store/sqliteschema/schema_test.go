package sqliteschema_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/manchtools/power-manage/server/internal/store/sqliteschema"
)

func TestBaselineEnablesRequiredSQLitePosture(t *testing.T) {
	db := openBaseline(t)

	assertPragma(t, db, "foreign_keys", "1")
	assertPragma(t, db, "journal_mode", "wal")
	assertPragma(t, db, "synchronous", "2")
	assertPragma(t, db, "user_version", "1")
	assertPragma(t, db, "integrity_check", "ok")

	var applicationTables int
	require.NoError(t, db.QueryRowContext(t.Context(), `
		SELECT count(*) FROM sqlite_schema
		WHERE type = 'table'
		  AND name NOT LIKE 'sqlite_%'
		  AND name NOT GLOB 'search_fts_*'
		  AND name NOT GLOB 'search_trigram_*'
	`).Scan(&applicationTables))
	assert.Equal(t, 55, applicationTables)
}

func TestBaselineEnforcesForeignKeys(t *testing.T) {
	db := openBaseline(t)

	_, err := db.ExecContext(t.Context(), `
		INSERT INTO device_labels (device_id, key, value)
		VALUES ('00000000000000000000000009', 'site', 'berlin')
	`)
	assert.ErrorContains(t, err, "FOREIGN KEY constraint failed")
}

func TestBaselineEnforcesCaseInsensitiveActiveEmailUniqueness(t *testing.T) {
	db := openBaseline(t)
	_, err := db.ExecContext(t.Context(), `
		INSERT INTO users (id, email) VALUES
		('00000000000000000000000009', 'operator@example.test')
	`)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), `
		INSERT INTO users (id, email) VALUES
		('00000000000000000000000008', 'OPERATOR@example.test')
	`)
	assert.ErrorContains(t, err, "UNIQUE constraint failed")
}

func TestBaselineAuditRowsAreAppendOnly(t *testing.T) {
	db := openBaseline(t)
	insertAuditOperation(t, db)

	_, err := db.ExecContext(t.Context(), `
		UPDATE audit_operations SET result = 'FAILURE'
		WHERE operation_id = '00000000000000000000000009'
	`)
	assert.ErrorContains(t, err, "append-only")

	_, err = db.ExecContext(t.Context(), `
		DELETE FROM audit_operations
		WHERE operation_id = '00000000000000000000000009'
	`)
	assert.ErrorContains(t, err, "append-only")

	insertAuditEffect(t, db, 2)
	_, err = db.ExecContext(t.Context(), `
		UPDATE audit_effects SET outcome = 'FAILED'
		WHERE effect_id = '00000000000000000000000008'
	`)
	assert.ErrorContains(t, err, "append-only")
	_, err = db.ExecContext(t.Context(), `
		DELETE FROM audit_effects
		WHERE effect_id = '00000000000000000000000008'
	`)
	assert.ErrorContains(t, err, "append-only")

	retentionDB := openBaseline(t)
	insertAuditOperation(t, retentionDB)
	tx, err := retentionDB.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(t.Context(), `
		INSERT INTO audit_retention_guard (stream, boundary_seq) VALUES ('control', 1)
	`)
	require.NoError(t, err)
	result, err := tx.ExecContext(t.Context(), `
		DELETE FROM audit_operations
		WHERE operation_id = '00000000000000000000000009'
	`)
	require.NoError(t, err)
	deleted, err := result.RowsAffected()
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)
	_, err = tx.ExecContext(t.Context(), `DELETE FROM audit_retention_guard WHERE stream = 'control'`)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
}

func TestBaselineRejectsInvalidAuditFieldNames(t *testing.T) {
	db := openBaseline(t)
	insertAuditOperation(t, db)

	_, err := db.ExecContext(t.Context(), `
		INSERT INTO audit_effects (
			effect_id, operation_id, chain_seq, effect_seq, resource_type,
			resource_id, action, outcome, changed_fields, occurred_at, prev_hash, row_hash
		) VALUES (
			'00000000000000000000000008', '00000000000000000000000009', 2, 0, 'device',
			'00000000000000000000000007', 'UPDATE', 'APPLIED', '["safe","secret value"]',
			CURRENT_TIMESTAMP, zeroblob(32), zeroblob(32)
		)
	`)
	assert.ErrorContains(t, err, "invalid field name")
}

func TestBaselineRejectsSharedAuditSequenceCollisionsAndSplitRetention(t *testing.T) {
	t.Run("operation then effect", func(t *testing.T) {
		db := openBaseline(t)
		insertAuditOperation(t, db)
		insertAuditEffect(t, db, 2)
		_, err := db.ExecContext(t.Context(), `
			INSERT INTO audit_operations (
				operation_id, chain_seq, operation_class, actor_type, origin,
				request_descriptor, authorization_outcome, result, occurred_at,
				prev_hash, row_hash
			) VALUES (
				'00000000000000000000000006', 2, 'MUTATION', 'user', 'rpc',
				'pm.v1.ControlService/Test', 'ALLOWED', 'SUCCESS', CURRENT_TIMESTAMP,
				zeroblob(32), zeroblob(32)
			)
		`)
		assert.ErrorContains(t, err, "already belongs to an effect")
	})

	t.Run("effect then operation", func(t *testing.T) {
		db := openBaseline(t)
		insertAuditOperation(t, db)
		_, err := db.ExecContext(t.Context(), `
			INSERT INTO audit_effects (
				effect_id, operation_id, chain_seq, effect_seq, resource_type,
				resource_id, action, outcome, changed_fields, occurred_at, prev_hash, row_hash
			) VALUES (
				'00000000000000000000000008', '00000000000000000000000009', 1, 0, 'device',
				'00000000000000000000000007', 'UPDATE', 'APPLIED', '["hostname"]',
				CURRENT_TIMESTAMP, zeroblob(32), zeroblob(32)
			)
		`)
		assert.ErrorContains(t, err, "already belongs to an operation")
	})

	t.Run("split retention", func(t *testing.T) {
		db := openBaseline(t)
		insertAuditOperation(t, db)
		insertAuditEffect(t, db, 2)
		_, err := db.ExecContext(t.Context(), `
			INSERT INTO audit_retention_guard (stream, boundary_seq) VALUES ('control', 1)
		`)
		assert.ErrorContains(t, err, "not a closed prefix")
	})
}

func TestBaselineFTS5ProvidesPrefixAndTrigramCandidates(t *testing.T) {
	db := openBaseline(t)
	_, err := db.ExecContext(t.Context(), `
		INSERT INTO search_documents (scope, entity_id, primary_text, description)
		VALUES ('devices', '00000000000000000000000009', 'straße-host-01', 'Berlin workstation')
	`)
	require.NoError(t, err)

	for _, query := range []struct {
		name  string
		table string
		term  string
	}{
		{name: "prefix", table: "search_fts", term: "straße*"},
		{name: "trigram candidate", table: "search_trigram", term: "stra"},
	} {
		t.Run(query.name, func(t *testing.T) {
			statement := fmt.Sprintf(`
				SELECT d.entity_id
				FROM %s AS f
				JOIN search_documents AS d ON d.rowid = f.rowid
				WHERE %s MATCH ?
			`, query.table, query.table)
			var id string
			require.NoError(t, db.QueryRowContext(t.Context(), statement, query.term).Scan(&id))
			assert.Equal(t, "00000000000000000000000009", id)
		})
	}

	_, err = db.ExecContext(t.Context(), `
		DELETE FROM search_documents
		WHERE scope = 'devices' AND entity_id = '00000000000000000000000009'
	`)
	require.NoError(t, err)
	for _, indexed := range []struct {
		table string
		term  string
	}{
		{table: "search_fts", term: "straße*"},
		{table: "search_trigram", term: "stra"},
	} {
		statement := fmt.Sprintf("SELECT count(*) FROM %s WHERE %s MATCH ?", indexed.table, indexed.table)
		var remaining int
		require.NoError(t, db.QueryRowContext(t.Context(), statement, indexed.term).Scan(&remaining))
		assert.Zero(t, remaining, "erasing the owner must erase %s", indexed.table)
	}
}

func openBaseline(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control.sqlite")
	dsn := (&url.URL{Scheme: "file", Path: path}).String() +
		"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)" +
		"&_pragma=busy_timeout(5000)&_time_format=sqlite"
	db, err := sql.Open("sqlite", dsn)
	require.NoError(t, err)
	db.SetMaxOpenConns(4)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	schema, err := sqliteschema.FS.ReadFile("schema.sql")
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), string(schema))
	require.NoError(t, err)
	return db
}

func assertPragma(t *testing.T, db *sql.DB, pragma, want string) {
	t.Helper()
	var got string
	require.NoError(t, db.QueryRowContext(t.Context(), "PRAGMA "+pragma).Scan(&got))
	assert.Equal(t, want, got)
}

func insertAuditOperation(t *testing.T, db interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `
		INSERT INTO audit_operations (
			operation_id, chain_seq, operation_class, actor_type, origin,
			request_descriptor, authorization_outcome, result, occurred_at,
			prev_hash, row_hash
		) VALUES (
			'00000000000000000000000009', 1, 'MUTATION', 'user', 'rpc',
			'pm.v1.ControlService/Test', 'ALLOWED', 'SUCCESS', CURRENT_TIMESTAMP,
			zeroblob(32), zeroblob(32)
		)
	`)
	require.NoError(t, err)
}

func insertAuditEffect(t *testing.T, db interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, chainSequence int64) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `
		INSERT INTO audit_effects (
			effect_id, operation_id, chain_seq, effect_seq, resource_type,
			resource_id, action, outcome, changed_fields, occurred_at, prev_hash, row_hash
		) VALUES (
			'00000000000000000000000008', '00000000000000000000000009', ?, 0, 'device',
			'00000000000000000000000007', 'UPDATE', 'APPLIED', '["hostname"]',
			CURRENT_TIMESTAMP, zeroblob(32), zeroblob(32)
		)
	`, chainSequence)
	require.NoError(t, err)
}
