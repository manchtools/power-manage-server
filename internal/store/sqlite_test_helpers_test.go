package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/testdb"
)

func auditActions(t *testing.T, raw *testdb.DB, resourceType, resourceID string) []string {
	t.Helper()
	rows, err := raw.Query(context.Background(), `
		SELECT action FROM audit_effects
		WHERE resource_type = ? AND resource_id = ?
		ORDER BY chain_seq`, resourceType, resourceID)
	require.NoError(t, err)
	defer rows.Close()

	actions := make([]string, 0)
	for rows.Next() {
		var action string
		require.NoError(t, rows.Scan(&action))
		actions = append(actions, action)
	}
	require.NoError(t, rows.Err())
	return actions
}

func searchDocumentMatches(t *testing.T, raw *testdb.DB, scope, entityID, expression string) bool {
	t.Helper()
	var matches bool
	require.NoError(t, raw.QueryRow(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM search_documents d
			JOIN search_fts f ON f.rowid = d.rowid
			WHERE d.scope = ? AND d.entity_id = ? AND search_fts MATCH ?
		)`, scope, entityID, expression).Scan(&matches))
	return matches
}

func rejectAuditOperation(t *testing.T, raw *testdb.DB, descriptor string) {
	t.Helper()
	_, err := raw.Exec(context.Background(), `
		CREATE TRIGGER test_reject_audit_operation
		BEFORE INSERT ON audit_operations
		WHEN NEW.request_descriptor = `+sqliteTestLiteral(descriptor)+`
		BEGIN SELECT RAISE(ABORT, 'fixture audit operation refusal'); END`)
	require.NoError(t, err)
}

func rejectAuditEffect(t *testing.T, raw *testdb.DB, action string) {
	t.Helper()
	_, err := raw.Exec(context.Background(), `
		CREATE TRIGGER test_reject_audit_effect
		BEFORE INSERT ON audit_effects
		WHEN NEW.action = `+sqliteTestLiteral(action)+`
		BEGIN SELECT RAISE(ABORT, 'fixture audit effect refusal'); END`)
	require.NoError(t, err)
}

func rejectRevocationFingerprint(t *testing.T, raw *testdb.DB, fingerprint string) {
	t.Helper()
	_, err := raw.Exec(context.Background(), `
		CREATE TRIGGER test_reject_revocation
		BEFORE INSERT ON revoked_certificates
		WHEN NEW.fingerprint = `+sqliteTestLiteral(fingerprint)+`
		BEGIN SELECT RAISE(ABORT, 'fixture revocation refusal'); END`)
	require.NoError(t, err)
}

func sqliteTestLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
