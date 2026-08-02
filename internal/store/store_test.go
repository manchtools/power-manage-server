package store_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/sqlitetype"
)

// The migration runner brings a fresh database all the way up.
func TestNew_RunsMigrations(t *testing.T) {
	st, pool := setupSQLite(t)
	ctx := context.Background()

	n, err := st.CountDevices(ctx)
	require.NoError(t, err)
	assert.Zero(t, n)

	// The seeds the server assumes exist on first boot.
	var settings int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM server_settings WHERE id = '00000000000000000000000003'`).Scan(&settings))
	assert.Equal(t, int64(1), settings)

	var roles int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM roles WHERE is_system`).Scan(&roles))
	assert.Equal(t, int64(2), roles)

	var version int
	require.NoError(t, pool.QueryRow(ctx, `PRAGMA user_version`).Scan(&version))
	assert.Equal(t, 1, version)
}

func TestSQLiteFile_IsPrivateAndReadOnlyOpenDoesNotCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")
	st, err := store.New(context.Background(), path)
	require.NoError(t, err)
	st.Close()
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	missing := filepath.Join(t.TempDir(), "missing.db")
	_, err = store.NewWithoutMigrations(context.Background(), missing)
	require.Error(t, err)
	_, statErr := os.Stat(missing)
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

// The boot-time role snapshot must not carry permissions for authentication
// subsystems that do not exist. Fresh seeds are intentionally empty until this
// audited reconciliation runs before the server starts accepting requests.
func TestSystemRoles_GrantNoLocalAuthenticationPermissions(t *testing.T) {
	st, pool := setupSQLite(t)
	ctx := context.Background()
	require.NoError(t, auth.ReconcileSystemRoles(ctx, st, time.Now(), slog.Default()))

	forbidden := []string{
		"UpdateUserPassword", "UpdateUserPassword:self",
		"SetupTOTP", "VerifyTOTP", "DisableTOTP", "AdminDisableUserTOTP",
		"GetTOTPStatus", "RegenerateBackupCodes",
	}
	require.NotEmpty(t, forbidden, "matches-zero guard: the forbidden-permission list is empty")

	rows, err := pool.Query(ctx, `SELECT name, permissions FROM roles WHERE is_system ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()

	seen := 0
	for rows.Next() {
		var name string
		var perms sqlitetype.StringList
		require.NoError(t, rows.Scan(&name, &perms))
		require.NotEmpty(t, perms, "role %s seeds no permissions at all", name)
		seen++
		for _, f := range forbidden {
			assert.NotContains(t, perms, f, "role %s seeds %s, which names a subsystem that does not exist", name, f)
		}
	}
	require.NoError(t, rows.Err())
	require.Equal(t, 2, seen, "matches-zero guard: no system roles were inspected")
}

// Every SQLite connection waits briefly for the serialized writer and enforces
// referential integrity. WAL is persistent on the database file.
func TestNew_ConfiguresSQLiteSafetyPragmas(t *testing.T) {
	_, pool := setupSQLite(t)
	ctx := context.Background()

	var foreignKeys, busyTimeout int
	var journalMode string
	require.NoError(t, pool.QueryRow(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys))
	require.NoError(t, pool.QueryRow(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout))
	require.NoError(t, pool.QueryRow(ctx, "PRAGMA journal_mode").Scan(&journalMode))
	assert.Equal(t, 1, foreignKeys)
	assert.Equal(t, 5_000, busyTimeout)
	assert.Equal(t, "wal", journalMode)
}

// The not-found recognizer is what callers use; reaching for the
// driver's sentinel directly is what this exists to prevent.
func TestIsNotFound_RecognisesAMissingRow(t *testing.T) {
	st, _ := setupSQLite(t)

	_, err := st.GetDevice(context.Background(), newID())
	require.Error(t, err)
	assert.True(t, store.IsNotFound(err), "a missing row must be recognisable through the store's recognizer: %v", err)
	assert.False(t, store.IsNotFound(nil))
}

// Certificate revocation is written inside the audited transaction
// that caused it, so the handshake gate can never admit a certificate
// whose revocation is still pending.
func TestRevokeInTx_CommitsWithItsAuditedOperation(t *testing.T) {
	st, _ := setupSQLite(t)
	ctx := context.Background()
	checker := store.NewRevocationChecker(st)

	fingerprint := sha256hex("superseded leaf certificate")

	revoked, err := checker.IsRevoked(ctx, fingerprint)
	require.NoError(t, err)
	require.False(t, revoked)

	deviceID := newID()
	op := mutationOp()
	op.RequestDescriptor = "powermanage.v1.ControlService/DeleteDevice"
	_, err = st.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, r *store.AuditRecorder) error {
		if err := store.RevokeInTx(ctx, tx, fingerprint, time.Now().UTC().Add(24*time.Hour), "device_deleted"); err != nil {
			return err
		}
		r.Effect(store.AuditEffect{
			ResourceType:        "device",
			ResourceID:          deviceID,
			Action:              "REVOKE",
			Outcome:             store.EffectApplied,
			EvidenceKind:        "certificate",
			EvidenceFingerprint: fingerprint,
		})
		return nil
	})
	require.NoError(t, err)

	revoked, err = checker.IsRevoked(ctx, fingerprint)
	require.NoError(t, err)
	assert.True(t, revoked)
}

// A revocation whose audited operation fails does not land: the gate
// must never be changed by a request that was refused.
func TestRevokeInTx_RollsBackWithAFailedOperation(t *testing.T) {
	st, _ := setupSQLite(t)
	ctx := context.Background()
	checker := store.NewRevocationChecker(st)

	fingerprint := sha256hex("certificate that must stay valid")

	// The effect names a reference value that is not a ULID, so the
	// audit insert is refused by the schema and the whole transaction
	// goes with it.
	notAULID := "revoked-by-hand"
	_, err := st.WithAudit(ctx, mutationOp(), func(ctx context.Context, tx *store.Tx, r *store.AuditRecorder) error {
		if err := store.RevokeInTx(ctx, tx, fingerprint, time.Now().UTC().Add(24*time.Hour), "manual"); err != nil {
			return err
		}
		e := store.AuditEffect{
			ResourceType: "device",
			ResourceID:   newID(),
			Action:       "REVOKE",
			Outcome:      store.EffectApplied,
			AfterRef:     &notAULID,
		}
		r.Effect(e)
		return nil
	})
	require.Error(t, err)

	revoked, err := checker.IsRevoked(ctx, fingerprint)
	require.NoError(t, err)
	assert.False(t, revoked, "an unaudited revocation must not reach the handshake gate")
}

func TestRevokeInTx_RefusesAnEmptyFingerprint(t *testing.T) {
	st, _ := setupSQLite(t)
	ctx := context.Background()

	_, err := st.WithAudit(ctx, mutationOp(), func(ctx context.Context, tx *store.Tx, r *store.AuditRecorder) error {
		return store.RevokeInTx(ctx, tx, "", time.Now().UTC(), "oops")
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty fingerprint")
}
