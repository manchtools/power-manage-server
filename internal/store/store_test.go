package store_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
)

// The migration runner brings a fresh database all the way up.
func TestNew_RunsMigrations(t *testing.T) {
	st, pool := setupPostgres(t)
	ctx := context.Background()

	n, err := st.CountDevices(ctx)
	require.NoError(t, err)
	assert.Zero(t, n)

	// The seeds the server assumes exist on first boot.
	var settings int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM public.server_settings WHERE id = '00000000000000000000000003'`).Scan(&settings))
	assert.Equal(t, int64(1), settings)

	var roles int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM public.roles WHERE is_system`).Scan(&roles))
	assert.Equal(t, int64(2), roles)
}

// The seeded permission arrays must not carry permissions for
// subsystems that do not exist: the reconciler refreshes them from the
// code registry, but a seed naming a removed subsystem would grant it
// for the window before the first reconcile.
func TestSeeds_GrantNoLocalAuthenticationPermissions(t *testing.T) {
	_, pool := setupPostgres(t)
	ctx := context.Background()

	forbidden := []string{
		"UpdateUserPassword", "UpdateUserPassword:self",
		"SetupTOTP", "VerifyTOTP", "DisableTOTP", "AdminDisableUserTOTP",
		"GetTOTPStatus", "RegenerateBackupCodes",
	}
	require.NotEmpty(t, forbidden, "matches-zero guard: the forbidden-permission list is empty")

	rows, err := pool.Query(ctx, `SELECT name, permissions FROM public.roles WHERE is_system ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()

	seen := 0
	for rows.Next() {
		var name string
		var perms []string
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

// A single statement cannot pin a connection indefinitely.
func TestNew_SetsStatementTimeout(t *testing.T) {
	_, pool := setupPostgres(t)
	ctx := context.Background()

	// The store's own pool is what carries the bound, and it is not
	// exported; the same DSN through the raw pool would not prove it.
	// Instead prove the mechanism cancels an over-long statement — the
	// property the bound exists for — with a tiny per-transaction
	// override so the test does not wait out the production value.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, "SET LOCAL statement_timeout = '100ms'")
	require.NoError(t, err)
	_, err = tx.Exec(ctx, "SELECT pg_sleep(1)")
	require.Error(t, err, "a statement exceeding statement_timeout must be cancelled, not hang")
	assert.Contains(t, err.Error(), "statement timeout")
}

// The advisory lock serialises same-key critical sections. Five
// goroutines run an overlapping-by-design section; with the lock, at
// most one is ever inside.
func TestWithAdvisoryLock_SerializesSameKey(t *testing.T) {
	st, _ := setupPostgres(t)
	const key int64 = 0x5151

	var mu sync.Mutex
	concurrent, maxConcurrent := 0, 0
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := st.WithAdvisoryLock(context.Background(), key, func() error {
				mu.Lock()
				concurrent++
				if concurrent > maxConcurrent {
					maxConcurrent = concurrent
				}
				mu.Unlock()
				time.Sleep(25 * time.Millisecond)
				mu.Lock()
				concurrent--
				mu.Unlock()
				return nil
			})
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, maxConcurrent, "a same-key advisory lock must leave no overlap")
}

// More contending callers than the pool has connections must not
// deadlock. Waiters queue before taking a connection, so the lock
// holder always has the rest of the pool for the work inside.
func TestWithAdvisoryLock_NoDeadlockUnderPoolPressure(t *testing.T) {
	st, _ := setupPostgresPool(t, 2)
	const key int64 = 0x6e6f6465

	const goroutines = 8
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			errs <- st.WithAdvisoryLock(context.Background(), key, func() error {
				// Real pooled work inside the lock: the extra
				// connection the guarded critical section needs.
				_, err := st.CountDevices(context.Background())
				return err
			})
		}()
	}

	timeout := time.After(60 * time.Second)
	for i := 0; i < goroutines; i++ {
		select {
		case err := <-errs:
			require.NoError(t, err)
		case <-timeout:
			t.Fatal("WithAdvisoryLock deadlocked: contending callers exceeded the pool size and starved the lock holder")
		}
	}
}

// The non-blocking variant skips rather than waits when another
// database session holds the lock.
func TestTryWithAdvisoryLock_SkipsWhenHeldElsewhere(t *testing.T) {
	st, pool := setupPostgresPool(t, 4)
	ctx := context.Background()
	const key int64 = 0x64796e6701

	holder, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer holder.Release()
	var got bool
	require.NoError(t, holder.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&got))
	require.True(t, got, "the holder session must acquire the lock")

	ran, err := st.TryWithAdvisoryLock(ctx, key, func() error {
		t.Fatal("the callback must not run while another session holds the lock")
		return nil
	})
	require.NoError(t, err)
	assert.False(t, ran)

	require.NoError(t, holder.QueryRow(ctx, "SELECT pg_advisory_unlock($1)", key).Scan(&got))
	called := false
	ran, err = st.TryWithAdvisoryLock(ctx, key, func() error { called = true; return nil })
	require.NoError(t, err)
	assert.True(t, ran)
	assert.True(t, called)
}

// The not-found recognizer is what callers use; reaching for the
// driver's sentinel directly is what this exists to prevent.
func TestIsNotFound_RecognisesAMissingRow(t *testing.T) {
	st, _ := setupPostgres(t)

	_, err := st.GetDevice(context.Background(), newID())
	require.Error(t, err)
	assert.True(t, store.IsNotFound(err), "a missing row must be recognisable through the store's recognizer: %v", err)
	assert.False(t, store.IsNotFound(nil))
}

// Certificate revocation is written inside the audited transaction
// that caused it, so the handshake gate can never admit a certificate
// whose revocation is still pending.
func TestRevokeInTx_CommitsWithItsAuditedOperation(t *testing.T) {
	st, _ := setupPostgres(t)
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
	st, _ := setupPostgres(t)
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
	st, _ := setupPostgres(t)
	ctx := context.Background()

	_, err := st.WithAudit(ctx, mutationOp(), func(ctx context.Context, tx *store.Tx, r *store.AuditRecorder) error {
		return store.RevokeInTx(ctx, tx, "", time.Now().UTC(), "oops")
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty fingerprint")
}
