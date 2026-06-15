package compliance_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/compliance"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// seedRule assigns a compliance policy rule (action + grace) to a device by
// inserting directly into the projections the evaluator reads — no event replay
// needed for a focused evaluator test.
func seedRule(t *testing.T, st *store.Store, deviceID, policyID, actionID string, graceHours int32) {
	t.Helper()
	ctx := context.Background()
	pool := st.TestingPool()
	_, err := pool.Exec(ctx,
		`INSERT INTO compliance_policies_projection (id, name) VALUES ($1, 'test-policy') ON CONFLICT (id) DO NOTHING`, policyID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`INSERT INTO compliance_policy_rules_projection (policy_id, action_id, grace_period_hours) VALUES ($1, $2, $3)`,
		policyID, actionID, graceHours)
	require.NoError(t, err)
	// One policy→device assignment regardless of how many rules the policy has.
	_, err = pool.Exec(ctx,
		`INSERT INTO assignments_projection (id, source_type, source_id, target_type, target_id)
		 VALUES ($1, 'compliance_policy', $2, 'device', $3)
		 ON CONFLICT (source_type, source_id, target_type, target_id) DO NOTHING`,
		testutil.NewID(), policyID, deviceID)
	require.NoError(t, err)
}

// seedResult records the latest compliance check result for (device, action).
func seedResult(t *testing.T, st *store.Store, deviceID, actionID string, compliant bool, checkedAt time.Time) {
	t.Helper()
	_, err := st.TestingPool().Exec(context.Background(),
		`INSERT INTO compliance_results_projection (device_id, action_id, compliant, checked_at)
		 VALUES ($1, $2, $3, $4)`,
		deviceID, actionID, compliant, checkedAt)
	require.NoError(t, err)
}

func deviceStatus(t *testing.T, st *store.Store, deviceID string) (status, total, passing int32) {
	t.Helper()
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		`SELECT compliance_status, compliance_total, compliance_passing FROM devices_projection WHERE id = $1`,
		deviceID).Scan(&status, &total, &passing))
	return
}

func evalFirstFailedAt(t *testing.T, st *store.Store, deviceID, policyID, actionID string) *time.Time {
	t.Helper()
	var ts *time.Time
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		`SELECT first_failed_at FROM compliance_policy_evaluation_projection
		 WHERE device_id=$1 AND policy_id=$2 AND action_id=$3`,
		deviceID, policyID, actionID).Scan(&ts))
	return ts
}

// TestEvaluator_GracePeriodBoundary pins the IN_GRACE_PERIOD -> NON_COMPLIANT
// transition at exactly first_failed_at + grace, evaluated on both sides of the
// boundary with the clock seam.
func TestEvaluator_GracePeriodBoundary(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	deviceID := testutil.CreateTestDevice(t, st, "grace-host")
	policyID, actionID := testutil.NewID(), testutil.NewID()
	seedRule(t, st, deviceID, policyID, actionID, 24) // 24h grace

	t0 := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	seedResult(t, st, deviceID, actionID, false, t0) // failing check

	e := compliance.New(slog.Default())

	// At t0: failing, first_failed_at seeded = t0, within grace -> IN_GRACE.
	e.SetClock(func() time.Time { return t0 })
	require.NoError(t, e.EvaluateInTx(ctx, st.Queries(), deviceID))
	status, _, _ := deviceStatus(t, st, deviceID)
	assert.Equal(t, compliance.StatusInGracePeriod, status, "fresh failure within grace must be IN_GRACE_PERIOD")

	// One nanosecond before the boundary: still in grace.
	e.SetClock(func() time.Time { return t0.Add(24 * time.Hour).Add(-time.Nanosecond) })
	require.NoError(t, e.EvaluateInTx(ctx, st.Queries(), deviceID))
	status, _, _ = deviceStatus(t, st, deviceID)
	assert.Equal(t, compliance.StatusInGracePeriod, status, "just before grace expiry must still be IN_GRACE_PERIOD")

	// Exactly at the boundary: graduates to NON_COMPLIANT (now is NOT before graceUntil).
	e.SetClock(func() time.Time { return t0.Add(24 * time.Hour) })
	require.NoError(t, e.EvaluateInTx(ctx, st.Queries(), deviceID))
	status, _, _ = deviceStatus(t, st, deviceID)
	assert.Equal(t, compliance.StatusNonCompliant, status, "at exactly first_failed_at+grace must be NON_COMPLIANT")
}

// TestEvaluator_FirstFailedAtPreservedAcrossReeval pins that the first-failed
// timestamp sticks across repeated failing evaluations (it is not re-seeded to
// the later now), which is what makes the grace window anchored.
func TestEvaluator_FirstFailedAtPreservedAcrossReeval(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	deviceID := testutil.CreateTestDevice(t, st, "ffa-host")
	policyID, actionID := testutil.NewID(), testutil.NewID()
	seedRule(t, st, deviceID, policyID, actionID, 24)

	t0 := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	seedResult(t, st, deviceID, actionID, false, t0)

	e := compliance.New(slog.Default())
	e.SetClock(func() time.Time { return t0 })
	require.NoError(t, e.EvaluateInTx(ctx, st.Queries(), deviceID))
	first := evalFirstFailedAt(t, st, deviceID, policyID, actionID)
	require.NotNil(t, first)
	require.WithinDuration(t, t0, *first, time.Second)

	// Re-evaluate later — still failing. first_failed_at must NOT move.
	e.SetClock(func() time.Time { return t0.Add(5 * time.Hour) })
	require.NoError(t, e.EvaluateInTx(ctx, st.Queries(), deviceID))
	again := evalFirstFailedAt(t, st, deviceID, policyID, actionID)
	require.NotNil(t, again)
	assert.WithinDuration(t, *first, *again, time.Second, "first_failed_at must be preserved across re-evaluation, not re-seeded to the later now")
}

// TestEvaluator_StatusRollupPrecedence pins the device-level rollup: any
// NON_COMPLIANT rule wins; else any IN_GRACE wins; all compliant -> COMPLIANT;
// an UNKNOWN (no result yet) keeps the device out of COMPLIANT. Also checks the
// total/passing counters.
func TestEvaluator_StatusRollupPrecedence(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	t.Run("non-compliant beats grace and compliant", func(t *testing.T) {
		st := testutil.SetupPostgres(t)
		deviceID := testutil.CreateTestDevice(t, st, "rollup-nc")
		pol := testutil.NewID()
		aOK, aGrace, aBad := testutil.NewID(), testutil.NewID(), testutil.NewID()
		seedRule(t, st, deviceID, pol, aOK, 0)
		seedRule(t, st, deviceID, pol, aGrace, 24)
		seedRule(t, st, deviceID, pol, aBad, 0) // grace 0 -> immediately non-compliant
		seedResult(t, st, deviceID, aOK, true, now)
		seedResult(t, st, deviceID, aGrace, false, now)
		seedResult(t, st, deviceID, aBad, false, now)

		e := compliance.New(slog.Default())
		e.SetClock(func() time.Time { return now })
		require.NoError(t, e.EvaluateInTx(context.Background(), st.Queries(), deviceID))
		status, total, passing := deviceStatus(t, st, deviceID)
		assert.Equal(t, compliance.StatusNonCompliant, status)
		assert.Equal(t, int32(3), total)
		assert.Equal(t, int32(1), passing)
	})

	t.Run("grace beats compliant when none non-compliant", func(t *testing.T) {
		st := testutil.SetupPostgres(t)
		deviceID := testutil.CreateTestDevice(t, st, "rollup-grace")
		pol := testutil.NewID()
		aOK, aGrace := testutil.NewID(), testutil.NewID()
		seedRule(t, st, deviceID, pol, aOK, 0)
		seedRule(t, st, deviceID, pol, aGrace, 24)
		seedResult(t, st, deviceID, aOK, true, now)
		seedResult(t, st, deviceID, aGrace, false, now)

		e := compliance.New(slog.Default())
		e.SetClock(func() time.Time { return now })
		require.NoError(t, e.EvaluateInTx(context.Background(), st.Queries(), deviceID))
		status, _, passing := deviceStatus(t, st, deviceID)
		assert.Equal(t, compliance.StatusInGracePeriod, status)
		assert.Equal(t, int32(1), passing)
	})

	t.Run("all compliant -> COMPLIANT", func(t *testing.T) {
		st := testutil.SetupPostgres(t)
		deviceID := testutil.CreateTestDevice(t, st, "rollup-ok")
		pol := testutil.NewID()
		a1, a2 := testutil.NewID(), testutil.NewID()
		seedRule(t, st, deviceID, pol, a1, 0)
		seedRule(t, st, deviceID, pol, a2, 0)
		seedResult(t, st, deviceID, a1, true, now)
		seedResult(t, st, deviceID, a2, true, now)

		e := compliance.New(slog.Default())
		e.SetClock(func() time.Time { return now })
		require.NoError(t, e.EvaluateInTx(context.Background(), st.Queries(), deviceID))
		status, total, passing := deviceStatus(t, st, deviceID)
		assert.Equal(t, compliance.StatusCompliant, status)
		assert.Equal(t, int32(2), total)
		assert.Equal(t, int32(2), passing)
	})

	t.Run("an UNKNOWN rule keeps the device out of COMPLIANT", func(t *testing.T) {
		st := testutil.SetupPostgres(t)
		deviceID := testutil.CreateTestDevice(t, st, "rollup-unknown")
		pol := testutil.NewID()
		aOK, aNoResult := testutil.NewID(), testutil.NewID()
		seedRule(t, st, deviceID, pol, aOK, 0)
		seedRule(t, st, deviceID, pol, aNoResult, 0) // no result seeded -> UNKNOWN
		seedResult(t, st, deviceID, aOK, true, now)

		e := compliance.New(slog.Default())
		e.SetClock(func() time.Time { return now })
		require.NoError(t, e.EvaluateInTx(context.Background(), st.Queries(), deviceID))
		status, _, _ := deviceStatus(t, st, deviceID)
		assert.NotEqual(t, compliance.StatusCompliant, status, "an unevaluated rule must keep the device out of COMPLIANT")
	})
}

// TestEvaluator_RecalculateOnlyWhenNoPolicies pins the no-rules fallback that
// counts compliance_results directly: total==0 -> UNKNOWN, passing==total ->
// COMPLIANT, else NON_COMPLIANT.
func TestEvaluator_RecalculateOnlyWhenNoPolicies(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	t.Run("no results -> UNKNOWN", func(t *testing.T) {
		st := testutil.SetupPostgres(t)
		deviceID := testutil.CreateTestDevice(t, st, "recalc-unknown")
		e := compliance.New(slog.Default())
		e.SetClock(func() time.Time { return now })
		require.NoError(t, e.EvaluateInTx(context.Background(), st.Queries(), deviceID))
		status, _, _ := deviceStatus(t, st, deviceID)
		assert.Equal(t, compliance.StatusUnknown, status)
	})

	t.Run("all results passing -> COMPLIANT", func(t *testing.T) {
		st := testutil.SetupPostgres(t)
		deviceID := testutil.CreateTestDevice(t, st, "recalc-ok")
		seedResult(t, st, deviceID, testutil.NewID(), true, now)
		seedResult(t, st, deviceID, testutil.NewID(), true, now)
		e := compliance.New(slog.Default())
		e.SetClock(func() time.Time { return now })
		require.NoError(t, e.EvaluateInTx(context.Background(), st.Queries(), deviceID))
		status, _, _ := deviceStatus(t, st, deviceID)
		assert.Equal(t, compliance.StatusCompliant, status)
	})

	t.Run("a failing result -> NON_COMPLIANT", func(t *testing.T) {
		st := testutil.SetupPostgres(t)
		deviceID := testutil.CreateTestDevice(t, st, "recalc-bad")
		seedResult(t, st, deviceID, testutil.NewID(), true, now)
		seedResult(t, st, deviceID, testutil.NewID(), false, now)
		e := compliance.New(slog.Default())
		e.SetClock(func() time.Time { return now })
		require.NoError(t, e.EvaluateInTx(context.Background(), st.Queries(), deviceID))
		status, _, _ := deviceStatus(t, st, deviceID)
		assert.Equal(t, compliance.StatusNonCompliant, status)
	})
}
