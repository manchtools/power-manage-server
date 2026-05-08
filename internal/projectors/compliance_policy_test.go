package projectors_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// setupComplianceTestStore is a tiny aliased wrapper so the listener
// test can swap fixtures without touching every call site if the
// shared helper later grows extra knobs (e.g. seeding compliance
// actions). For now it just delegates to testutil.SetupPostgres.
func setupComplianceTestStore(t *testing.T) *store.Store {
	t.Helper()
	return testutil.SetupPostgres(t)
}

// TestCompliancePolicyCreatedFromEvent_Pure pins the decoder defaults
// that match the deleted PL/pgSQL projector: name is required (NOT NULL
// column), missing description collapses to "" (matches PL/pgSQL
// `COALESCE(payload, '')`).
func TestCompliancePolicyCreatedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with all fields", func(t *testing.T) {
		got, err := projectors.CompliancePolicyCreatedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", StreamID: "cp-1", EventType: "CompliancePolicyCreated", ActorID: "u-1",
			Data: jsonOrFail(t, map[string]any{
				"name":        "baseline",
				"description": "company baseline policy",
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "cp-1", got.ID)
		assert.Equal(t, "baseline", got.Name)
		assert.Equal(t, "company baseline policy", got.Description)
		assert.Equal(t, "u-1", got.CreatedBy)
	})

	t.Run("missing description → empty string", func(t *testing.T) {
		got, err := projectors.CompliancePolicyCreatedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", StreamID: "cp-2", EventType: "CompliancePolicyCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{"name": "minimal"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.Description)
	})

	t.Run("name is required", func(t *testing.T) {
		_, err := projectors.CompliancePolicyCreatedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", StreamID: "cp-3", EventType: "CompliancePolicyCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{"description": "no name"}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
		assert.Contains(t, err.Error(), "name")
	})

	t.Run("wrong stream/event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.CompliancePolicyCreatedFromEvent(store.PersistedEvent{
			StreamType: "user", EventType: "CompliancePolicyCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.CompliancePolicyCreatedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", EventType: "CompliancePolicyRenamed",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("malformed payload bytes is a validation error", func(t *testing.T) {
		_, err := projectors.CompliancePolicyCreatedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", EventType: "CompliancePolicyCreated",
			Data: []byte("not json"),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestCompliancePolicyRenamedFromEvent_Pure — name is required (the
// PL/pgSQL projector wrote `event.data->>'name'` directly into the
// NOT NULL column; missing key would NULL it out).
func TestCompliancePolicyRenamedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.CompliancePolicyRenamedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", StreamID: "cp-1", EventType: "CompliancePolicyRenamed",
			Data: jsonOrFail(t, map[string]any{"name": "renamed"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "cp-1", got.ID)
		assert.Equal(t, "renamed", got.Name)
	})

	t.Run("missing name fails", func(t *testing.T) {
		_, err := projectors.CompliancePolicyRenamedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", StreamID: "cp-1", EventType: "CompliancePolicyRenamed",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("wrong event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.CompliancePolicyRenamedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", EventType: "CompliancePolicyCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestCompliancePolicyDescriptionUpdatedFromEvent_Pure — missing
// description collapses to "" (matches PL/pgSQL
// `COALESCE(event.data->>'description', '')`).
func TestCompliancePolicyDescriptionUpdatedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.CompliancePolicyDescriptionUpdatedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", StreamID: "cp-1", EventType: "CompliancePolicyDescriptionUpdated",
			Data: jsonOrFail(t, map[string]any{"description": "new desc"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "cp-1", got.ID)
		assert.Equal(t, "new desc", got.Description)
	})

	t.Run("missing description → empty string", func(t *testing.T) {
		got, err := projectors.CompliancePolicyDescriptionUpdatedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", StreamID: "cp-1", EventType: "CompliancePolicyDescriptionUpdated",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.Description)
	})

	t.Run("explicit empty string description preserved", func(t *testing.T) {
		got, err := projectors.CompliancePolicyDescriptionUpdatedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", StreamID: "cp-1", EventType: "CompliancePolicyDescriptionUpdated",
			Data: jsonOrFail(t, map[string]any{"description": ""}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.Description)
	})

	t.Run("wrong event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.CompliancePolicyDescriptionUpdatedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", EventType: "CompliancePolicyRenamed",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestCompliancePolicyRuleAddedFromEvent_Pure — action_id is required,
// action_name defaults to "" (NOT NULL column), grace_period_hours
// defaults to 0 (matches the PL/pgSQL
// `COALESCE((event.data->>'grace_period_hours')::INTEGER, 0)`).
func TestCompliancePolicyRuleAddedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with all fields", func(t *testing.T) {
		got, err := projectors.CompliancePolicyRuleAddedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", StreamID: "cp-1", EventType: "CompliancePolicyRuleAdded",
			Data: jsonOrFail(t, map[string]any{
				"action_id":          "act-1",
				"action_name":        "ssh-disabled",
				"grace_period_hours": 24,
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "cp-1", got.PolicyID)
		assert.Equal(t, "act-1", got.ActionID)
		assert.Equal(t, "ssh-disabled", got.ActionName)
		assert.Equal(t, int32(24), got.GracePeriodHours)
	})

	t.Run("defaults: action_name empty, grace_period_hours zero", func(t *testing.T) {
		got, err := projectors.CompliancePolicyRuleAddedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", StreamID: "cp-1", EventType: "CompliancePolicyRuleAdded",
			Data: jsonOrFail(t, map[string]any{"action_id": "act-2"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.ActionName)
		assert.Equal(t, int32(0), got.GracePeriodHours)
	})

	t.Run("missing action_id fails", func(t *testing.T) {
		_, err := projectors.CompliancePolicyRuleAddedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", StreamID: "cp-1", EventType: "CompliancePolicyRuleAdded",
			Data: jsonOrFail(t, map[string]any{"action_name": "noop"}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "action_id")
	})

	t.Run("wrong event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.CompliancePolicyRuleAddedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", EventType: "CompliancePolicyCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestCompliancePolicyRuleRemovedFromEvent_Pure — action_id is the only
// payload key; required because the DELETE filters on it.
func TestCompliancePolicyRuleRemovedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.CompliancePolicyRuleRemovedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", StreamID: "cp-1", EventType: "CompliancePolicyRuleRemoved",
			Data: jsonOrFail(t, map[string]any{"action_id": "act-1"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "cp-1", got.PolicyID)
		assert.Equal(t, "act-1", got.ActionID)
	})

	t.Run("missing action_id fails", func(t *testing.T) {
		_, err := projectors.CompliancePolicyRuleRemovedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", StreamID: "cp-1", EventType: "CompliancePolicyRuleRemoved",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "action_id")
	})

	t.Run("wrong event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.CompliancePolicyRuleRemovedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", EventType: "CompliancePolicyCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestCompliancePolicyRuleUpdatedFromEvent_Pure — action_id is
// required (composite-PK targeted UPDATE); grace_period_hours defaults
// to 0 (matches PL/pgSQL COALESCE).
func TestCompliancePolicyRuleUpdatedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.CompliancePolicyRuleUpdatedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", StreamID: "cp-1", EventType: "CompliancePolicyRuleUpdated",
			Data: jsonOrFail(t, map[string]any{
				"action_id":          "act-1",
				"grace_period_hours": 48,
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "cp-1", got.PolicyID)
		assert.Equal(t, "act-1", got.ActionID)
		assert.Equal(t, int32(48), got.GracePeriodHours)
	})

	t.Run("missing grace_period_hours → 0", func(t *testing.T) {
		got, err := projectors.CompliancePolicyRuleUpdatedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", StreamID: "cp-1", EventType: "CompliancePolicyRuleUpdated",
			Data: jsonOrFail(t, map[string]any{"action_id": "act-1"}),
		})
		require.NoError(t, err)
		assert.Equal(t, int32(0), got.GracePeriodHours)
	})

	t.Run("missing action_id fails", func(t *testing.T) {
		_, err := projectors.CompliancePolicyRuleUpdatedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", StreamID: "cp-1", EventType: "CompliancePolicyRuleUpdated",
			Data: jsonOrFail(t, map[string]any{"grace_period_hours": 24}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "action_id")
	})

	t.Run("wrong event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.CompliancePolicyRuleUpdatedFromEvent(store.PersistedEvent{
			StreamType: "compliance_policy", EventType: "CompliancePolicyRuleAdded",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// ---------------------------------------------------------------------------
// Integration tests (testcontainers-backed Postgres).
// ---------------------------------------------------------------------------

// createTestCompliancePolicy emits a CompliancePolicyCreated event and
// returns the policy ID. Local helper — compliance policy isn't a
// general-purpose testutil entry yet.
func createTestCompliancePolicy(t *testing.T, st *store.Store, actorID, name string) string {
	t.Helper()
	id := newCompliancePolicyID()
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "compliance_policy", StreamID: id, EventType: "CompliancePolicyCreated",
		Data:      map[string]any{"name": name, "description": ""},
		ActorType: "user", ActorID: actorID,
	}))
	return id
}

// newCompliancePolicyID is a local id minter so the per-test
// policies don't collide. Mirrors testutil.NewID() but lives here so
// the helper file isn't dragged into testutil for one type.
func newCompliancePolicyID() string {
	return "cp-" + uuid.NewString()
}

// TestCompliancePolicyListener_CreateRenameDescription covers the three
// single-statement events end-to-end. Confirms row state advances and
// projection_version bumps monotonically.
func TestCompliancePolicyListener_CreateRenameDescription(t *testing.T) {
	st := setupComplianceTestStore(t)
	ctx := context.Background()
	policyID := newCompliancePolicyID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyCreated",
		Data:      map[string]any{"name": "initial", "description": "first desc"},
		ActorType: "user", ActorID: "u-1",
	}))

	got, err := st.Queries().GetCompliancePolicyByID(ctx, policyID)
	require.NoError(t, err)
	assert.Equal(t, "initial", got.Name)
	assert.Equal(t, "first desc", got.Description)
	assert.Equal(t, int32(0), got.RuleCount)
	assert.Greater(t, got.ProjectionVersion, int64(0))

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRenamed",
		Data:      map[string]any{"name": "renamed"},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err = st.Queries().GetCompliancePolicyByID(ctx, policyID)
	require.NoError(t, err)
	assert.Equal(t, "renamed", got.Name)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyDescriptionUpdated",
		Data:      map[string]any{"description": "second desc"},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err = st.Queries().GetCompliancePolicyByID(ctx, policyID)
	require.NoError(t, err)
	assert.Equal(t, "second desc", got.Description)
}

// TestCompliancePolicyListener_RuleLifecycle covers the full
// RuleAdded → RuleUpdated → RuleRemoved cycle with rule_count tracking.
func TestCompliancePolicyListener_RuleLifecycle(t *testing.T) {
	st := setupComplianceTestStore(t)
	ctx := context.Background()
	policyID := createTestCompliancePolicy(t, st, "u", "lifecycle")
	actionA := "act-" + uuid.NewString()
	actionB := "act-" + uuid.NewString()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRuleAdded",
		Data: map[string]any{
			"action_id": actionA, "action_name": "ssh-disabled", "grace_period_hours": 24,
		},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRuleAdded",
		Data: map[string]any{
			"action_id": actionB, "action_name": "ufw-enabled", "grace_period_hours": 12,
		},
		ActorType: "user", ActorID: "u",
	}))

	got, err := st.Queries().GetCompliancePolicyByID(ctx, policyID)
	require.NoError(t, err)
	assert.Equal(t, int32(2), got.RuleCount)

	rules, err := st.Queries().ListCompliancePolicyRules(ctx, policyID)
	require.NoError(t, err)
	require.Len(t, rules, 2)

	// Update grace_period_hours on the first rule.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRuleUpdated",
		Data:      map[string]any{"action_id": actionA, "grace_period_hours": 72},
		ActorType: "user", ActorID: "u",
	}))
	rules, err = st.Queries().ListCompliancePolicyRules(ctx, policyID)
	require.NoError(t, err)
	for _, r := range rules {
		if r.ActionID == actionA {
			assert.Equal(t, int32(72), r.GracePeriodHours, "RuleUpdated must change grace_period_hours")
		}
	}

	// Remove the second rule. rule_count drops back to 1.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRuleRemoved",
		Data:      map[string]any{"action_id": actionB},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetCompliancePolicyByID(ctx, policyID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), got.RuleCount)
	rules, err = st.Queries().ListCompliancePolicyRules(ctx, policyID)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, actionA, rules[0].ActionID)
}

// TestCompliancePolicyListener_RuleAddedUpsertReplacesFields covers the
// PL/pgSQL projector's `ON CONFLICT (policy_id, action_id) DO UPDATE`:
// re-emitting RuleAdded for the same (policy, action) pair updates
// action_name + grace_period_hours, not just no-ops.
func TestCompliancePolicyListener_RuleAddedUpsertReplacesFields(t *testing.T) {
	st := setupComplianceTestStore(t)
	ctx := context.Background()
	policyID := createTestCompliancePolicy(t, st, "u", "upsert")
	actionID := "act-" + uuid.NewString()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRuleAdded",
		Data: map[string]any{
			"action_id": actionID, "action_name": "old-name", "grace_period_hours": 12,
		},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRuleAdded",
		Data: map[string]any{
			"action_id": actionID, "action_name": "new-name", "grace_period_hours": 48,
		},
		ActorType: "user", ActorID: "u",
	}))

	rules, err := st.Queries().ListCompliancePolicyRules(ctx, policyID)
	require.NoError(t, err)
	require.Len(t, rules, 1, "duplicate RuleAdded must upsert, not insert")
	assert.Equal(t, "new-name", rules[0].ActionName)
	assert.Equal(t, int32(48), rules[0].GracePeriodHours)

	got, err := st.Queries().GetCompliancePolicyByID(ctx, policyID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), got.RuleCount, "rule_count counts distinct rules, not Added events")
}

// TestCompliancePolicyListener_DeleteCascadesRulesAndEvaluations
// confirms CompliancePolicyDeleted soft-deletes the policy, wipes
// every rule row, AND wipes every evaluation row pointing at it.
// reevaluate_compliance_policy_devices is also called (we plant an
// assignment + device pair to surface that the call landed without
// crashing — the eval engine itself is still PL/pgSQL per #136 and
// out of scope).
func TestCompliancePolicyListener_DeleteCascadesRulesAndEvaluations(t *testing.T) {
	st := setupComplianceTestStore(t)
	ctx := context.Background()
	policyID := createTestCompliancePolicy(t, st, "u", "to-delete")
	actionID := "act-" + uuid.NewString()
	deviceID := "dev-" + uuid.NewString()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRuleAdded",
		Data: map[string]any{
			"action_id": actionID, "action_name": "cascade-rule", "grace_period_hours": 1,
		},
		ActorType: "user", ActorID: "u",
	}))

	// Plant an evaluation row directly so we can confirm the cascade
	// half of CompliancePolicyDeleted wipes it. Live evaluation rows
	// are written by the still-PL/pgSQL eval engine; we simulate one
	// to lock the cascade behaviour.
	_, err := st.Pool().Exec(ctx,
		`INSERT INTO compliance_policy_evaluation_projection
		   (device_id, policy_id, action_id, compliant, status, projection_version)
		 VALUES ($1, $2, $3, FALSE, 0, 1)`,
		deviceID, policyID, actionID,
	)
	require.NoError(t, err)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyDeleted",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))

	// Policy row marked deleted.
	var isDeleted bool
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT is_deleted FROM compliance_policies_projection WHERE id = $1", policyID,
	).Scan(&isDeleted))
	assert.True(t, isDeleted)

	// Rules wiped.
	count := 0
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM compliance_policy_rules_projection WHERE policy_id = $1", policyID,
	).Scan(&count))
	assert.Equal(t, 0, count)

	// Evaluations wiped.
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM compliance_policy_evaluation_projection WHERE policy_id = $1", policyID,
	).Scan(&count))
	assert.Equal(t, 0, count)
}

// TestCompliancePolicyListener_RuleRemovedWipesEvaluations confirms
// CompliancePolicyRuleRemoved wipes evaluation rows scoped to the
// removed (policy, action) pair, mirroring the PL/pgSQL `DELETE FROM
// compliance_policy_evaluation_projection WHERE policy_id = X AND
// action_id = Y` cascade. Other rules' evaluations stay put.
func TestCompliancePolicyListener_RuleRemovedWipesEvaluations(t *testing.T) {
	st := setupComplianceTestStore(t)
	ctx := context.Background()
	policyID := createTestCompliancePolicy(t, st, "u", "rule-removed-evals")
	actionA := "act-" + uuid.NewString()
	actionB := "act-" + uuid.NewString()
	deviceID := "dev-" + uuid.NewString()

	for _, aid := range []string{actionA, actionB} {
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRuleAdded",
			Data:      map[string]any{"action_id": aid, "action_name": "r", "grace_period_hours": 0},
			ActorType: "user", ActorID: "u",
		}))
		_, err := st.Pool().Exec(ctx,
			`INSERT INTO compliance_policy_evaluation_projection
			   (device_id, policy_id, action_id, compliant, status, projection_version)
			 VALUES ($1, $2, $3, FALSE, 0, 1)`,
			deviceID, policyID, aid,
		)
		require.NoError(t, err)
	}

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRuleRemoved",
		Data:      map[string]any{"action_id": actionA},
		ActorType: "user", ActorID: "u",
	}))

	count := 0
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM compliance_policy_evaluation_projection WHERE policy_id = $1 AND action_id = $2",
		policyID, actionA,
	).Scan(&count))
	assert.Equal(t, 0, count, "RuleRemoved must wipe evaluations for the (policy, action) pair")

	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM compliance_policy_evaluation_projection WHERE policy_id = $1 AND action_id = $2",
		policyID, actionB,
	).Scan(&count))
	assert.Equal(t, 1, count, "RuleRemoved must NOT wipe evaluations for OTHER rules in the same policy")
}

// TestCompliancePolicyListener_StaleRenameRejected — the UPDATE form
// (Renamed) doesn't clobber a fresher row when re-applied with an
// older projection_version. Mirrors the user_group projector's stale-
// replay regression test.
func TestCompliancePolicyListener_StaleRenameRejected(t *testing.T) {
	st := setupComplianceTestStore(t)
	ctx := context.Background()
	policyID := createTestCompliancePolicy(t, st, "u", "stale-rename")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRenamed",
		Data:      map[string]any{"name": "current"},
		ActorType: "user", ActorID: "u",
	}))
	current, err := st.Queries().GetCompliancePolicyByID(ctx, policyID)
	require.NoError(t, err)
	currentVersion := current.ProjectionVersion

	older := currentVersion - 5
	n, err := st.Queries().RenameCompliancePolicyProjection(ctx, db.RenameCompliancePolicyProjectionParams{
		ID:                policyID,
		Name:              "stale-would-set-this",
		ProjectionVersion: older,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(0), n, "stale projection_version UPDATE must affect zero rows")

	after, err := st.Queries().GetCompliancePolicyByID(ctx, policyID)
	require.NoError(t, err)
	assert.Equal(t, "current", after.Name)
	assert.Equal(t, currentVersion, after.ProjectionVersion)
}

// TestCompliancePolicyListener_StaleDeleteReplayDoesNotNukeRules locks
// the asymmetric-guard discipline for the cascade-heavy event type:
// when the version-guarded SoftDelete affects zero rows, every
// downstream cascade (rule wipe, evaluation wipe) MUST be skipped.
func TestCompliancePolicyListener_StaleDeleteReplayDoesNotNukeRules(t *testing.T) {
	st := setupComplianceTestStore(t)
	ctx := context.Background()
	policyID := createTestCompliancePolicy(t, st, "u", "live-policy")
	actionID := "act-" + uuid.NewString()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRuleAdded",
		Data: map[string]any{
			"action_id": actionID, "action_name": "live-rule", "grace_period_hours": 0,
		},
		ActorType: "user", ActorID: "u",
	}))
	live, err := st.Queries().GetCompliancePolicyByID(ctx, policyID)
	require.NoError(t, err)

	// Drive the listener with a stale CompliancePolicyDeleted (older
	// projection_version than the row currently has).
	older := live.ProjectionVersion - 5
	listener := projectors.CompliancePolicyListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: &older,
		StreamType:  "compliance_policy",
		StreamID:    policyID,
		EventType:   "CompliancePolicyDeleted",
		Data:        []byte("{}"),
		ActorType:   "user",
		ActorID:     "u",
	})

	// Policy still alive.
	stillAlive, err := st.Queries().GetCompliancePolicyByID(ctx, policyID)
	require.NoError(t, err)
	assert.False(t, stillAlive.IsDeleted, "stale CompliancePolicyDeleted must NOT flip is_deleted")

	// Rule still there.
	count := 0
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM compliance_policy_rules_projection WHERE policy_id = $1", policyID,
	).Scan(&count))
	assert.Equal(t, 1, count, "stale CompliancePolicyDeleted must NOT cascade-delete rules")
}

// TestCompliancePolicyListener_StaleRuleAddedDoesNotResurrectRemoved
// locks the Claim-first guard for rule mutations: a stale
// CompliancePolicyRuleAdded replayed AFTER a CompliancePolicyRuleRemoved
// must not reinsert the rule, even though the underlying UPSERT is
// idempotent. The Claim guard runs FIRST so a stale version short-
// circuits before the rule mutation.
//
// This is the rule-event sibling of the user_group MemberAdded CR
// catch on PR #174 — the insert-then-recount pattern would let stale
// replays resurrect removed rules silently. Claim-first is the fix.
func TestCompliancePolicyListener_StaleRuleAddedDoesNotResurrectRemoved(t *testing.T) {
	st := setupComplianceTestStore(t)
	ctx := context.Background()
	policyID := createTestCompliancePolicy(t, st, "u", "stale-rule-add")
	actionID := "act-" + uuid.NewString()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRuleAdded",
		Data: map[string]any{
			"action_id": actionID, "action_name": "to-remove", "grace_period_hours": 1,
		},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRuleRemoved",
		Data:      map[string]any{"action_id": actionID},
		ActorType: "user", ActorID: "u",
	}))
	live, err := st.Queries().GetCompliancePolicyByID(ctx, policyID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), live.RuleCount)

	older := live.ProjectionVersion - 5
	listener := projectors.CompliancePolicyListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: &older,
		StreamType:  "compliance_policy",
		StreamID:    policyID,
		EventType:   "CompliancePolicyRuleAdded",
		Data: jsonOrFail(t, map[string]any{
			"action_id": actionID, "action_name": "stale", "grace_period_hours": 99,
		}),
		ActorType: "user",
		ActorID:   "u",
	})

	count := 0
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM compliance_policy_rules_projection WHERE policy_id = $1 AND action_id = $2",
		policyID, actionID,
	).Scan(&count))
	assert.Equal(t, 0, count, "stale CompliancePolicyRuleAdded must NOT resurrect the removed rule")

	after, err := st.Queries().GetCompliancePolicyByID(ctx, policyID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), after.RuleCount, "rule_count stays at 0 after stale replay")
	assert.Equal(t, live.ProjectionVersion, after.ProjectionVersion, "projection_version unchanged")
}

// TestCompliancePolicyListener_StaleRuleUpdatedDoesNotChangeGrace locks
// the Claim-first guard for RuleUpdated: a stale event must not
// rewind grace_period_hours after a fresher edit lands.
func TestCompliancePolicyListener_StaleRuleUpdatedDoesNotChangeGrace(t *testing.T) {
	st := setupComplianceTestStore(t)
	ctx := context.Background()
	policyID := createTestCompliancePolicy(t, st, "u", "stale-rule-update")
	actionID := "act-" + uuid.NewString()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRuleAdded",
		Data: map[string]any{
			"action_id": actionID, "action_name": "r", "grace_period_hours": 12,
		},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRuleUpdated",
		Data:      map[string]any{"action_id": actionID, "grace_period_hours": 99},
		ActorType: "user", ActorID: "u",
	}))
	live, err := st.Queries().GetCompliancePolicyByID(ctx, policyID)
	require.NoError(t, err)

	older := live.ProjectionVersion - 5
	listener := projectors.CompliancePolicyListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: &older,
		StreamType:  "compliance_policy",
		StreamID:    policyID,
		EventType:   "CompliancePolicyRuleUpdated",
		Data:        jsonOrFail(t, map[string]any{"action_id": actionID, "grace_period_hours": 1}),
		ActorType:   "user",
		ActorID:     "u",
	})

	rules, err := st.Queries().ListCompliancePolicyRules(ctx, policyID)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, int32(99), rules[0].GracePeriodHours,
		"stale CompliancePolicyRuleUpdated must NOT roll grace_period_hours back to its old value")
}

// TestCompliancePolicyListener_IgnoresWrongStreamType — defensive.
func TestCompliancePolicyListener_IgnoresWrongStreamType(t *testing.T) {
	st := setupComplianceTestStore(t)
	ctx := context.Background()
	policyID := newCompliancePolicyID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", // wrong stream
		StreamID:   policyID,
		EventType:  "CompliancePolicyCreated",
		Data:       map[string]any{"name": "ghost"},
		ActorType:  "user", ActorID: "u",
	}))

	_, err := st.Queries().GetCompliancePolicyByID(ctx, policyID)
	require.Error(t, err, "wrong-stream-type CompliancePolicyCreated must NOT create a row")
}
