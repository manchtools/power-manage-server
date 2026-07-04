package projectors_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestActionCreatedFromEvent_Pure pins the decoder defaults that match
// the deleted PL/pgSQL projector: missing description → nil pointer
// (NULL on the column); missing action_type / desired_state → 0;
// missing params → `{}`; missing timeout_seconds → 300; missing
// is_system → false; missing schedule → nil bytes.
func TestActionCreatedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with all fields", func(t *testing.T) {
		got, err := projectors.ActionCreatedFromEvent(store.PersistedEvent{
			StreamType: "action", StreamID: "act-1", EventType: "ActionCreated", ActorID: "u-1",
			Data: jsonOrFail(t, map[string]any{
				"name":            "install-curl",
				"description":     "package install",
				"action_type":     2,
				"desired_state":   1,
				"params":          map[string]any{"package": "curl"},
				"timeout_seconds": 600,
				"is_system":       true,
				"schedule":        map[string]any{"interval_hours": 4},
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "act-1", got.ID)
		assert.Equal(t, "install-curl", got.Name)
		require.NotNil(t, got.Description)
		assert.Equal(t, "package install", *got.Description)
		assert.Equal(t, int32(2), got.ActionType)
		assert.Equal(t, int32(1), got.DesiredState)
		assert.JSONEq(t, `{"package":"curl"}`, string(got.Params))
		assert.Equal(t, int32(600), got.TimeoutSeconds)
		assert.True(t, got.IsSystem)
		assert.JSONEq(t, `{"interval_hours":4}`, string(got.Schedule))
		assert.Equal(t, "u-1", got.CreatedBy)
	})

	t.Run("defaults: params={}, timeout=300, action_type=0, is_system=false", func(t *testing.T) {
		got, err := projectors.ActionCreatedFromEvent(store.PersistedEvent{
			StreamType: "action", StreamID: "act-2", EventType: "ActionCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{"name": "minimal"}),
		})
		require.NoError(t, err)
		assert.Nil(t, got.Description)
		assert.Equal(t, int32(0), got.ActionType)
		assert.Equal(t, int32(0), got.DesiredState)
		assert.JSONEq(t, `{}`, string(got.Params))
		assert.Equal(t, int32(300), got.TimeoutSeconds)
		assert.False(t, got.IsSystem)
		assert.Nil(t, got.Schedule)
	})

	t.Run("name is required", func(t *testing.T) {
		_, err := projectors.ActionCreatedFromEvent(store.PersistedEvent{
			StreamType: "action", StreamID: "act-3", EventType: "ActionCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{"description": "no name"}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
		assert.Contains(t, err.Error(), "name")
	})

	t.Run("wrong stream/event → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.ActionCreatedFromEvent(store.PersistedEvent{
			StreamType: "definition", EventType: "ActionCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.ActionCreatedFromEvent(store.PersistedEvent{
			StreamType: "action", EventType: "ActionRenamed",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("malformed payload bytes is a validation error", func(t *testing.T) {
		_, err := projectors.ActionCreatedFromEvent(store.PersistedEvent{
			StreamType: "action", EventType: "ActionCreated",
			Data: []byte("not json"),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestActionRenamedFromEvent_Pure — name is required.
func TestActionRenamedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.ActionRenamedFromEvent(store.PersistedEvent{
			StreamType: "action", StreamID: "act-1", EventType: "ActionRenamed",
			Data: jsonOrFail(t, map[string]any{"name": "renamed"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "renamed", got.Name)
	})
	t.Run("missing name fails", func(t *testing.T) {
		_, err := projectors.ActionRenamedFromEvent(store.PersistedEvent{
			StreamType: "action", StreamID: "act-1", EventType: "ActionRenamed",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
	})
	t.Run("wrong event → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.ActionRenamedFromEvent(store.PersistedEvent{
			StreamType: "action", EventType: "ActionCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestActionDescriptionUpdatedFromEvent_Pure — *string preserves the
// absent-vs-empty distinction (nil vs &"") so the nullable column gets
// the correct value.
func TestActionDescriptionUpdatedFromEvent_Pure(t *testing.T) {
	t.Run("explicit description", func(t *testing.T) {
		got, err := projectors.ActionDescriptionUpdatedFromEvent(store.PersistedEvent{
			StreamType: "action", StreamID: "act-1", EventType: "ActionDescriptionUpdated",
			Data: jsonOrFail(t, map[string]any{"description": "new"}),
		})
		require.NoError(t, err)
		require.NotNil(t, got.Description)
		assert.Equal(t, "new", *got.Description)
	})
	t.Run("missing description → nil pointer (NULL)", func(t *testing.T) {
		got, err := projectors.ActionDescriptionUpdatedFromEvent(store.PersistedEvent{
			StreamType: "action", StreamID: "act-1", EventType: "ActionDescriptionUpdated",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Nil(t, got.Description)
	})
	t.Run("explicit empty string round-trips as &\"\"", func(t *testing.T) {
		got, err := projectors.ActionDescriptionUpdatedFromEvent(store.PersistedEvent{
			StreamType: "action", StreamID: "act-1", EventType: "ActionDescriptionUpdated",
			Data: jsonOrFail(t, map[string]any{"description": ""}),
		})
		require.NoError(t, err)
		require.NotNil(t, got.Description)
		assert.Equal(t, "", *got.Description)
	})
}

// TestActionParamsUpdatedFromEvent_Pure — every field is optional and
// nil means "preserve the existing column value". The PL/pgSQL projector
// did `COALESCE(payload, existing)` per-field; the decoder surfaces
// absence as nil pointers / empty bytes so the SQL COALESCE picks
// `existing`.
func TestActionParamsUpdatedFromEvent_Pure(t *testing.T) {
	t.Run("all fields present", func(t *testing.T) {
		got, err := projectors.ActionParamsUpdatedFromEvent(store.PersistedEvent{
			StreamType: "action", StreamID: "act-1", EventType: "ActionParamsUpdated",
			Data: jsonOrFail(t, map[string]any{
				"params":          map[string]any{"k": "v"},
				"timeout_seconds": 99,
				"desired_state":   2,
				"schedule":        map[string]any{"cron": "0 * * * *"},
			}),
		})
		require.NoError(t, err)
		assert.JSONEq(t, `{"k":"v"}`, string(got.Params))
		require.NotNil(t, got.TimeoutSeconds)
		assert.Equal(t, int32(99), *got.TimeoutSeconds)
		require.NotNil(t, got.DesiredState)
		assert.Equal(t, int32(2), *got.DesiredState)
		assert.JSONEq(t, `{"cron":"0 * * * *"}`, string(got.Schedule))
	})
	t.Run("all fields missing → all nil/empty (preserve existing)", func(t *testing.T) {
		got, err := projectors.ActionParamsUpdatedFromEvent(store.PersistedEvent{
			StreamType: "action", StreamID: "act-1", EventType: "ActionParamsUpdated",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Nil(t, got.Params)
		assert.Nil(t, got.TimeoutSeconds)
		assert.Nil(t, got.DesiredState)
		assert.Nil(t, got.Schedule)
	})
}

// TestActionDeletedFromEvent_Pure — payload-less validator.
func TestActionDeletedFromEvent_Pure(t *testing.T) {
	id, err := projectors.ActionDeletedFromEvent(store.PersistedEvent{
		StreamType: "action", StreamID: "act-1", EventType: "ActionDeleted",
	})
	require.NoError(t, err)
	assert.Equal(t, "act-1", id)
	_, err = projectors.ActionDeletedFromEvent(store.PersistedEvent{
		StreamType: "definition", EventType: "ActionDeleted",
	})
	assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
}

// TestActionListener_FullLifecycle covers the four single-statement
// action events end-to-end.
func TestActionListener_FullLifecycle(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	actionID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action", StreamID: actionID, EventType: "ActionCreated",
		Data: map[string]any{
			"name":            "initial",
			"description":     "first",
			"action_type":     1,
			"params":          map[string]any{"k": "v"},
			"timeout_seconds": 120,
		},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err := st.Queries().GetActionByID(ctx, actionID)
	require.NoError(t, err)
	assert.Equal(t, "initial", got.Name)
	require.NotNil(t, got.Description)
	assert.Equal(t, "first", *got.Description)
	assert.Equal(t, int32(1), got.ActionType)
	assert.Equal(t, int32(120), got.TimeoutSeconds)
	assert.Greater(t, got.ProjectionVersion, int64(0))

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action", StreamID: actionID, EventType: "ActionRenamed",
		Data:      map[string]any{"name": "renamed"},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err = st.Queries().GetActionByID(ctx, actionID)
	require.NoError(t, err)
	assert.Equal(t, "renamed", got.Name)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action", StreamID: actionID, EventType: "ActionParamsUpdated",
		Data: map[string]any{
			"timeout_seconds": 30,
			// params + desired_state + schedule omitted: must be preserved.
		},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err = st.Queries().GetActionByID(ctx, actionID)
	require.NoError(t, err)
	assert.Equal(t, int32(30), got.TimeoutSeconds, "timeout updated")
	assert.JSONEq(t, `{"k":"v"}`, string(got.Params),
		"params NOT in payload must be preserved (PL/pgSQL COALESCE semantic)")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action", StreamID: actionID, EventType: "ActionDeleted",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u-1",
	}))
	_, err = st.Queries().GetActionByID(ctx, actionID)
	require.Error(t, err, "GetActionByID filters out is_deleted=TRUE rows")
}

// TestActionListener_RenameCascadesIntoComplianceRule confirms the
// cross-stream cascade: ActionRenamed updates compliance_policy_rules
// .action_name as a denormalised projection mirror.
func TestActionListener_RenameCascadesIntoComplianceRule(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	actionID := testutil.NewID()
	policyID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action", StreamID: actionID, EventType: "ActionCreated",
		Data:      map[string]any{"name": "before-rename"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyCreated",
		Data:      map[string]any{"name": "p1", "description": ""},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRuleAdded",
		Data: map[string]any{
			"action_id":          actionID,
			"action_name":        "before-rename",
			"grace_period_hours": 0,
		},
		ActorType: "user", ActorID: "u",
	}))

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action", StreamID: actionID, EventType: "ActionRenamed",
		Data:      map[string]any{"name": "after-rename"},
		ActorType: "user", ActorID: "u",
	}))

	var actionName string
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		`SELECT action_name FROM compliance_policy_rules_projection
		 WHERE policy_id = $1 AND action_id = $2`, policyID, actionID,
	).Scan(&actionName))
	assert.Equal(t, "after-rename", actionName,
		"ActionRenamed must cascade into compliance_policy_rules.action_name")
}

// TestActionListener_DeletedCascadesAcrossEverything covers the full
// 4-table cascade: action_set decrement + member wipe, compliance rule
// delete + per-policy rule_count decrement, evaluation wipe, results
// wipe.
func TestActionListener_DeletedCascadesAcrossEverything(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	actionID := testutil.NewID()
	setID := testutil.NewID()
	policyID := testutil.NewID()
	deviceID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action", StreamID: actionID, EventType: "ActionCreated",
		Data:      map[string]any{"name": "doomed"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetCreated",
		Data:      map[string]any{"name": "set-with-doomed"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetMemberAdded",
		Data:      map[string]any{"action_id": actionID},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyCreated",
		Data:      map[string]any{"name": "p1", "description": ""},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRuleAdded",
		Data: map[string]any{
			"action_id":          actionID,
			"action_name":        "doomed",
			"grace_period_hours": 0,
		},
		ActorType: "user", ActorID: "u",
	}))
	// Plant a compliance result + an evaluation row directly so we
	// don't have to drive the full eval engine to exercise the wipes.
	_, err := st.TestingPool().Exec(ctx,
		`INSERT INTO compliance_results_projection (device_id, action_id, action_name, compliant, checked_at)
		 VALUES ($1, $2, $3, TRUE, NOW())`,
		deviceID, actionID, "doomed",
	)
	require.NoError(t, err)
	_, err = st.TestingPool().Exec(ctx,
		`INSERT INTO compliance_policy_evaluation_projection (device_id, policy_id, action_id, compliant, checked_at)
		 VALUES ($1, $2, $3, TRUE, NOW())`,
		deviceID, policyID, actionID,
	)
	require.NoError(t, err)

	// Verify pre-state: parent action_set has member_count == 1, policy
	// has rule_count == 1.
	beforeSet, err := st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), beforeSet.MemberCount)
	beforePolicy, err := st.Queries().GetCompliancePolicyByID(ctx, policyID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), beforePolicy.RuleCount)

	// Delete the action.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action", StreamID: actionID, EventType: "ActionDeleted",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))

	// action_set member wiped + member_count decremented.
	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM action_set_members_projection WHERE action_id = $1", actionID,
	).Scan(&count))
	assert.Equal(t, 0, count, "action_set members for deleted action wiped")
	afterSet, err := st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), afterSet.MemberCount, "parent action_set member_count decremented")

	// Compliance rules wiped + per-policy rule_count decremented.
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM compliance_policy_rules_projection WHERE action_id = $1", actionID,
	).Scan(&count))
	assert.Equal(t, 0, count, "compliance rules for deleted action wiped")
	afterPolicy, err := st.Queries().GetCompliancePolicyByID(ctx, policyID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), afterPolicy.RuleCount, "policy rule_count decremented")

	// Evaluation + result rows wiped.
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM compliance_policy_evaluation_projection WHERE action_id = $1", actionID,
	).Scan(&count))
	assert.Equal(t, 0, count, "evaluation rows for deleted action wiped")
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM compliance_results_projection WHERE action_id = $1", actionID,
	).Scan(&count))
	assert.Equal(t, 0, count, "result rows for deleted action wiped")
}

// TestActionListener_StaleDeleteReplayDoesNotNukeCascade locks the
// asymmetric-guard discipline for the most cascade-heavy event type:
// when the version-guarded SoftDelete affects zero rows, every
// downstream cascade (action_set member decrement, compliance rule
// delete + recount, evaluation delete, results delete) MUST be
// skipped.
func TestActionListener_StaleDeleteReplayDoesNotNukeCascade(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	actionID := testutil.NewID()
	setID := testutil.NewID()
	policyID := testutil.NewID()
	deviceID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action", StreamID: actionID, EventType: "ActionCreated",
		Data:      map[string]any{"name": "live"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetCreated",
		Data:      map[string]any{"name": "live-set"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetMemberAdded",
		Data:      map[string]any{"action_id": actionID},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyCreated",
		Data:      map[string]any{"name": "live-policy"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy", StreamID: policyID, EventType: "CompliancePolicyRuleAdded",
		Data: map[string]any{
			"action_id":   actionID,
			"action_name": "live",
		},
		ActorType: "user", ActorID: "u",
	}))
	_, err := st.TestingPool().Exec(ctx,
		`INSERT INTO compliance_results_projection (device_id, action_id, action_name, compliant, checked_at)
		 VALUES ($1, $2, $3, TRUE, NOW())`,
		deviceID, actionID, "live",
	)
	require.NoError(t, err)

	live, err := st.Queries().GetActionByID(ctx, actionID)
	require.NoError(t, err)

	// Drive the listener directly with a stale ActionDeleted (older
	// projection_version than the row currently has).
	older := live.ProjectionVersion - 5
	staleAt := *live.UpdatedAt
	listener := projectors.ActionListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          ulid.Make().String(),
		SequenceNum: older,
		StreamType:  "action",
		StreamID:    actionID,
		EventType:   "ActionDeleted",
		Data:        []byte("{}"),
		ActorType:   "user",
		ActorID:     "u",
		OccurredAt:  staleAt,
	})

	// Action still alive.
	stillAlive, err := st.Queries().GetActionByID(ctx, actionID)
	require.NoError(t, err)
	assert.False(t, stillAlive.IsDeleted, "stale ActionDeleted must NOT flip is_deleted")

	// action_set member NOT wiped, member_count NOT decremented.
	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM action_set_members_projection WHERE action_id = $1", actionID,
	).Scan(&count))
	assert.Equal(t, 1, count, "stale ActionDeleted must NOT cascade-delete action_set members")
	afterSet, err := st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), afterSet.MemberCount,
		"stale ActionDeleted must NOT decrement live action_set member_count")

	// Compliance rule NOT wiped, rule_count NOT decremented.
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM compliance_policy_rules_projection WHERE action_id = $1", actionID,
	).Scan(&count))
	assert.Equal(t, 1, count, "stale ActionDeleted must NOT cascade-delete compliance rules")
	afterPolicy, err := st.Queries().GetCompliancePolicyByID(ctx, policyID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), afterPolicy.RuleCount,
		"stale ActionDeleted must NOT decrement live policy rule_count")

	// Compliance results NOT wiped.
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM compliance_results_projection WHERE action_id = $1", actionID,
	).Scan(&count))
	assert.Equal(t, 1, count, "stale ActionDeleted must NOT cascade-delete compliance results")
}

// TestActionListener_ActionSetMemberCountDecrementsOnDelete is a
// focused regression for the action_set decrement step — covered by
// the cascade test above but kept as a dedicated probe.
func TestActionListener_ActionSetMemberCountDecrementsOnDelete(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	actionID := testutil.NewID()
	setID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action", StreamID: actionID, EventType: "ActionCreated",
		Data:      map[string]any{"name": "to-delete"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetCreated",
		Data:      map[string]any{"name": "container"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetMemberAdded",
		Data:      map[string]any{"action_id": actionID},
		ActorType: "user", ActorID: "u",
	}))
	pre, err := st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), pre.MemberCount)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action", StreamID: actionID, EventType: "ActionDeleted",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))

	post, err := st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), post.MemberCount,
		"ActionDeleted must decrement member_count on every parent set")
}

// TestActionListener_StaleRenamedReplayRejected — UPDATE form on the
// action stream doesn't clobber a fresher row when re-applied with an
// older projection_version.
func TestActionListener_StaleRenamedReplayRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	actionID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action", StreamID: actionID, EventType: "ActionCreated",
		Data:      map[string]any{"name": "first"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action", StreamID: actionID, EventType: "ActionRenamed",
		Data:      map[string]any{"name": "current"},
		ActorType: "user", ActorID: "u",
	}))
	current, err := st.Queries().GetActionByID(ctx, actionID)
	require.NoError(t, err)
	currentVersion := current.ProjectionVersion

	older := currentVersion - 5
	updatedAt := current.UpdatedAt
	n, err := st.Queries().RenameActionProjection(ctx, db.RenameActionProjectionParams{
		ID:                actionID,
		Name:              "stale",
		UpdatedAt:         updatedAt,
		ProjectionVersion: older,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)

	after, err := st.Queries().GetActionByID(ctx, actionID)
	require.NoError(t, err)
	assert.Equal(t, "current", after.Name)
}

// TestActionListener_IgnoresOtherStreamTypes — defensive.
func TestActionListener_IgnoresOtherStreamTypes(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	id := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", // wrong
		StreamID:   id,
		EventType:  "ActionCreated",
		Data:       map[string]any{"name": "ghost"},
		ActorType:  "user", ActorID: "u",
	}))

	_, err := st.Queries().GetActionByID(ctx, id)
	require.Error(t, err, "wrong-stream ActionCreated must NOT create a row")
}
