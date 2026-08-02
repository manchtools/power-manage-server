package store_test

import (
	"context"
	"testing"

	"github.com/manchtools/power-manage/server/internal/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/manifest"
)

type manifestFixture struct {
	compiler         *manifest.Compiler
	raw              *testdb.DB
	action1, action2 string
	set1, set2       string
	definition       string
}

func newManifestFixture(t *testing.T) *manifestFixture {
	t.Helper()
	st, raw := setupSQLite(t)
	ctx := context.Background()
	action1, action2 := newID(), newID()
	_, err := raw.Exec(ctx, `
		INSERT INTO actions
			(id, name, action_type, desired_state, params, timeout_seconds, schedule, created_at)
		VALUES
			($1, 'first', $3, 1, '{}', 30, '{"runOnAssign":true}', CURRENT_TIMESTAMP),
			($2, 'second', $4, 2, '{}', 60, '{"cron":"0 3 * * *"}', CURRENT_TIMESTAMP)
	`, action1, action2, int32(pmv1.ActionType_ACTION_TYPE_REBOOT), int32(pmv1.ActionType_ACTION_TYPE_SYNC))
	require.NoError(t, err)
	set1, set2 := newID(), newID()
	_, err = raw.Exec(ctx, `
		INSERT INTO action_sets (id, name, schedule, on_failure, created_at) VALUES
			($1, 'daily', '{"cron":"0 4 * * *"}', $3, CURRENT_TIMESTAMP),
			($2, 'on assign', '{"runOnAssign":true}', $4, CURRENT_TIMESTAMP)
	`, set1, set2, int32(pmv1.OnFailure_ON_FAILURE_STOP), int32(pmv1.OnFailure_ON_FAILURE_CONTINUE))
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `
		INSERT INTO action_set_members (set_id, action_id, sort_order, added_at) VALUES
			($1, $4, 20, CURRENT_TIMESTAMP), ($1, $3, 10, CURRENT_TIMESTAMP), ($2, $3, 0, CURRENT_TIMESTAMP)
	`, set1, set2, action1, action2)
	require.NoError(t, err)
	definition := newID()
	_, err = raw.Exec(ctx, `
		INSERT INTO definitions (id, name, schedule, created_at)
		VALUES ($1, 'workstation', '{"cron":"0 1 * * *"}', CURRENT_TIMESTAMP)
	`, definition)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `
		INSERT INTO definition_members (definition_id, action_set_id, sort_order, added_at)
		VALUES ($1, $3, 10, CURRENT_TIMESTAMP), ($1, $2, 20, CURRENT_TIMESTAMP)
	`, definition, set1, set2)
	require.NoError(t, err)
	return &manifestFixture{
		compiler: manifest.New(st), raw: raw, action1: action1, action2: action2,
		set1: set1, set2: set2, definition: definition,
	}
}

func TestManifestCompiler_ActionCreatesSingleton(t *testing.T) {
	f := newManifestFixture(t)
	got, err := f.compiler.Action(context.Background(), f.action1)
	require.NoError(t, err)
	require.Len(t, got.Occurrences, 1)
	assert.Equal(t, f.action1, got.Provenance.ActionId)
	assert.Empty(t, got.Provenance.ActionSetId)
	assert.True(t, got.Schedule.RunOnAssign)
	assert.Equal(t, f.action1, got.Occurrences[0].Action.Id.Value)
	assert.Equal(t, pmv1.OnFailure_ON_FAILURE_CONTINUE, got.Occurrences[0].OnFailure)
}

func TestManifestCompiler_ActionSetFlattensInAuthoredOrder(t *testing.T) {
	f := newManifestFixture(t)
	got, err := f.compiler.ActionSet(context.Background(), f.set1)
	require.NoError(t, err)
	assert.Equal(t, f.set1, got.Provenance.ActionSetId)
	assert.Equal(t, "0 4 * * *", got.Schedule.Cron)
	assert.Equal(t, pmv1.OnFailure_ON_FAILURE_STOP, got.DefaultOnFailure)
	require.Len(t, got.Occurrences, 2)
	assert.Equal(t, f.action1, got.Occurrences[0].Action.Id.Value)
	assert.Equal(t, f.action2, got.Occurrences[1].Action.Id.Value)
	assert.Equal(t, pmv1.OnFailure_ON_FAILURE_STOP, got.Occurrences[0].OnFailure)
	assert.Equal(t, pmv1.OnFailure_ON_FAILURE_STOP, got.Occurrences[1].OnFailure)
	assert.NotEqual(t, got.Occurrences[0].OccurrenceId, got.Occurrences[1].OccurrenceId)
}

func TestManifestCompiler_DefinitionScheduleOverridesOnlyCompiledManifests(t *testing.T) {
	f := newManifestFixture(t)
	got, err := f.compiler.Definition(context.Background(), f.definition)
	require.NoError(t, err)
	require.Len(t, got, 2)

	assert.Equal(t, f.definition, got[0].Provenance.DefinitionId)
	assert.Equal(t, f.set2, got[0].Provenance.ActionSetId, "definition member order is preserved")
	assert.Equal(t, "0 1 * * *", got[0].Schedule.Cron)
	assert.False(t, got[0].Schedule.RunOnAssign)
	assert.Equal(t, pmv1.OnFailure_ON_FAILURE_CONTINUE, got[0].DefaultOnFailure)
	require.Len(t, got[0].Occurrences, 1)
	assert.Equal(t, f.action1, got[0].Occurrences[0].Action.Id.Value)

	assert.Equal(t, f.set1, got[1].Provenance.ActionSetId)
	assert.Equal(t, "0 1 * * *", got[1].Schedule.Cron)
	assert.Equal(t, pmv1.OnFailure_ON_FAILURE_STOP, got[1].DefaultOnFailure,
		"the definition overrides schedule, not the set failure policy")
	require.Len(t, got[1].Occurrences, 2)
	assert.Equal(t, f.action1, got[1].Occurrences[0].Action.Id.Value,
		"the same authored action reached through another set is preserved")
	assert.NotEqual(t, got[0].Occurrences[0].OccurrenceId, got[1].Occurrences[0].OccurrenceId)

	var unchanged bool
	require.NoError(t, f.raw.QueryRow(context.Background(), `
		SELECT schedule = '{"cron":"0 4 * * *"}'
		FROM action_sets WHERE id = $1`, f.set1).Scan(&unchanged))
	assert.True(t, unchanged, "compilation must not rewrite the ActionSet schedule")

	standalone, err := f.compiler.ActionSet(context.Background(), f.set1)
	require.NoError(t, err)
	assert.Equal(t, "0 4 * * *", standalone.Schedule.Cron,
		"independent ActionSet compilation still uses its own schedule")
}

func dispatchableAction() *pmv1.Action {
	return &pmv1.Action{
		Id: &pmv1.ActionId{Value: newID()}, Type: pmv1.ActionType_ACTION_TYPE_SHELL,
		DesiredState: pmv1.DesiredState_DESIRED_STATE_PRESENT, TimeoutSeconds: 300,
		Params: &pmv1.Action_Shell{Shell: &pmv1.ShellParams{Script: "printf once"}},
	}
}

func TestManifestCompiler_OneShotActionMarksManifestStructurally(t *testing.T) {
	compiled, err := manifest.OneShotAction(dispatchableAction())
	require.NoError(t, err)
	assert.True(t, compiled.GetOneShot(),
		"an explicit dispatch is one-shot by the structural manifest flag, not by schedule shape")
}

func TestManifestCompiler_FreshCopyPreservesOneShotMarking(t *testing.T) {
	source, err := manifest.OneShotAction(dispatchableAction())
	require.NoError(t, err)
	source.OneShot = true

	fresh, err := manifest.FreshCopy(source)
	require.NoError(t, err)
	assert.True(t, fresh.GetOneShot(), "a per-device copy stays one-shot")
	assert.NotEqual(t, source.ManifestId, fresh.ManifestId)
}

func TestManifestCompiler_AssignedCompilationIsNotOneShot(t *testing.T) {
	f := newManifestFixture(t)
	unscheduled := newID()
	_, err := f.raw.Exec(context.Background(), `
		INSERT INTO actions
			(id, name, action_type, desired_state, params, timeout_seconds, schedule, created_at)
		VALUES ($1, 'unscheduled', $2, 1, '{}', 30, '{}', CURRENT_TIMESTAMP)
	`, unscheduled, int32(pmv1.ActionType_ACTION_TYPE_REBOOT))
	require.NoError(t, err)

	single, err := f.compiler.Action(context.Background(), unscheduled)
	require.NoError(t, err)
	require.NotNil(t, single.Schedule)
	assert.False(t, single.GetOneShot(),
		"an empty compiled schedule is not what makes assigned work one-shot")

	set, err := f.compiler.ActionSet(context.Background(), f.set1)
	require.NoError(t, err)
	assert.False(t, set.GetOneShot())

	definitions, err := f.compiler.Definition(context.Background(), f.definition)
	require.NoError(t, err)
	require.NotEmpty(t, definitions)
	for _, item := range definitions {
		assert.False(t, item.GetOneShot())
	}
}

func TestManifestCompiler_RejectsMalformedStoredParams(t *testing.T) {
	f := newManifestFixture(t)
	_, err := f.raw.Exec(context.Background(), `
		UPDATE actions SET action_type = $2, params = '{"unexpected":true}' WHERE id = $1
	`, f.action2, int32(pmv1.ActionType_ACTION_TYPE_SHELL))
	require.NoError(t, err)
	_, err = f.compiler.Action(context.Background(), f.action2)
	require.Error(t, err)
}
