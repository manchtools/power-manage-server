package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/manifest"
)

type manifestFixture struct {
	compiler         *manifest.Compiler
	raw              *pgxpool.Pool
	action1, action2 string
	set1, set2       string
	definition       string
}

func newManifestFixture(t *testing.T) *manifestFixture {
	t.Helper()
	st, raw := setupPostgres(t)
	ctx := context.Background()
	action1, action2 := newID(), newID()
	_, err := raw.Exec(ctx, `
		INSERT INTO actions
			(id, name, action_type, desired_state, params, timeout_seconds, schedule, created_at)
		VALUES
			($1, 'first', $3, 1, '{}'::jsonb, 30, '{"runOnAssign":true}'::jsonb, now()),
			($2, 'second', $4, 2, '{}'::jsonb, 60, '{"cron":"0 3 * * *"}'::jsonb, now())
	`, action1, action2, int32(pmv1.ActionType_ACTION_TYPE_REBOOT), int32(pmv1.ActionType_ACTION_TYPE_SYNC))
	require.NoError(t, err)
	set1, set2 := newID(), newID()
	_, err = raw.Exec(ctx, `
		INSERT INTO action_sets (id, name, schedule, on_failure, created_at) VALUES
			($1, 'daily', '{"cron":"0 4 * * *"}'::jsonb, $3, now()),
			($2, 'on assign', '{"runOnAssign":true}'::jsonb, $4, now())
	`, set1, set2, int32(pmv1.OnFailure_ON_FAILURE_STOP), int32(pmv1.OnFailure_ON_FAILURE_CONTINUE))
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `
		INSERT INTO action_set_members (set_id, action_id, sort_order, added_at) VALUES
			($1, $4, 20, now()), ($1, $3, 10, now()), ($2, $3, 0, now())
	`, set1, set2, action1, action2)
	require.NoError(t, err)
	definition := newID()
	_, err = raw.Exec(ctx, `
		INSERT INTO definitions (id, name, schedule, created_at)
		VALUES ($1, 'workstation', '{"cron":"0 1 * * *"}'::jsonb, now())
	`, definition)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `
		INSERT INTO definition_members (definition_id, action_set_id, sort_order, added_at)
		VALUES ($1, $3, 10, now()), ($1, $2, 20, now())
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

func TestManifestCompiler_DefinitionCreatesOneManifestPerIndependentSet(t *testing.T) {
	f := newManifestFixture(t)
	got, err := f.compiler.Definition(context.Background(), f.definition)
	require.NoError(t, err)
	require.Len(t, got, 2)

	assert.Equal(t, f.definition, got[0].Provenance.DefinitionId)
	assert.Equal(t, f.set2, got[0].Provenance.ActionSetId, "definition member order is preserved")
	assert.True(t, got[0].Schedule.RunOnAssign, "the contained set keeps its own schedule")
	require.Len(t, got[0].Occurrences, 1)
	assert.Equal(t, f.action1, got[0].Occurrences[0].Action.Id.Value)

	assert.Equal(t, f.set1, got[1].Provenance.ActionSetId)
	assert.Equal(t, "0 4 * * *", got[1].Schedule.Cron)
	require.Len(t, got[1].Occurrences, 2)
	assert.Equal(t, f.action1, got[1].Occurrences[0].Action.Id.Value,
		"the same authored action reached through another set is preserved")
	assert.NotEqual(t, got[0].Occurrences[0].OccurrenceId, got[1].Occurrences[0].OccurrenceId)
}

func TestManifestCompiler_RejectsMalformedStoredParams(t *testing.T) {
	f := newManifestFixture(t)
	_, err := f.raw.Exec(context.Background(), `
		UPDATE actions SET action_type = $2, params = '{"unexpected":true}'::jsonb WHERE id = $1
	`, f.action2, int32(pmv1.ActionType_ACTION_TYPE_SHELL))
	require.NoError(t, err)
	_, err = f.compiler.Action(context.Background(), f.action2)
	require.Error(t, err)
}
