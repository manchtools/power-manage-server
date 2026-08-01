package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/authoring"
	"github.com/manchtools/power-manage/server/internal/manifest"
	"github.com/manchtools/power-manage/server/internal/store"
)

func createNoParamsAction(t *testing.T, svc *authoring.Service, actionType pmv1.ActionType) store.ActionRow {
	t.Helper()
	op := actionOperation()
	row, err := svc.CreateAction(context.Background(), op, authoring.CreateActionParams{
		Name: actionType.String(), CreatedBy: op.ActorID, Type: actionType, Params: []byte(`{}`),
	})
	require.NoError(t, err)
	return row
}

func TestActionSetState_CRUDCompilesAuthoredOrderAndPolicy(t *testing.T) {
	st, raw := setupPostgres(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 1, 14, 0, 0, 0, time.UTC)
	svc := authoring.New(authoring.Config{Store: st, Now: func() time.Time { return now }})
	action1 := createNoParamsAction(t, svc, pmv1.ActionType_ACTION_TYPE_REBOOT)
	action2 := createNoParamsAction(t, svc, pmv1.ActionType_ACTION_TYPE_SYNC)

	createOp := actionOperation()
	set, err := svc.CreateActionSet(ctx, createOp, authoring.CreateActionSetParams{
		Name: "daily baseline", Description: "ordered", CreatedBy: createOp.ActorID,
		Schedule:  &pmv1.ActionSchedule{Cron: "0 4 * * *"},
		OnFailure: pmv1.OnFailure_ON_FAILURE_STOP,
	})
	require.NoError(t, err)
	assert.Equal(t, int32(pmv1.OnFailure_ON_FAILURE_STOP), set.OnFailure)
	var staleCounter bool
	require.NoError(t, raw.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = 'action_sets' AND column_name = 'member_count'
		)
	`).Scan(&staleCounter))
	assert.False(t, staleCounter, "member count is derived from ordinary membership rows, not projector state")
	effects, err := st.ListAuditEffects(ctx, createOp.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 1)
	assert.Equal(t, set.ID, effects[0].ResourceID)

	require.NoError(t, svc.AddActionToSet(ctx, actionOperation(), set.ID, action2.ID, 20))
	require.NoError(t, svc.AddActionToSet(ctx, actionOperation(), set.ID, action1.ID, 10))
	err = svc.AddActionToSet(ctx, actionOperation(), set.ID, action1.ID, 30)
	assert.ErrorIs(t, err, authoring.ErrAlreadyMember)

	compiled, err := manifest.New(st).ActionSet(ctx, set.ID)
	require.NoError(t, err)
	require.Len(t, compiled.Occurrences, 2)
	assert.Equal(t, action1.ID, compiled.Occurrences[0].Action.Id.Value)
	assert.Equal(t, action2.ID, compiled.Occurrences[1].Action.Id.Value)
	assert.Equal(t, pmv1.OnFailure_ON_FAILURE_STOP, compiled.DefaultOnFailure)

	require.NoError(t, svc.ReorderActionInSet(ctx, actionOperation(), set.ID, action2.ID, 0))
	members, err := st.ListActionSetMembers(ctx, set.ID)
	require.NoError(t, err)
	require.Len(t, members, 2)
	assert.Equal(t, action2.ID, members[0].ActionID)
	assert.Equal(t, action1.ID, members[1].ActionID)

	renameOp := actionOperation()
	renamed, err := svc.RenameActionSet(ctx, renameOp, set.ID, "renamed baseline")
	require.NoError(t, err)
	assert.Equal(t, "renamed baseline", renamed.Name)
	var searchable bool
	require.NoError(t, raw.QueryRow(ctx, `
		SELECT search_tsv @@ plainto_tsquery('simple', 'renamed') FROM action_sets WHERE id = $1
	`, set.ID).Scan(&searchable))
	assert.True(t, searchable)

	require.NoError(t, svc.RemoveActionFromSet(ctx, actionOperation(), set.ID, action1.ID))
	members, err = st.ListActionSetMembers(ctx, set.ID)
	require.NoError(t, err)
	require.Len(t, members, 1)

	definitionID := newID()
	_, err = raw.Exec(ctx, `INSERT INTO definitions (id, name, created_at) VALUES ($1, 'parent', now())`, definitionID)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `INSERT INTO definition_members (definition_id, action_set_id) VALUES ($1, $2)`, definitionID, set.ID)
	require.NoError(t, err)

	require.NoError(t, svc.DeleteActionSet(ctx, actionOperation(), set.ID))
	_, err = st.GetManifestActionSet(ctx, set.ID)
	assert.True(t, store.IsNotFound(err))
	var edges int
	require.NoError(t, raw.QueryRow(ctx, `SELECT count(*) FROM definition_members WHERE action_set_id = $1`, set.ID).Scan(&edges))
	assert.Zero(t, edges, "soft deletion removes dead definition edges")
	require.NoError(t, raw.QueryRow(ctx, `SELECT count(*) FROM action_set_members WHERE set_id = $1`, set.ID).Scan(&edges))
	assert.Zero(t, edges, "soft deletion removes dead action edges")
}

func TestActionSetState_AuditFailureRollsBackCreate(t *testing.T) {
	st, _ := setupPostgres(t)
	svc := authoring.New(authoring.Config{Store: st})
	_, err := svc.CreateActionSet(context.Background(), store.AuditOperation{}, authoring.CreateActionSetParams{
		Name: "must not exist", CreatedBy: newID(), Schedule: &pmv1.ActionSchedule{RunOnAssign: true},
	})
	require.Error(t, err)
	count, err := st.CountActionSets(context.Background())
	require.NoError(t, err)
	assert.Zero(t, count)
}

func TestActionSetState_RejectsSystemActionMembership(t *testing.T) {
	st, _ := setupPostgres(t)
	svc := authoring.New(authoring.Config{Store: st})
	setOp := actionOperation()
	set, err := svc.CreateActionSet(context.Background(), setOp, authoring.CreateActionSetParams{
		Name: "operator set", CreatedBy: setOp.ActorID, Schedule: &pmv1.ActionSchedule{RunOnAssign: true},
	})
	require.NoError(t, err)
	actionOp := actionOperation()
	action, err := svc.CreateAction(context.Background(), actionOp, authoring.CreateActionParams{
		Name: "managed", CreatedBy: actionOp.ActorID, Type: pmv1.ActionType_ACTION_TYPE_REBOOT,
		Params: []byte(`{}`), System: true,
	})
	require.NoError(t, err)

	err = svc.AddActionToSet(context.Background(), actionOperation(), set.ID, action.ID, 0)
	assert.ErrorIs(t, err, authoring.ErrSystemAction)
	members, err := st.ListActionSetMembers(context.Background(), set.ID)
	require.NoError(t, err)
	assert.Empty(t, members)
}
