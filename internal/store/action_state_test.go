package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/authoring"
	"github.com/manchtools/power-manage/server/internal/store"
)

func actionOperation() store.AuditOperation {
	op := mutationOp()
	op.OperationID = newID()
	return op
}

func TestActionState_CRUDCommitsWithAudit(t *testing.T) {
	st, raw := setupSQLite(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	svc := authoring.New(authoring.Config{Store: st, Now: func() time.Time { return now }})

	createOp := actionOperation()
	action, err := svc.CreateAction(ctx, createOp, authoring.CreateActionParams{
		Name: "bootstrap shell", Description: "initial", CreatedBy: createOp.ActorID,
		Type:         pmv1.ActionType_ACTION_TYPE_SHELL,
		DesiredState: pmv1.DesiredState_DESIRED_STATE_PRESENT,
		Params:       []byte(`{"interpreter":"/bin/sh","script":"printf ok"}`),
		Schedule:     &pmv1.ActionSchedule{RunOnAssign: true},
	})
	require.NoError(t, err)
	assert.Equal(t, int32(300), action.TimeoutSeconds, "create applies the existing default")
	assert.Equal(t, `{"interpreter":"/bin/sh","script":"printf ok"}`, string(action.ParamsCanonical))
	assert.True(t, action.CreatedAt.Equal(now))
	effects, err := st.ListAuditEffects(ctx, createOp.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 1)
	assert.Equal(t, action.ID, effects[0].ResourceID)

	updateOp := actionOperation()
	updated, err := svc.UpdateActionParams(ctx, updateOp, authoring.UpdateActionParams{
		ID: action.ID, DesiredState: pmv1.DesiredState_DESIRED_STATE_ABSENT,
		Params:         []byte(`{"script":"printf changed","interpreter":"/bin/sh"}`),
		TimeoutSeconds: 45, Schedule: &pmv1.ActionSchedule{Cron: "0 5 * * *"},
	})
	require.NoError(t, err)
	assert.Equal(t, int32(45), updated.TimeoutSeconds)
	assert.Equal(t, `{"interpreter":"/bin/sh","script":"printf changed"}`, string(updated.ParamsCanonical),
		"canonical bytes do not depend on caller key order")
	preserveOp := actionOperation()
	preserved, err := svc.UpdateActionParams(ctx, preserveOp, authoring.UpdateActionParams{
		ID: action.ID, DesiredState: pmv1.DesiredState_DESIRED_STATE_PRESENT,
		Params: []byte(`{"script":"printf again","interpreter":"/bin/sh"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, int32(45), preserved.TimeoutSeconds, "an omitted timeout preserves the stored value")
	assert.Contains(t, string(preserved.Schedule), "0 5 * * *", "an omitted schedule preserves the stored value")

	renameOp := actionOperation()
	renamed, err := svc.RenameAction(ctx, renameOp, action.ID, "renamed shell", false)
	require.NoError(t, err)
	assert.Equal(t, "renamed shell", renamed.Name)
	assert.True(t, searchDocumentMatches(t, raw, "actions", action.ID, "renamed*"),
		"the FTS5 document changes in the mutation transaction")

	setID := newID()
	_, err = raw.Exec(ctx, `INSERT INTO action_sets (id, name, created_at) VALUES ($1, 'holder', CURRENT_TIMESTAMP)`, setID)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `INSERT INTO action_set_members (set_id, action_id) VALUES ($1, $2)`, setID, action.ID)
	require.NoError(t, err)

	deleteOp := actionOperation()
	require.NoError(t, svc.DeleteAction(ctx, deleteOp, action.ID, false))
	_, err = st.GetManifestAction(ctx, action.ID)
	assert.True(t, store.IsNotFound(err))
	var memberships int
	require.NoError(t, raw.QueryRow(ctx, `SELECT count(*) FROM action_set_members WHERE action_id = $1`, action.ID).Scan(&memberships))
	assert.Zero(t, memberships, "soft deletion removes dead composition edges")
	deleteEffects, err := st.ListAuditEffects(ctx, deleteOp.OperationID)
	require.NoError(t, err)
	require.Len(t, deleteEffects, 1)
	assert.ElementsMatch(t, []string{"is_deleted", "memberships"}, deleteEffects[0].ChangedFields)
}

func TestActionState_AuditFailureRollsBackCreate(t *testing.T) {
	st, _ := setupSQLite(t)
	svc := authoring.New(authoring.Config{Store: st})

	_, err := svc.CreateAction(context.Background(), store.AuditOperation{}, authoring.CreateActionParams{
		Name: "must not exist", CreatedBy: newID(), Type: pmv1.ActionType_ACTION_TYPE_REBOOT,
		Params: []byte(`{}`),
	})
	require.Error(t, err)
	count, err := st.CountActions(context.Background())
	require.NoError(t, err)
	assert.Zero(t, count)

	validOp := actionOperation()
	_, err = svc.CreateAction(context.Background(), validOp, authoring.CreateActionParams{
		Name: "unknown params", CreatedBy: validOp.ActorID, Type: pmv1.ActionType_ACTION_TYPE_SHELL,
		Params: []byte(`{"unexpected":true}`),
	})
	require.Error(t, err)
	count, err = st.CountActions(context.Background())
	require.NoError(t, err)
	assert.Zero(t, count, "unknown action fields fail closed before storage")
}

func TestActionState_UserMutationCannotChangeSystemAction(t *testing.T) {
	st, _ := setupSQLite(t)
	svc := authoring.New(authoring.Config{Store: st})
	createOp := actionOperation()
	action, err := svc.CreateAction(context.Background(), createOp, authoring.CreateActionParams{
		Name: "managed", CreatedBy: createOp.ActorID, Type: pmv1.ActionType_ACTION_TYPE_REBOOT,
		Params: []byte(`{}`), System: true,
	})
	require.NoError(t, err)

	_, err = svc.RenameAction(context.Background(), actionOperation(), action.ID, "operator edit", false)
	assert.ErrorIs(t, err, authoring.ErrSystemAction)
	unchanged, err := st.GetManifestAction(context.Background(), action.ID)
	require.NoError(t, err)
	assert.Equal(t, "managed", unchanged.Name)
}
