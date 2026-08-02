package store_test

import (
	"context"
	"net/http"
	"sort"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/authoring"
)

func setCreate(name string, policy pmv1.OnFailure) *pmv1.CreateActionSetRequest {
	return &pmv1.CreateActionSetRequest{
		Name: name, Schedule: &pmv1.ActionSchedule{Cron: "0 4 * * *"}, OnFailure: policy,
	}
}

func TestActionSetHandlers_ValidateBeforeAuthentication(t *testing.T) {
	f := newActionHandlerFixture(t)
	_, err := f.handlers.GetActionSet(context.Background(), connect.NewRequest(&pmv1.GetActionSetRequest{Id: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = f.handlers.GetActionSet(context.Background(), connect.NewRequest(&pmv1.GetActionSetRequest{Id: newID()}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestActionSetHandlers_CRUDMembershipAndAudit(t *testing.T) {
	f := newActionHandlerFixture(t)
	ctx := f.actor(
		"CreateActionSet", "GetActionSet", "ListActionSets", "RenameActionSet",
		"UpdateActionSetDescription", "UpdateActionSetSchedule", "DeleteActionSet",
		"AddActionToSet", "RemoveActionFromSet", "ReorderActionInSet",
	)
	state := authoring.New(authoring.Config{Store: f.store, Now: func() time.Time { return f.now }})
	action1 := createNoParamsAction(t, state, pmv1.ActionType_ACTION_TYPE_REBOOT)
	action2 := createNoParamsAction(t, state, pmv1.ActionType_ACTION_TYPE_SYNC)

	created, err := f.handlers.CreateActionSet(ctx, connect.NewRequest(setCreate("baseline", pmv1.OnFailure_ON_FAILURE_STOP)))
	require.NoError(t, err)
	setID := created.Msg.Set.Id
	assert.Equal(t, pmv1.OnFailure_ON_FAILURE_STOP, created.Msg.Set.OnFailure)
	assert.Equal(t, int32(0), created.Msg.Set.MemberCount)
	assert.Equal(t, "0 4 * * *", created.Msg.Set.Schedule.Cron)

	added, err := f.handlers.AddActionToSet(ctx, connect.NewRequest(&pmv1.AddActionToSetRequest{
		SetId: setID, ActionId: action2.ID, SortOrder: 20,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(1), added.Msg.Set.MemberCount)
	_, err = f.handlers.AddActionToSet(ctx, connect.NewRequest(&pmv1.AddActionToSetRequest{
		SetId: setID, ActionId: action1.ID, SortOrder: 10,
	}))
	require.NoError(t, err)
	_, err = f.handlers.AddActionToSet(ctx, connect.NewRequest(&pmv1.AddActionToSetRequest{
		SetId: setID, ActionId: action1.ID, SortOrder: 30,
	}))
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))

	got, err := f.handlers.GetActionSet(ctx, connect.NewRequest(&pmv1.GetActionSetRequest{Id: setID}))
	require.NoError(t, err)
	require.Len(t, got.Msg.Members, 2)
	assert.Equal(t, action1.ID, got.Msg.Members[0].ActionId)
	assert.Equal(t, action2.ID, got.Msg.Members[1].ActionId)
	assert.Equal(t, int32(2), got.Msg.Set.MemberCount)

	renamed, err := f.handlers.RenameActionSet(ctx, connect.NewRequest(&pmv1.RenameActionSetRequest{Id: setID, Name: "renamed"}))
	require.NoError(t, err)
	assert.Equal(t, "renamed", renamed.Msg.Set.Name)
	described, err := f.handlers.UpdateActionSetDescription(ctx, connect.NewRequest(&pmv1.UpdateActionSetDescriptionRequest{
		Id: setID, Description: "direct state",
	}))
	require.NoError(t, err)
	assert.Equal(t, "direct state", described.Msg.Set.Description)
	policy, err := f.handlers.UpdateActionSetSchedule(ctx, connect.NewRequest(&pmv1.UpdateActionSetScheduleRequest{
		Id: setID, Schedule: &pmv1.ActionSchedule{IntervalHours: 12}, OnFailure: pmv1.OnFailure_ON_FAILURE_CONTINUE,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(12), policy.Msg.Set.Schedule.IntervalHours)
	assert.Equal(t, pmv1.OnFailure_ON_FAILURE_CONTINUE, policy.Msg.Set.OnFailure)

	reordered, err := f.handlers.ReorderActionInSet(ctx, connect.NewRequest(&pmv1.ReorderActionInSetRequest{
		SetId: setID, ActionId: action2.ID, NewOrder: 0,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(2), reordered.Msg.Set.MemberCount)
	got, err = f.handlers.GetActionSet(ctx, connect.NewRequest(&pmv1.GetActionSetRequest{Id: setID}))
	require.NoError(t, err)
	assert.Equal(t, action2.ID, got.Msg.Members[0].ActionId)

	removed, err := f.handlers.RemoveActionFromSet(ctx, connect.NewRequest(&pmv1.RemoveActionFromSetRequest{
		SetId: setID, ActionId: action1.ID,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(1), removed.Msg.Set.MemberCount)
	_, err = f.handlers.RemoveActionFromSet(ctx, connect.NewRequest(&pmv1.RemoveActionFromSetRequest{
		SetId: setID, ActionId: action1.ID,
	}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	_, err = f.handlers.DeleteActionSet(ctx, connect.NewRequest(&pmv1.DeleteActionSetRequest{Id: setID}))
	require.NoError(t, err)
	_, err = f.handlers.GetActionSet(ctx, connect.NewRequest(&pmv1.GetActionSetRequest{Id: setID}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	for _, procedure := range authoring.ActionSetMutationProcedures() {
		operation, err := latestOperationFor(t, f.store, f.raw, procedure)
		require.NoError(t, err, procedure)
		effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
		require.NoError(t, err, procedure)
		assert.NotEmpty(t, effects, procedure)
	}
}

func TestActionSetHandlers_KeysetAndTransitiveScope(t *testing.T) {
	f := newActionHandlerFixture(t)
	state := authoring.New(authoring.Config{Store: f.store, Now: func() time.Time { return f.now }})
	create := func(name string) string {
		op := actionOperation()
		row, err := state.CreateActionSet(context.Background(), op, authoring.CreateActionSetParams{
			Name: name, CreatedBy: op.ActorID, Schedule: &pmv1.ActionSchedule{RunOnAssign: true},
		})
		require.NoError(t, err)
		return row.ID
	}
	directID, transitiveID, outsideID, unassignedID := create("direct"), create("transitive"), create("outside"), create("unassigned")
	groupA, groupB, definitionID := newID(), newID(), newID()
	_, err := f.raw.Exec(context.Background(),
		`INSERT INTO device_groups (id, name) VALUES ($1, 'A'), ($2, 'B')`, groupA, groupB)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(),
		`INSERT INTO definitions (id, name, created_at) VALUES ($1, 'parent', $2)`, definitionID, f.now)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(),
		`INSERT INTO definition_members (definition_id, action_set_id) VALUES ($1, $2)`, definitionID, transitiveID)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `
		INSERT INTO assignments (id, source_type, source_id, target_type, target_id, created_at, created_by)
		VALUES ($1, 'action_set', $2, 'device_group', $3, $4, $5),
		       ($6, 'definition', $7, 'device_group', $3, $4, $5),
		       ($8, 'action_set', $9, 'device_group', $10, $4, $5)`,
		newID(), directID, groupA, f.now, f.actorID,
		newID(), definitionID, newID(), outsideID, groupB)
	require.NoError(t, err)

	scoped := auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser,
		Permissions: []string{"GetActionSet", "ListActionSets", "RenameActionSet"},
		ScopedGrants: []auth.ScopedGrant{{
			Permission: "ListDevices", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: groupA,
		}},
	})
	for _, id := range []string{directID, transitiveID} {
		_, err := f.handlers.GetActionSet(scoped, connect.NewRequest(&pmv1.GetActionSetRequest{Id: id}))
		require.NoError(t, err)
	}
	for _, id := range []string{outsideID, unassignedID} {
		_, err := f.handlers.GetActionSet(scoped, connect.NewRequest(&pmv1.GetActionSetRequest{Id: id}))
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), id)
	}
	_, err = f.handlers.RenameActionSet(scoped, connect.NewRequest(&pmv1.RenameActionSetRequest{Id: transitiveID, Name: "denied"}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	_, err = f.handlers.RenameActionSet(scoped, connect.NewRequest(&pmv1.RenameActionSetRequest{Id: directID, Name: "allowed"}))
	require.NoError(t, err)

	list, err := f.handlers.ListActionSets(scoped, connect.NewRequest(&pmv1.ListActionSetsRequest{}))
	require.NoError(t, err)
	require.Len(t, list.Msg.Sets, 2)
	ids := []string{list.Msg.Sets[0].Id, list.Msg.Sets[1].Id}
	sort.Strings(ids)
	want := []string{directID, transitiveID}
	sort.Strings(want)
	assert.Equal(t, want, ids)
	assert.Equal(t, int32(2), list.Msg.TotalCount)

	global := f.actor("ListActionSets")
	page, err := f.handlers.ListActionSets(global, connect.NewRequest(&pmv1.ListActionSetsRequest{PageSize: 1}))
	require.NoError(t, err)
	require.Len(t, page.Msg.Sets, 1)
	assert.NotEmpty(t, page.Msg.NextPageToken)
	assert.Equal(t, int32(4), page.Msg.TotalCount)
	unassigned, err := f.handlers.ListActionSets(global, connect.NewRequest(&pmv1.ListActionSetsRequest{UnassignedOnly: true}))
	require.NoError(t, err)
	require.Len(t, unassigned.Msg.Sets, 2)
	assert.ElementsMatch(t, []string{transitiveID, unassignedID}, []string{unassigned.Msg.Sets[0].Id, unassigned.Msg.Sets[1].Id})
}

func TestActionSetHandlers_AddRequiresVisibleOrdinaryAction(t *testing.T) {
	f := newActionHandlerFixture(t)
	state := authoring.New(authoring.Config{Store: f.store})
	setOp := actionOperation()
	set, err := state.CreateActionSet(context.Background(), setOp, authoring.CreateActionSetParams{
		Name: "target", CreatedBy: setOp.ActorID, Schedule: &pmv1.ActionSchedule{RunOnAssign: true},
	})
	require.NoError(t, err)
	actionOp := actionOperation()
	system, err := state.CreateAction(context.Background(), actionOp, authoring.CreateActionParams{
		Name: "system", CreatedBy: actionOp.ActorID, Type: pmv1.ActionType_ACTION_TYPE_REBOOT,
		Params: []byte(`{}`), System: true,
	})
	require.NoError(t, err)
	ctx := f.actor("AddActionToSet")
	_, err = f.handlers.AddActionToSet(ctx, connect.NewRequest(&pmv1.AddActionToSetRequest{
		SetId: set.ID, ActionId: system.ID,
	}))
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))

	inScope := createNoParamsAction(t, state, pmv1.ActionType_ACTION_TYPE_REBOOT)
	outOfScope := createNoParamsAction(t, state, pmv1.ActionType_ACTION_TYPE_SYNC)
	groupA, groupB := newID(), newID()
	_, err = f.raw.Exec(context.Background(),
		`INSERT INTO device_groups (id, name) VALUES ($1, 'A'), ($2, 'B')`, groupA, groupB)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `
		INSERT INTO assignments (id, source_type, source_id, target_type, target_id, created_at, created_by)
		VALUES ($1, 'action_set', $2, 'device_group', $3, CURRENT_TIMESTAMP, $4),
		       ($5, 'action', $6, 'device_group', $3, CURRENT_TIMESTAMP, $4),
		       ($7, 'action', $8, 'device_group', $9, CURRENT_TIMESTAMP, $4)`,
		newID(), set.ID, groupA, f.actorID,
		newID(), inScope.ID, newID(), outOfScope.ID, groupB)
	require.NoError(t, err)
	scoped := auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser, Permissions: []string{"AddActionToSet"},
		ScopedGrants: []auth.ScopedGrant{{
			Permission: "ListDevices", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: groupA,
		}},
	})
	_, err = f.handlers.AddActionToSet(scoped, connect.NewRequest(&pmv1.AddActionToSetRequest{
		SetId: set.ID, ActionId: outOfScope.ID,
	}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "membership must not import an out-of-scope action")
	_, err = f.handlers.AddActionToSet(scoped, connect.NewRequest(&pmv1.AddActionToSetRequest{
		SetId: set.ID, ActionId: inScope.ID,
	}))
	require.NoError(t, err)
}

func TestActionSetHandlers_CorruptStoredPolicyFailsClosed(t *testing.T) {
	f := newActionHandlerFixture(t)
	state := authoring.New(authoring.Config{Store: f.store})
	op := actionOperation()
	set, err := state.CreateActionSet(context.Background(), op, authoring.CreateActionSetParams{
		Name: "safe", CreatedBy: op.ActorID, Schedule: &pmv1.ActionSchedule{RunOnAssign: true},
	})
	require.NoError(t, err)
	conn, err := f.raw.Conn(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Exec(context.Background(), `PRAGMA ignore_check_constraints = ON`)
	require.NoError(t, err)
	defer func() {
		_, offErr := conn.Exec(context.Background(), `PRAGMA ignore_check_constraints = OFF`)
		require.NoError(t, offErr)
	}()
	_, err = conn.Exec(context.Background(), `UPDATE action_sets SET on_failure = 99 WHERE id = $1`, set.ID)
	require.NoError(t, err)

	_, err = f.handlers.GetActionSet(f.actor("GetActionSet"), connect.NewRequest(&pmv1.GetActionSetRequest{Id: set.ID}))
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
}

func TestActionSetHandlers_MountsExactSurface(t *testing.T) {
	f := newActionHandlerFixture(t)
	assert.Equal(t, []string{
		powermanagev1connect.ControlServiceCreateActionSetProcedure,
		powermanagev1connect.ControlServiceGetActionSetProcedure,
		powermanagev1connect.ControlServiceListActionSetsProcedure,
		powermanagev1connect.ControlServiceRenameActionSetProcedure,
		powermanagev1connect.ControlServiceUpdateActionSetDescriptionProcedure,
		powermanagev1connect.ControlServiceUpdateActionSetScheduleProcedure,
		powermanagev1connect.ControlServiceDeleteActionSetProcedure,
		powermanagev1connect.ControlServiceAddActionToSetProcedure,
		powermanagev1connect.ControlServiceRemoveActionFromSetProcedure,
		powermanagev1connect.ControlServiceReorderActionInSetProcedure,
	}, f.handlers.MountActionSets(http.NewServeMux()))
}
