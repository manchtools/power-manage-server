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

func definitionCreate(name string) *pmv1.CreateDefinitionRequest {
	return &pmv1.CreateDefinitionRequest{
		Name: name, Schedule: &pmv1.ActionSchedule{Cron: "0 1 * * *"},
	}
}

func createDefinitionSet(t *testing.T, state *authoring.Service, name string) string {
	t.Helper()
	op := actionOperation()
	set, err := state.CreateActionSet(context.Background(), op, authoring.CreateActionSetParams{
		Name: name, CreatedBy: op.ActorID, Schedule: &pmv1.ActionSchedule{Cron: "0 4 * * *"},
	})
	require.NoError(t, err)
	return set.ID
}

func TestDefinitionHandlers_ValidateBeforeAuthentication(t *testing.T) {
	f := newActionHandlerFixture(t)
	_, err := f.handlers.GetDefinition(context.Background(), connect.NewRequest(&pmv1.GetDefinitionRequest{Id: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = f.handlers.GetDefinition(context.Background(), connect.NewRequest(&pmv1.GetDefinitionRequest{Id: newID()}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestDefinitionHandlers_CRUDMembershipAndAudit(t *testing.T) {
	f := newActionHandlerFixture(t)
	ctx := f.actor(
		"CreateDefinition", "GetDefinition", "ListDefinitions", "RenameDefinition",
		"UpdateDefinitionDescription", "UpdateDefinitionSchedule", "DeleteDefinition",
		"AddActionSetToDefinition", "RemoveActionSetFromDefinition", "ReorderActionSetInDefinition",
	)
	state := authoring.New(authoring.Config{Store: f.store, Now: func() time.Time { return f.now }})
	set1 := createDefinitionSet(t, state, "one")
	set2 := createDefinitionSet(t, state, "two")

	created, err := f.handlers.CreateDefinition(ctx, connect.NewRequest(definitionCreate("baseline")))
	require.NoError(t, err)
	definitionID := created.Msg.Definition.Id
	assert.Equal(t, int32(0), created.Msg.Definition.MemberCount)
	assert.Equal(t, "0 1 * * *", created.Msg.Definition.Schedule.Cron)

	added, err := f.handlers.AddActionSetToDefinition(ctx, connect.NewRequest(&pmv1.AddActionSetToDefinitionRequest{
		DefinitionId: definitionID, ActionSetId: set2, SortOrder: 20,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(1), added.Msg.Definition.MemberCount)
	_, err = f.handlers.AddActionSetToDefinition(ctx, connect.NewRequest(&pmv1.AddActionSetToDefinitionRequest{
		DefinitionId: definitionID, ActionSetId: set1, SortOrder: 10,
	}))
	require.NoError(t, err)
	_, err = f.handlers.AddActionSetToDefinition(ctx, connect.NewRequest(&pmv1.AddActionSetToDefinitionRequest{
		DefinitionId: definitionID, ActionSetId: set1, SortOrder: 30,
	}))
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))

	got, err := f.handlers.GetDefinition(ctx, connect.NewRequest(&pmv1.GetDefinitionRequest{Id: definitionID}))
	require.NoError(t, err)
	require.Len(t, got.Msg.Members, 2)
	assert.Equal(t, set1, got.Msg.Members[0].ActionSetId)
	assert.Equal(t, "one", got.Msg.Members[0].ActionSetName)
	assert.Equal(t, set2, got.Msg.Members[1].ActionSetId)
	assert.Equal(t, int32(2), got.Msg.Definition.MemberCount)

	renamed, err := f.handlers.RenameDefinition(ctx, connect.NewRequest(&pmv1.RenameDefinitionRequest{Id: definitionID, Name: "renamed"}))
	require.NoError(t, err)
	assert.Equal(t, "renamed", renamed.Msg.Definition.Name)
	described, err := f.handlers.UpdateDefinitionDescription(ctx, connect.NewRequest(&pmv1.UpdateDefinitionDescriptionRequest{
		Id: definitionID, Description: "direct state",
	}))
	require.NoError(t, err)
	assert.Equal(t, "direct state", described.Msg.Definition.Description)
	scheduled, err := f.handlers.UpdateDefinitionSchedule(ctx, connect.NewRequest(&pmv1.UpdateDefinitionScheduleRequest{
		Id: definitionID, Schedule: &pmv1.ActionSchedule{IntervalHours: 12},
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(12), scheduled.Msg.Definition.Schedule.IntervalHours)

	reordered, err := f.handlers.ReorderActionSetInDefinition(ctx, connect.NewRequest(&pmv1.ReorderActionSetInDefinitionRequest{
		DefinitionId: definitionID, ActionSetId: set2, NewOrder: 0,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(2), reordered.Msg.Definition.MemberCount)
	got, err = f.handlers.GetDefinition(ctx, connect.NewRequest(&pmv1.GetDefinitionRequest{Id: definitionID}))
	require.NoError(t, err)
	assert.Equal(t, set2, got.Msg.Members[0].ActionSetId)

	removed, err := f.handlers.RemoveActionSetFromDefinition(ctx, connect.NewRequest(&pmv1.RemoveActionSetFromDefinitionRequest{
		DefinitionId: definitionID, ActionSetId: set1,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(1), removed.Msg.Definition.MemberCount)
	_, err = f.handlers.RemoveActionSetFromDefinition(ctx, connect.NewRequest(&pmv1.RemoveActionSetFromDefinitionRequest{
		DefinitionId: definitionID, ActionSetId: set1,
	}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	_, err = f.handlers.DeleteDefinition(ctx, connect.NewRequest(&pmv1.DeleteDefinitionRequest{Id: definitionID}))
	require.NoError(t, err)
	_, err = f.handlers.GetDefinition(ctx, connect.NewRequest(&pmv1.GetDefinitionRequest{Id: definitionID}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	for _, procedure := range authoring.DefinitionMutationProcedures() {
		operation, err := latestOperationFor(t, f.store, f.raw, procedure)
		require.NoError(t, err, procedure)
		effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
		require.NoError(t, err, procedure)
		assert.NotEmpty(t, effects, procedure)
	}
}

func TestDefinitionHandlers_KeysetAndDirectScope(t *testing.T) {
	f := newActionHandlerFixture(t)
	state := authoring.New(authoring.Config{Store: f.store, Now: func() time.Time { return f.now }})
	create := func(name string) string {
		op := actionOperation()
		row, err := state.CreateDefinition(context.Background(), op, authoring.CreateDefinitionParams{
			Name: name, CreatedBy: op.ActorID, Schedule: &pmv1.ActionSchedule{RunOnAssign: true},
		})
		require.NoError(t, err)
		return row.ID
	}
	directID, outsideID, unassignedID := create("direct"), create("outside"), create("unassigned")
	groupA, groupB := newID(), newID()
	_, err := f.raw.Exec(context.Background(),
		`INSERT INTO device_groups (id, name) VALUES ($1, 'A'), ($2, 'B')`, groupA, groupB)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `
		INSERT INTO assignments (id, source_type, source_id, target_type, target_id, created_at, created_by)
		VALUES ($1, 'definition', $2, 'device_group', $3, $4, $5),
		       ($6, 'definition', $7, 'device_group', $8, $4, $5)`,
		newID(), directID, groupA, f.now, f.actorID,
		newID(), outsideID, groupB)
	require.NoError(t, err)

	scoped := auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser,
		Permissions: []string{"GetDefinition", "ListDefinitions", "RenameDefinition"},
		ScopedGrants: []auth.ScopedGrant{{
			Permission: "ListDevices", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: groupA,
		}},
	})
	_, err = f.handlers.GetDefinition(scoped, connect.NewRequest(&pmv1.GetDefinitionRequest{Id: directID}))
	require.NoError(t, err)
	for _, id := range []string{outsideID, unassignedID} {
		_, err = f.handlers.GetDefinition(scoped, connect.NewRequest(&pmv1.GetDefinitionRequest{Id: id}))
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), id)
	}
	_, err = f.handlers.RenameDefinition(scoped, connect.NewRequest(&pmv1.RenameDefinitionRequest{Id: outsideID, Name: "denied"}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	_, err = f.handlers.RenameDefinition(scoped, connect.NewRequest(&pmv1.RenameDefinitionRequest{Id: directID, Name: "allowed"}))
	require.NoError(t, err)

	list, err := f.handlers.ListDefinitions(scoped, connect.NewRequest(&pmv1.ListDefinitionsRequest{}))
	require.NoError(t, err)
	require.Len(t, list.Msg.Definitions, 1)
	assert.Equal(t, directID, list.Msg.Definitions[0].Id)
	assert.Equal(t, int32(1), list.Msg.TotalCount)

	global := f.actor("ListDefinitions")
	page, err := f.handlers.ListDefinitions(global, connect.NewRequest(&pmv1.ListDefinitionsRequest{PageSize: 1}))
	require.NoError(t, err)
	require.Len(t, page.Msg.Definitions, 1)
	assert.NotEmpty(t, page.Msg.NextPageToken)
	assert.Equal(t, int32(3), page.Msg.TotalCount)
	all, err := f.handlers.ListDefinitions(global, connect.NewRequest(&pmv1.ListDefinitionsRequest{}))
	require.NoError(t, err)
	ids := []string{all.Msg.Definitions[0].Id, all.Msg.Definitions[1].Id, all.Msg.Definitions[2].Id}
	sort.Strings(ids)
	want := []string{directID, outsideID, unassignedID}
	sort.Strings(want)
	assert.Equal(t, want, ids)
}

func TestDefinitionHandlers_AddRequiresVisibleActionSet(t *testing.T) {
	f := newActionHandlerFixture(t)
	state := authoring.New(authoring.Config{Store: f.store})
	definitionOp := actionOperation()
	definition, err := state.CreateDefinition(context.Background(), definitionOp, authoring.CreateDefinitionParams{
		Name: "target", CreatedBy: definitionOp.ActorID, Schedule: &pmv1.ActionSchedule{RunOnAssign: true},
	})
	require.NoError(t, err)
	inScope := createDefinitionSet(t, state, "in")
	outOfScope := createDefinitionSet(t, state, "out")
	groupA, groupB := newID(), newID()
	_, err = f.raw.Exec(context.Background(),
		`INSERT INTO device_groups (id, name) VALUES ($1, 'A'), ($2, 'B')`, groupA, groupB)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `
		INSERT INTO assignments (id, source_type, source_id, target_type, target_id, created_at, created_by)
		VALUES ($1, 'definition', $2, 'device_group', $3, now(), $4),
		       ($5, 'action_set', $6, 'device_group', $3, now(), $4),
		       ($7, 'action_set', $8, 'device_group', $9, now(), $4)`,
		newID(), definition.ID, groupA, f.actorID,
		newID(), inScope, newID(), outOfScope, groupB)
	require.NoError(t, err)
	scoped := auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser, Permissions: []string{"AddActionSetToDefinition"},
		ScopedGrants: []auth.ScopedGrant{{
			Permission: "ListDevices", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: groupA,
		}},
	})
	_, err = f.handlers.AddActionSetToDefinition(scoped, connect.NewRequest(&pmv1.AddActionSetToDefinitionRequest{
		DefinitionId: definition.ID, ActionSetId: outOfScope,
	}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	_, err = f.handlers.AddActionSetToDefinition(scoped, connect.NewRequest(&pmv1.AddActionSetToDefinitionRequest{
		DefinitionId: definition.ID, ActionSetId: inScope,
	}))
	require.NoError(t, err)
}

func TestDefinitionHandlers_CorruptStoredScheduleFailsClosed(t *testing.T) {
	f := newActionHandlerFixture(t)
	state := authoring.New(authoring.Config{Store: f.store})
	op := actionOperation()
	definition, err := state.CreateDefinition(context.Background(), op, authoring.CreateDefinitionParams{
		Name: "safe", CreatedBy: op.ActorID, Schedule: &pmv1.ActionSchedule{RunOnAssign: true},
	})
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `UPDATE definitions SET schedule = '{}' WHERE id = $1`, definition.ID)
	require.NoError(t, err)

	_, err = f.handlers.GetDefinition(f.actor("GetDefinition"), connect.NewRequest(&pmv1.GetDefinitionRequest{Id: definition.ID}))
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
}

func TestDefinitionHandlers_MountsExactSurface(t *testing.T) {
	f := newActionHandlerFixture(t)
	assert.Equal(t, []string{
		powermanagev1connect.ControlServiceCreateDefinitionProcedure,
		powermanagev1connect.ControlServiceGetDefinitionProcedure,
		powermanagev1connect.ControlServiceListDefinitionsProcedure,
		powermanagev1connect.ControlServiceRenameDefinitionProcedure,
		powermanagev1connect.ControlServiceUpdateDefinitionDescriptionProcedure,
		powermanagev1connect.ControlServiceUpdateDefinitionScheduleProcedure,
		powermanagev1connect.ControlServiceDeleteDefinitionProcedure,
		powermanagev1connect.ControlServiceAddActionSetToDefinitionProcedure,
		powermanagev1connect.ControlServiceRemoveActionSetFromDefinitionProcedure,
		powermanagev1connect.ControlServiceReorderActionSetInDefinitionProcedure,
	}, f.handlers.MountDefinitions(http.NewServeMux()))
}
