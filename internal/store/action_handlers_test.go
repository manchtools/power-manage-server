package store_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/authoring"
	"github.com/manchtools/power-manage/server/internal/store"
)

type actionHandlerFixture struct {
	t        *testing.T
	store    *store.Store
	raw      *pgxpool.Pool
	handlers *authoring.Handlers
	now      time.Time
	actorID  string
}

func newActionHandlerFixture(t *testing.T) *actionHandlerFixture {
	t.Helper()
	st, raw := setupPostgres(t)
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	f := &actionHandlerFixture{t: t, store: st, raw: raw, now: now, actorID: newID()}
	f.handlers = authoring.NewHandlers(authoring.HandlersConfig{
		Store: st, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return now },
	})
	return f
}

func (f *actionHandlerFixture) actor(perms ...string) context.Context {
	f.t.Helper()
	return auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser, Permissions: perms,
	})
}

func shellCreate(name string) *pmv1.CreateActionRequest {
	return &pmv1.CreateActionRequest{
		Name: name, Type: pmv1.ActionType_ACTION_TYPE_SHELL,
		DesiredState: pmv1.DesiredState_DESIRED_STATE_PRESENT,
		Schedule:     &pmv1.ActionSchedule{RunOnAssign: true},
		Params: &pmv1.CreateActionRequest_Shell{Shell: &pmv1.ShellParams{
			Interpreter: "/bin/sh", Script: "printf ok",
		}},
	}
}

func TestActionHandlers_ValidateBeforeAuthentication(t *testing.T) {
	f := newActionHandlerFixture(t)
	_, err := f.handlers.GetAction(context.Background(), connect.NewRequest(&pmv1.GetActionRequest{Id: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = f.handlers.GetAction(context.Background(), connect.NewRequest(&pmv1.GetActionRequest{Id: newID()}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestActionHandlers_CRUDIsDirectAuditedState(t *testing.T) {
	f := newActionHandlerFixture(t)
	ctx := f.actor(
		"CreateAction", "GetAction", "ListActions", "RenameAction",
		"UpdateActionDescription", "UpdateActionParams", "DeleteAction",
	)

	created, err := f.handlers.CreateAction(ctx, connect.NewRequest(shellCreate("bootstrap")))
	require.NoError(t, err)
	id := created.Msg.Action.Id
	assert.Equal(t, int32(300), created.Msg.Action.TimeoutSeconds)
	assert.Equal(t, "printf ok", created.Msg.Action.GetShell().Script)
	assert.True(t, created.Msg.Action.CreatedAt.AsTime().Equal(f.now))

	got, err := f.handlers.GetAction(ctx, connect.NewRequest(&pmv1.GetActionRequest{Id: id}))
	require.NoError(t, err)
	assert.Equal(t, "bootstrap", got.Msg.Action.Name)

	renamed, err := f.handlers.RenameAction(ctx, connect.NewRequest(&pmv1.RenameActionRequest{Id: id, Name: "renamed"}))
	require.NoError(t, err)
	assert.Equal(t, "renamed", renamed.Msg.Action.Name)

	described, err := f.handlers.UpdateActionDescription(ctx, connect.NewRequest(&pmv1.UpdateActionDescriptionRequest{
		Id: id, Description: "audited direct state",
	}))
	require.NoError(t, err)
	assert.Equal(t, "audited direct state", described.Msg.Action.Description)

	updated, err := f.handlers.UpdateActionParams(ctx, connect.NewRequest(&pmv1.UpdateActionParamsRequest{
		Id: id, DesiredState: pmv1.DesiredState_DESIRED_STATE_ABSENT,
		TimeoutSeconds: 45, Schedule: &pmv1.ActionSchedule{Cron: "0 5 * * *"},
		Params: &pmv1.UpdateActionParamsRequest_Shell{Shell: &pmv1.ShellParams{
			Interpreter: "/bin/bash", Script: "printf changed",
		}},
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(45), updated.Msg.Action.TimeoutSeconds)
	assert.Equal(t, "printf changed", updated.Msg.Action.GetShell().Script)

	listed, err := f.handlers.ListActions(ctx, connect.NewRequest(&pmv1.ListActionsRequest{}))
	require.NoError(t, err)
	require.Len(t, listed.Msg.Actions, 1)
	assert.Equal(t, id, listed.Msg.Actions[0].Id)
	assert.Equal(t, int32(1), listed.Msg.TotalCount)

	_, err = f.handlers.DeleteAction(ctx, connect.NewRequest(&pmv1.DeleteActionRequest{Id: id}))
	require.NoError(t, err)
	_, err = f.handlers.GetAction(ctx, connect.NewRequest(&pmv1.GetActionRequest{Id: id}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	for _, procedure := range authoring.ActionMutationProcedures() {
		operation, err := latestOperationFor(t, f.store, f.raw, procedure)
		require.NoError(t, err, procedure)
		effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
		require.NoError(t, err, procedure)
		assert.NotEmpty(t, effects, procedure)
	}
}

func TestActionHandlers_KeysetFiltersAndObjectScope(t *testing.T) {
	f := newActionHandlerFixture(t)
	state := authoring.New(authoring.Config{Store: f.store, Now: func() time.Time { return f.now }})
	create := func(name string, actionType pmv1.ActionType, system bool) string {
		op := actionOperation()
		row, err := state.CreateAction(context.Background(), op, authoring.CreateActionParams{
			Name: name, CreatedBy: op.ActorID, Type: actionType,
			DesiredState: pmv1.DesiredState_DESIRED_STATE_PRESENT,
			Params: func() []byte {
				if actionType == pmv1.ActionType_ACTION_TYPE_SHELL {
					return []byte(`{"interpreter":"/bin/sh","script":"printf ok"}`)
				}
				return []byte(`{}`)
			}(),
			Schedule: &pmv1.ActionSchedule{RunOnAssign: true}, System: system,
		})
		require.NoError(t, err)
		return row.ID
	}
	directID := create("direct", pmv1.ActionType_ACTION_TYPE_SHELL, false)
	transitiveID := create("transitive", pmv1.ActionType_ACTION_TYPE_REBOOT, false)
	outsideID := create("outside", pmv1.ActionType_ACTION_TYPE_REBOOT, false)
	unassignedID := create("unassigned", pmv1.ActionType_ACTION_TYPE_SYNC, false)
	systemID := create("system", pmv1.ActionType_ACTION_TYPE_REBOOT, true)

	groupA, groupB, setID := newID(), newID(), newID()
	raw := f.raw
	_, err := raw.Exec(context.Background(),
		`INSERT INTO device_groups (id, name) VALUES ($1, 'A'), ($2, 'B')`, groupA, groupB)
	require.NoError(t, err)
	_, err = raw.Exec(context.Background(),
		`INSERT INTO action_sets (id, name, schedule, created_at) VALUES ($1, 'holder', '{"intervalHours":8}', $2)`,
		setID, f.now)
	require.NoError(t, err)
	_, err = raw.Exec(context.Background(),
		`INSERT INTO action_set_members (set_id, action_id) VALUES ($1, $2)`, setID, transitiveID)
	require.NoError(t, err)
	_, err = raw.Exec(context.Background(), `
		INSERT INTO assignments (id, source_type, source_id, target_type, target_id, created_at, created_by)
		VALUES ($1, 'action', $2, 'device_group', $3, $4, $5),
		       ($6, 'action_set', $7, 'device_group', $3, $4, $5),
		       ($8, 'action', $9, 'device_group', $10, $4, $5)`,
		newID(), directID, groupA, f.now, f.actorID,
		newID(), setID, newID(), outsideID, groupB)
	require.NoError(t, err)

	scoped := auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser,
		Permissions: []string{"GetAction", "ListActions", "RenameAction"},
		ScopedGrants: []auth.ScopedGrant{{
			Permission: "ListDevices", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: groupA,
		}},
	})
	for _, id := range []string{directID, transitiveID} {
		_, err := f.handlers.GetAction(scoped, connect.NewRequest(&pmv1.GetActionRequest{Id: id}))
		require.NoError(t, err)
	}
	for _, id := range []string{outsideID, unassignedID, systemID} {
		_, err := f.handlers.GetAction(scoped, connect.NewRequest(&pmv1.GetActionRequest{Id: id}))
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), id)
	}
	_, err = f.handlers.RenameAction(scoped, connect.NewRequest(&pmv1.RenameActionRequest{Id: transitiveID, Name: "denied"}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "transitive visibility never grants write scope")
	_, err = f.handlers.RenameAction(scoped, connect.NewRequest(&pmv1.RenameActionRequest{Id: directID, Name: "allowed"}))
	require.NoError(t, err)

	list, err := f.handlers.ListActions(scoped, connect.NewRequest(&pmv1.ListActionsRequest{}))
	require.NoError(t, err)
	ids := []string{list.Msg.Actions[0].Id, list.Msg.Actions[1].Id}
	sort.Strings(ids)
	want := []string{directID, transitiveID}
	sort.Strings(want)
	assert.Equal(t, want, ids)
	assert.Equal(t, int32(2), list.Msg.TotalCount)

	global := f.actor("ListActions")
	page1, err := f.handlers.ListActions(global, connect.NewRequest(&pmv1.ListActionsRequest{PageSize: 1}))
	require.NoError(t, err)
	require.Len(t, page1.Msg.Actions, 1)
	require.NotEmpty(t, page1.Msg.NextPageToken)
	page2, err := f.handlers.ListActions(global, connect.NewRequest(&pmv1.ListActionsRequest{
		PageSize: 1, PageToken: page1.Msg.NextPageToken,
	}))
	require.NoError(t, err)
	require.Len(t, page2.Msg.Actions, 1)
	assert.NotEqual(t, page1.Msg.Actions[0].Id, page2.Msg.Actions[0].Id)
	assert.Equal(t, int32(4), page2.Msg.TotalCount, "system actions are absent from the operator surface")

	unassigned, err := f.handlers.ListActions(global, connect.NewRequest(&pmv1.ListActionsRequest{UnassignedOnly: true}))
	require.NoError(t, err)
	require.Len(t, unassigned.Msg.Actions, 2)
	unassignedIDs := []string{unassigned.Msg.Actions[0].Id, unassigned.Msg.Actions[1].Id}
	assert.ElementsMatch(t, []string{transitiveID, unassignedID}, unassignedIDs,
		"membership is not an assignment; only direct assignment rows exclude an action")
	typeFiltered, err := f.handlers.ListActions(global, connect.NewRequest(&pmv1.ListActionsRequest{
		TypeFilter: pmv1.ActionType_ACTION_TYPE_SYNC,
	}))
	require.NoError(t, err)
	require.Len(t, typeFiltered.Msg.Actions, 1)
	assert.Equal(t, unassignedID, typeFiltered.Msg.Actions[0].Id)
}

func TestActionHandlers_CorruptStoredParamsFailClosed(t *testing.T) {
	f := newActionHandlerFixture(t)
	state := authoring.New(authoring.Config{Store: f.store})
	op := actionOperation()
	action, err := state.CreateAction(context.Background(), op, authoring.CreateActionParams{
		Name: "safe", CreatedBy: op.ActorID, Type: pmv1.ActionType_ACTION_TYPE_SHELL,
		Params: []byte(`{"interpreter":"/bin/sh","script":"printf ok"}`),
	})
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `UPDATE actions SET params = '{"bogus":true}' WHERE id = $1`, action.ID)
	require.NoError(t, err)

	_, err = f.handlers.GetAction(f.actor("GetAction"), connect.NewRequest(&pmv1.GetActionRequest{Id: action.ID}))
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
}

func TestActionHandlers_RejectUnsafeOrMismatchedParamsAndSystemMutation(t *testing.T) {
	f := newActionHandlerFixture(t)
	ctx := f.actor("CreateAction", "RenameAction")

	_, err := f.handlers.CreateAction(ctx, connect.NewRequest(&pmv1.CreateActionRequest{
		Name: "empty shell", Type: pmv1.ActionType_ACTION_TYPE_SHELL,
		Params: &pmv1.CreateActionRequest_Shell{Shell: &pmv1.ShellParams{Interpreter: "/bin/sh"}},
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = f.handlers.CreateAction(ctx, connect.NewRequest(&pmv1.CreateActionRequest{
		Name: "insecure package", Type: pmv1.ActionType_ACTION_TYPE_DEB,
		Params: &pmv1.CreateActionRequest_App{App: &pmv1.AppInstallParams{
			Url: "http://example.test/pkg.deb", ChecksumSha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}},
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = f.handlers.CreateAction(ctx, connect.NewRequest(&pmv1.CreateActionRequest{
		Name: "mismatch", Type: pmv1.ActionType_ACTION_TYPE_SHELL,
		Params: &pmv1.CreateActionRequest_Service{Service: &pmv1.ServiceParams{UnitName: "sshd"}},
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	state := authoring.New(authoring.Config{Store: f.store})
	op := actionOperation()
	system, err := state.CreateAction(context.Background(), op, authoring.CreateActionParams{
		Name: "system", CreatedBy: op.ActorID, Type: pmv1.ActionType_ACTION_TYPE_REBOOT,
		Params: []byte(`{}`), System: true,
	})
	require.NoError(t, err)
	_, err = f.handlers.RenameAction(ctx, connect.NewRequest(&pmv1.RenameActionRequest{Id: system.ID, Name: "operator"}))
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func TestActionHandlers_MountsExactSurface(t *testing.T) {
	f := newActionHandlerFixture(t)
	assert.Equal(t, []string{
		powermanagev1connect.ControlServiceCreateActionProcedure,
		powermanagev1connect.ControlServiceGetActionProcedure,
		powermanagev1connect.ControlServiceListActionsProcedure,
		powermanagev1connect.ControlServiceRenameActionProcedure,
		powermanagev1connect.ControlServiceUpdateActionDescriptionProcedure,
		powermanagev1connect.ControlServiceUpdateActionParamsProcedure,
		powermanagev1connect.ControlServiceDeleteActionProcedure,
	}, f.handlers.MountActions(http.NewServeMux()))
}
