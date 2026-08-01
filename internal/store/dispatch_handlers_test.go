package store_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/dispatch"
	"github.com/manchtools/power-manage/server/internal/store"
)

type dispatchHandlerFixture struct {
	t        *testing.T
	store    *store.Store
	raw      *pgxpool.Pool
	handlers *dispatch.Handlers
	waker    *committedWaker
	now      time.Time
	actorID  string
	deviceID string
	actionID string
}

func newDispatchHandlerFixture(t *testing.T) *dispatchHandlerFixture {
	t.Helper()
	st, raw := setupPostgres(t)
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	f := &dispatchHandlerFixture{
		t: t, store: st, raw: raw, now: now, actorID: newID(),
		deviceID: seedDevice(t, raw), actionID: newID(),
	}
	_, err := raw.Exec(context.Background(), `
		INSERT INTO actions
			(id, name, action_type, desired_state, params, timeout_seconds, schedule, created_at)
		VALUES ($1, 'catalog shell', $2, $3, $4::jsonb, 90, $5::jsonb, $6)`,
		f.actionID, int32(pmv1.ActionType_ACTION_TYPE_SHELL),
		int32(pmv1.DesiredState_DESIRED_STATE_ABSENT),
		`{"script":"printf catalog","interpreter":"/bin/sh"}`,
		`{"cron":"0 4 * * *"}`, now)
	require.NoError(t, err)
	f.waker = &committedWaker{store: st}
	f.handlers = dispatch.NewHandlers(dispatch.HandlersConfig{
		Store: st, Waker: f.waker,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:    func() time.Time { return now },
	})
	return f
}

func (f *dispatchHandlerFixture) actor(perms ...string) context.Context {
	return auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser, Permissions: perms,
	})
}

func (f *dispatchHandlerFixture) manifest(deliveryID string) *pmv1.Manifest {
	f.t.Helper()
	row, err := f.store.GetDelivery(context.Background(), deliveryID)
	require.NoError(f.t, err)
	var result pmv1.Manifest
	require.NoError(f.t, protojson.Unmarshal(row.Manifest, &result))
	return &result
}

func TestDispatchHandlers_CatalogAndInlineActionsUseDurableOneShotManifests(t *testing.T) {
	f := newDispatchHandlerFixture(t)
	ctx := f.actor("DispatchAction")

	catalog, err := f.handlers.DispatchAction(ctx, connect.NewRequest(&pmv1.DispatchActionRequest{
		DeviceId: f.deviceID,
		ActionSource: &pmv1.DispatchActionRequest_ActionId{
			ActionId: f.actionID,
		},
	}))
	require.NoError(t, err)
	require.Len(t, f.waker.ids, 1)
	assert.Equal(t, f.actionID, catalog.Msg.Execution.ActionId)
	assert.Equal(t, pmv1.ExecutionStatus_EXECUTION_STATUS_PENDING, catalog.Msg.Execution.Status)
	catalogManifest := f.manifest(f.waker.ids[0])
	require.NotNil(t, catalogManifest.Schedule)
	assert.Empty(t, catalogManifest.Schedule.Cron,
		"an explicit dispatch runs once instead of adopting the authored manifest schedule")
	assert.Zero(t, catalogManifest.Schedule.IntervalHours)
	assert.False(t, catalogManifest.Schedule.RunOnAssign)
	assert.False(t, catalogManifest.Schedule.SkipIfUnchanged)
	require.Len(t, catalogManifest.Occurrences, 1)
	assert.Equal(t, "0 4 * * *", catalogManifest.Occurrences[0].Action.Schedule.Cron,
		"the nested Action keeps its authoring/display schedule")

	inlineID := newID()
	inline, err := f.handlers.DispatchAction(ctx, connect.NewRequest(&pmv1.DispatchActionRequest{
		DeviceId: f.deviceID,
		ActionSource: &pmv1.DispatchActionRequest_InlineAction{InlineAction: &pmv1.Action{
			Id: &pmv1.ActionId{Value: inlineID}, Type: pmv1.ActionType_ACTION_TYPE_SHELL,
			DesiredState: pmv1.DesiredState_DESIRED_STATE_PRESENT,
			Params:       &pmv1.Action_Shell{Shell: &pmv1.ShellParams{Script: "printf inline"}},
		}},
	}))
	require.NoError(t, err)
	require.Len(t, f.waker.ids, 2)
	assert.Empty(t, inline.Msg.Execution.ActionId, "an inline action is not a catalog reference")
	inlineManifest := f.manifest(f.waker.ids[1])
	assert.Equal(t, inlineID, inlineManifest.Provenance.ActionId)
	assert.Equal(t, "printf inline", inlineManifest.Occurrences[0].Action.GetShell().Script)
	assert.Equal(t, int32(300), inlineManifest.Occurrences[0].Action.TimeoutSeconds)

	operation, err := latestOperationFor(t, f.store, f.raw,
		powermanagev1connect.ControlServiceDispatchActionProcedure)
	require.NoError(t, err)
	effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 2)
	assert.ElementsMatch(t, []string{"delivery", "execution"},
		[]string{effects[0].ResourceType, effects[1].ResourceType})
}

func TestDispatchHandlers_InstantSchedulingAndValidation(t *testing.T) {
	f := newDispatchHandlerFixture(t)
	runAt := f.now.Add(time.Hour)
	response, err := f.handlers.DispatchInstantAction(f.actor("DispatchInstantAction"),
		connect.NewRequest(&pmv1.DispatchInstantActionRequest{
			DeviceId: f.deviceID, InstantAction: pmv1.ActionType_ACTION_TYPE_REBOOT,
			RunAt: timestamppb.New(runAt),
		}))
	require.NoError(t, err)
	assert.Equal(t, pmv1.ExecutionStatus_EXECUTION_STATUS_SCHEDULED, response.Msg.Execution.Status)
	assert.True(t, response.Msg.Execution.ScheduledFor.AsTime().Equal(runAt))
	require.Len(t, f.waker.ids, 1)
	manifest := f.manifest(f.waker.ids[0])
	assert.Equal(t, pmv1.ActionType_ACTION_TYPE_REBOOT, manifest.Occurrences[0].Action.Type)
	assert.Equal(t, int32(600), manifest.Occurrences[0].Action.TimeoutSeconds)

	_, err = f.handlers.DispatchInstantAction(f.actor("DispatchInstantAction"),
		connect.NewRequest(&pmv1.DispatchInstantActionRequest{
			DeviceId: f.deviceID, InstantAction: pmv1.ActionType_ACTION_TYPE_SHELL,
		}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.DispatchInstantAction(context.Background(),
		connect.NewRequest(&pmv1.DispatchInstantActionRequest{
			DeviceId: f.deviceID, InstantAction: pmv1.ActionType_ACTION_TYPE_SYNC,
		}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))

	_, err = f.handlers.DispatchAction(f.actor("DispatchAction"), connect.NewRequest(&pmv1.DispatchActionRequest{
		DeviceId: f.deviceID,
		ActionSource: &pmv1.DispatchActionRequest_InlineAction{InlineAction: &pmv1.Action{
			Id: &pmv1.ActionId{Value: newID()}, Type: pmv1.ActionType_ACTION_TYPE_USER,
			Params: &pmv1.Action_Shell{Shell: &pmv1.ShellParams{Script: "mismatch"}},
		}},
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestDispatchHandlers_RefuseUnauthorizedAndMissingTargetsWithoutWork(t *testing.T) {
	f := newDispatchHandlerFixture(t)
	request := connect.NewRequest(&pmv1.DispatchActionRequest{
		DeviceId: f.deviceID,
		ActionSource: &pmv1.DispatchActionRequest_ActionId{
			ActionId: f.actionID,
		},
	})
	_, err := f.handlers.DispatchAction(f.actor(), request)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	request.Msg.DeviceId = newID()
	_, err = f.handlers.DispatchAction(f.actor("DispatchAction"), request)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	assert.Empty(t, f.waker.ids)
}

func TestDispatchHandlers_MountsExactInitialSurface(t *testing.T) {
	f := newDispatchHandlerFixture(t)
	assert.ElementsMatch(t, []string{
		powermanagev1connect.ControlServiceDispatchActionProcedure,
		powermanagev1connect.ControlServiceDispatchInstantActionProcedure,
	}, f.handlers.MountActions(http.NewServeMux()))
	assert.ElementsMatch(t, f.handlers.MountActions(http.NewServeMux()), dispatch.MutationProcedures())
}
