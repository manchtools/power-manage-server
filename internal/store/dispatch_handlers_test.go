package store_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/manchtools/power-manage/server/internal/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	pmcrypto "github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/dispatch"
	"github.com/manchtools/power-manage/server/internal/store"
)

type dispatchHandlerFixture struct {
	t           *testing.T
	store       *store.Store
	raw         *testdb.DB
	handlers    *dispatch.Handlers
	waker       *committedWaker
	now         time.Time
	actorID     string
	deviceID    string
	otherDevice string
	groupID     string
	actionID    string
	set1        string
	set2        string
	definition  string
}

func newDispatchHandlerFixture(t *testing.T) *dispatchHandlerFixture {
	t.Helper()
	st, raw := setupSQLite(t)
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	f := &dispatchHandlerFixture{
		t: t, store: st, raw: raw, now: now, actorID: newID(),
		deviceID: seedDevice(t, raw), otherDevice: seedDevice(t, raw),
		groupID: newID(), actionID: newID(),
	}
	_, err := raw.Exec(context.Background(), `
		INSERT INTO device_groups (id, name, created_at) VALUES ($1, 'fanout', $2)`,
		f.groupID, now)
	require.NoError(t, err)
	_, err = raw.Exec(context.Background(), `
		INSERT INTO device_group_members (group_id, device_id, added_at) VALUES
			($1, $2, $4), ($1, $3, $4)`, f.groupID, f.deviceID, f.otherDevice, now)
	require.NoError(t, err)
	_, err = raw.Exec(context.Background(), `
		INSERT INTO actions
			(id, name, action_type, desired_state, params, timeout_seconds, schedule, created_at)
		VALUES ($1, 'catalog shell', $2, $3, $4, 90, $5, $6)`,
		f.actionID, int32(pmv1.ActionType_ACTION_TYPE_SHELL),
		int32(pmv1.DesiredState_DESIRED_STATE_ABSENT),
		`{"script":"printf catalog","interpreter":"/bin/sh"}`,
		`{"cron":"0 4 * * *"}`, now)
	require.NoError(t, err)
	f.set1, f.set2, f.definition = newID(), newID(), newID()
	_, err = raw.Exec(context.Background(), `
		INSERT INTO action_sets (id, name, schedule, on_failure, created_at) VALUES
			($1, 'first set', '{"cron":"0 2 * * *"}', $3, $5),
			($2, 'second set', '{"runOnAssign":true}', $4, $5)`,
		f.set1, f.set2,
		int32(pmv1.OnFailure_ON_FAILURE_STOP), int32(pmv1.OnFailure_ON_FAILURE_CONTINUE),
		now)
	require.NoError(t, err)
	_, err = raw.Exec(context.Background(), `
		INSERT INTO action_set_members (set_id, action_id, sort_order, added_at) VALUES
			($1, $3, 0, $4), ($2, $3, 0, $4)`, f.set1, f.set2, f.actionID, now)
	require.NoError(t, err)
	_, err = raw.Exec(context.Background(), `
		INSERT INTO definitions (id, name, schedule, created_at)
			VALUES ($1, 'two sets', '{"cron":"0 1 * * *"}', $2)`, f.definition, now)
	require.NoError(t, err)
	_, err = raw.Exec(context.Background(), `
		INSERT INTO definition_members (definition_id, action_set_id, sort_order, added_at) VALUES
			($1, $2, 0, $4), ($1, $3, 1, $4)`, f.definition, f.set1, f.set2, now)
	require.NoError(t, err)
	f.waker = &committedWaker{store: st}
	atRest, err := pmcrypto.NewEncryptor("0202020202020202020202020202020202020202020202020202020202020202")
	require.NoError(t, err)
	f.handlers = dispatch.NewHandlers(dispatch.HandlersConfig{
		Store: st, AtRest: atRest, Waker: f.waker,
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

func (f *dispatchHandlerFixture) assign(sourceType, sourceID, targetType, targetID string, mode pmv1.AssignmentMode) {
	f.t.Helper()
	_, err := f.raw.Exec(context.Background(), `
		INSERT INTO assignments
			(id, source_type, source_id, target_type, target_id, mode, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		newID(), sourceType, sourceID, targetType, targetID, int32(mode), f.now, f.actorID)
	require.NoError(f.t, err)
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

func TestDispatchHandlers_ActionSetAndDefinitionPreserveComposition(t *testing.T) {
	f := newDispatchHandlerFixture(t)
	setResponse, err := f.handlers.DispatchActionSet(f.actor("DispatchActionSet"),
		connect.NewRequest(&pmv1.DispatchActionSetRequest{
			DeviceId: f.deviceID, ActionSetId: f.set1,
		}))
	require.NoError(t, err)
	require.Len(t, setResponse.Msg.Executions, 1)
	require.Len(t, f.waker.ids, 1)
	setManifest := f.manifest(f.waker.ids[0])
	assert.Equal(t, f.set1, setManifest.Provenance.ActionSetId)
	assert.Empty(t, setManifest.Schedule.Cron)
	assert.Equal(t, pmv1.OnFailure_ON_FAILURE_STOP, setManifest.DefaultOnFailure)
	assert.Equal(t, pmv1.OnFailure_ON_FAILURE_STOP, setManifest.Occurrences[0].OnFailure)

	definitionResponse, err := f.handlers.DispatchDefinition(f.actor("DispatchDefinition"),
		connect.NewRequest(&pmv1.DispatchDefinitionRequest{
			DeviceId: f.deviceID, DefinitionId: f.definition,
		}))
	require.NoError(t, err)
	require.Len(t, definitionResponse.Msg.Executions, 2)
	require.Len(t, f.waker.ids, 3)
	first, second := f.manifest(f.waker.ids[1]), f.manifest(f.waker.ids[2])
	assert.Equal(t, f.definition, first.Provenance.DefinitionId)
	assert.Equal(t, f.definition, second.Provenance.DefinitionId)
	assert.ElementsMatch(t, []string{f.set1, f.set2},
		[]string{first.Provenance.ActionSetId, second.Provenance.ActionSetId})
	assert.NotEqual(t, definitionResponse.Msg.Executions[0].Id, definitionResponse.Msg.Executions[1].Id,
		"the same Action authored through two sets remains two occurrences")
	assert.Equal(t, definitionResponse.Msg.Executions[0].ActionId, definitionResponse.Msg.Executions[1].ActionId)
	operation, err := latestOperationFor(t, f.store, f.raw,
		powermanagev1connect.ControlServiceDispatchDefinitionProcedure)
	require.NoError(t, err)
	effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 4, "two deliveries and two executions share one initiating operation")
	for _, deliveryID := range f.waker.ids[1:] {
		row, err := f.store.GetDelivery(context.Background(), deliveryID)
		require.NoError(t, err)
		require.NotNil(t, row.OperationID)
		assert.Equal(t, operation.OperationID, *row.OperationID)
	}

	var set1Schedule, set2Schedule string
	require.NoError(t, f.raw.QueryRow(context.Background(), `
		SELECT (SELECT schedule FROM action_sets WHERE id = $1),
		       (SELECT schedule FROM action_sets WHERE id = $2)`, f.set1, f.set2).
		Scan(&set1Schedule, &set2Schedule))
	assert.JSONEq(t, `{"cron":"0 2 * * *"}`, set1Schedule)
	assert.JSONEq(t, `{"runOnAssign":true}`, set2Schedule)
}

func TestDispatchHandlers_ExplicitDispatchMarksEveryManifestOneShot(t *testing.T) {
	f := newDispatchHandlerFixture(t)

	_, err := f.handlers.DispatchAction(f.actor("DispatchAction"),
		connect.NewRequest(&pmv1.DispatchActionRequest{
			DeviceId:     f.deviceID,
			ActionSource: &pmv1.DispatchActionRequest_ActionId{ActionId: f.actionID},
		}))
	require.NoError(t, err)
	require.Len(t, f.waker.ids, 1)
	catalog := f.manifest(f.waker.ids[0])
	assert.True(t, catalog.GetOneShot(),
		"an explicitly dispatched catalog action executes exactly once")
	assert.Empty(t, catalog.Schedule.Cron)

	_, err = f.handlers.DispatchActionSet(f.actor("DispatchActionSet"),
		connect.NewRequest(&pmv1.DispatchActionSetRequest{
			DeviceId: f.deviceID, ActionSetId: f.set1,
		}))
	require.NoError(t, err)
	require.Len(t, f.waker.ids, 2)
	set := f.manifest(f.waker.ids[1])
	assert.True(t, set.GetOneShot(),
		"an explicitly dispatched ActionSet executes exactly once")
	assert.Empty(t, set.Schedule.Cron)

	_, err = f.handlers.DispatchDefinition(f.actor("DispatchDefinition"),
		connect.NewRequest(&pmv1.DispatchDefinitionRequest{
			DeviceId: f.deviceID, DefinitionId: f.definition,
		}))
	require.NoError(t, err)
	require.Len(t, f.waker.ids, 4)
	for _, deliveryID := range f.waker.ids[2:] {
		compiled := f.manifest(deliveryID)
		assert.True(t, compiled.GetOneShot(),
			"every manifest of an explicitly dispatched Definition executes exactly once")
		assert.Empty(t, compiled.Schedule.Cron)
	}
}

func TestDispatchHandlers_AssignedDispatchIsNotOneShot(t *testing.T) {
	f := newDispatchHandlerFixture(t)
	f.assign("action", f.actionID, "device", f.deviceID, pmv1.AssignmentMode_ASSIGNMENT_MODE_REQUIRED)

	_, err := f.handlers.DispatchAssignedActions(f.actor("DispatchAssignedActions"),
		connect.NewRequest(&pmv1.DispatchAssignedActionsRequest{DeviceId: f.deviceID}))
	require.NoError(t, err)
	require.Len(t, f.waker.ids, 1)
	compiled := f.manifest(f.waker.ids[0])
	assert.False(t, compiled.GetOneShot(),
		"assigned work stays scheduled and never becomes one-shot")
	assert.Equal(t, "0 4 * * *", compiled.Schedule.Cron)
}

func TestDispatchHandlers_AssignedDefinitionAbsorbsChildrenAndOverridesManifestSchedules(t *testing.T) {
	f := newDispatchHandlerFixture(t)
	f.assign("action", f.actionID, "device", f.deviceID, pmv1.AssignmentMode_ASSIGNMENT_MODE_REQUIRED)
	f.assign("action_set", f.set1, "device", f.deviceID, pmv1.AssignmentMode_ASSIGNMENT_MODE_REQUIRED)
	f.assign("definition", f.definition, "device", f.deviceID, pmv1.AssignmentMode_ASSIGNMENT_MODE_UNINSTALL)

	response, err := f.handlers.DispatchAssignedActions(f.actor("DispatchAssignedActions"),
		connect.NewRequest(&pmv1.DispatchAssignedActionsRequest{DeviceId: f.deviceID}))
	require.NoError(t, err)
	require.Len(t, response.Msg.Executions, 2,
		"the Definition emits one manifest per set and absorbs direct assignments to its children")
	require.Len(t, f.waker.ids, 2)
	for _, deliveryID := range f.waker.ids {
		compiled := f.manifest(deliveryID)
		assert.Equal(t, f.definition, compiled.Provenance.DefinitionId)
		assert.Equal(t, "0 1 * * *", compiled.Schedule.Cron,
			"the Definition schedule overrides only its compiled manifests")
		require.Len(t, compiled.Occurrences, 1)
		assert.Equal(t, pmv1.DesiredState_DESIRED_STATE_ABSENT,
			compiled.Occurrences[0].Action.DesiredState)
	}

	var set1Schedule, set2Schedule string
	require.NoError(t, f.raw.QueryRow(context.Background(), `
		SELECT (SELECT schedule FROM action_sets WHERE id = $1),
		       (SELECT schedule FROM action_sets WHERE id = $2)`, f.set1, f.set2).
		Scan(&set1Schedule, &set2Schedule))
	assert.JSONEq(t, `{"cron":"0 2 * * *"}`, set1Schedule)
	assert.JSONEq(t, `{"runOnAssign":true}`, set2Schedule)

	operation, err := latestOperationFor(t, f.store, f.raw,
		powermanagev1connect.ControlServiceDispatchAssignedActionsProcedure)
	require.NoError(t, err)
	effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 4)
}

func TestDispatchHandlers_ExcludedAssignedContainerAbsorbsDirectChildren(t *testing.T) {
	f := newDispatchHandlerFixture(t)
	f.assign("definition", f.definition, "device", f.deviceID, pmv1.AssignmentMode_ASSIGNMENT_MODE_REQUIRED)
	f.assign("definition", f.definition, "device_group", f.groupID, pmv1.AssignmentMode_ASSIGNMENT_MODE_EXCLUDED)
	f.assign("action_set", f.set1, "device", f.deviceID, pmv1.AssignmentMode_ASSIGNMENT_MODE_REQUIRED)
	f.assign("action", f.actionID, "device", f.deviceID, pmv1.AssignmentMode_ASSIGNMENT_MODE_REQUIRED)

	response, err := f.handlers.DispatchAssignedActions(f.actor("DispatchAssignedActions"),
		connect.NewRequest(&pmv1.DispatchAssignedActionsRequest{DeviceId: f.deviceID}))
	require.NoError(t, err)
	assert.Empty(t, response.Msg.Executions)
	assert.Empty(t, f.waker.ids)

	operation, err := latestOperationFor(t, f.store, f.raw,
		powermanagev1connect.ControlServiceDispatchAssignedActionsProcedure)
	require.NoError(t, err)
	effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 1, "an empty assigned dispatch is still an auditable operation")
	assert.Equal(t, "device", effects[0].ResourceType)
}

func TestDispatchHandlers_MultiDeviceAndGroupFanoutAreSingleOperations(t *testing.T) {
	f := newDispatchHandlerFixture(t)
	multiple, err := f.handlers.DispatchToMultiple(f.actor("DispatchToMultiple"),
		connect.NewRequest(&pmv1.DispatchToMultipleRequest{
			DeviceIds: []string{f.deviceID, f.otherDevice},
			ActionSource: &pmv1.DispatchToMultipleRequest_ActionId{
				ActionId: f.actionID,
			},
		}))
	require.NoError(t, err)
	require.Len(t, multiple.Msg.Executions, 2)
	assert.Equal(t, []string{f.deviceID, f.otherDevice}, []string{
		multiple.Msg.Executions[0].DeviceId, multiple.Msg.Executions[1].DeviceId,
	})
	require.Len(t, f.waker.ids, 2)
	firstManifest, secondManifest := f.manifest(f.waker.ids[0]), f.manifest(f.waker.ids[1])
	assert.NotEqual(t, firstManifest.ManifestId, secondManifest.ManifestId)
	assert.NotEqual(t, firstManifest.Occurrences[0].OccurrenceId, secondManifest.Occurrences[0].OccurrenceId)
	operation, err := latestOperationFor(t, f.store, f.raw,
		powermanagev1connect.ControlServiceDispatchToMultipleProcedure)
	require.NoError(t, err)
	effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 4)

	group, err := f.handlers.DispatchToGroup(f.actor("DispatchToGroup"),
		connect.NewRequest(&pmv1.DispatchToGroupRequest{
			GroupId: f.groupID,
			ActionSource: &pmv1.DispatchToGroupRequest_DefinitionId{
				DefinitionId: f.definition,
			},
		}))
	require.NoError(t, err)
	require.Len(t, group.Msg.Executions, 4, "two set manifests are copied to each of two devices")
	require.Len(t, f.waker.ids, 6)
	counts := map[string]int{}
	for _, execution := range group.Msg.Executions {
		counts[execution.DeviceId]++
	}
	assert.Equal(t, map[string]int{f.deviceID: 2, f.otherDevice: 2}, counts)
	operation, err = latestOperationFor(t, f.store, f.raw,
		powermanagev1connect.ControlServiceDispatchToGroupProcedure)
	require.NoError(t, err)
	effects, err = f.store.ListAuditEffects(context.Background(), operation.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 8, "four deliveries and four executions share the group operation")
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
	_, err = f.handlers.DispatchToMultiple(f.actor("DispatchToMultiple"),
		connect.NewRequest(&pmv1.DispatchToMultipleRequest{
			DeviceIds: []string{f.deviceID, f.deviceID},
			ActionSource: &pmv1.DispatchToMultipleRequest_ActionId{
				ActionId: f.actionID,
			},
		}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	assert.Empty(t, f.waker.ids)
}

func TestDispatchHandlers_MountsExactInitialSurface(t *testing.T) {
	f := newDispatchHandlerFixture(t)
	assert.ElementsMatch(t, []string{
		powermanagev1connect.ControlServiceDispatchActionProcedure,
		powermanagev1connect.ControlServiceDispatchInstantActionProcedure,
		powermanagev1connect.ControlServiceDispatchActionSetProcedure,
		powermanagev1connect.ControlServiceDispatchDefinitionProcedure,
		powermanagev1connect.ControlServiceDispatchToMultipleProcedure,
		powermanagev1connect.ControlServiceDispatchToGroupProcedure,
		powermanagev1connect.ControlServiceDispatchAssignedActionsProcedure,
	}, f.handlers.MountActions(http.NewServeMux()))
	assert.ElementsMatch(t, f.handlers.MountActions(http.NewServeMux()), dispatch.MutationProcedures())
}
