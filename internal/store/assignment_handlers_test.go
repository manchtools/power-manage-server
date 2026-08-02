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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/assignment"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/authoring"
	"github.com/manchtools/power-manage/server/internal/compliance"
)

type assignmentHandlerFixture struct {
	*actionHandlerFixture
	handlers *assignment.Handlers
	sources  map[pmv1.AssignmentSourceType]string
	targets  map[pmv1.AssignmentTargetType]string
	systemID string
}

func newAssignmentHandlerFixture(t *testing.T) *assignmentHandlerFixture {
	t.Helper()
	actions := newActionHandlerFixture(t)
	f := &assignmentHandlerFixture{
		actionHandlerFixture: actions,
		handlers: assignment.New(assignment.Config{
			Store: actions.store, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Now: func() time.Time { return actions.now },
		}),
		sources: make(map[pmv1.AssignmentSourceType]string),
		targets: make(map[pmv1.AssignmentTargetType]string),
	}

	state := authoring.New(authoring.Config{Store: actions.store, Now: func() time.Time { return actions.now }})
	normal := createPolicyAction(t, state, "assigned action", false)
	f.sources[pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION] = normal

	op := actionOperation()
	set, err := state.CreateActionSet(context.Background(), op, authoring.CreateActionSetParams{
		Name: "assigned set", CreatedBy: op.ActorID,
		Schedule: &pmv1.ActionSchedule{IntervalHours: 8},
	})
	require.NoError(t, err)
	f.sources[pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION_SET] = set.ID

	op = actionOperation()
	definition, err := state.CreateDefinition(context.Background(), op, authoring.CreateDefinitionParams{
		Name: "assigned definition", CreatedBy: op.ActorID,
		Schedule: &pmv1.ActionSchedule{IntervalHours: 8},
	})
	require.NoError(t, err)
	f.sources[pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_DEFINITION] = definition.ID

	op = actionOperation()
	policy, err := compliance.NewState(compliance.StateConfig{Store: actions.store, Now: func() time.Time { return actions.now }}).
		Create(context.Background(), op, compliance.CreateParams{Name: "assigned policy", CreatedBy: op.ActorID})
	require.NoError(t, err)
	f.sources[pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_COMPLIANCE_POLICY] = policy.ID

	op = actionOperation()
	system, err := state.CreateAction(context.Background(), op, authoring.CreateActionParams{
		Name: "system action", CreatedBy: op.ActorID, System: true,
		Type: pmv1.ActionType_ACTION_TYPE_SHELL, DesiredState: pmv1.DesiredState_DESIRED_STATE_PRESENT,
		Params: []byte(`{"interpreter":"/bin/sh","script":"true"}`),
	})
	require.NoError(t, err)
	f.systemID = system.ID

	for _, targetType := range []pmv1.AssignmentTargetType{
		pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE,
		pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE_GROUP,
		pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER,
		pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER_GROUP,
	} {
		f.targets[targetType] = newID()
	}
	ctx := context.Background()
	_, err = f.raw.Exec(ctx, `INSERT INTO devices (id, hostname, agent_sealing_public_key)
		VALUES ($1, 'assigned-device', zeroblob(32))`,
		f.targets[pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE])
	require.NoError(t, err)
	_, err = f.raw.Exec(ctx, `INSERT INTO device_groups (id, name) VALUES ($1, 'assigned-device-group')`,
		f.targets[pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE_GROUP])
	require.NoError(t, err)
	_, err = f.raw.Exec(ctx, `INSERT INTO users (id, email, display_name, linux_username, linux_uid)
		VALUES ($1, 'assigned@example.test', 'Assigned User', 'assigned', 210001)`,
		f.targets[pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER])
	require.NoError(t, err)
	_, err = f.raw.Exec(ctx, `INSERT INTO user_groups (id, name, created_by) VALUES ($1, 'assigned-user-group', $2)`,
		f.targets[pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER_GROUP], f.actorID)
	require.NoError(t, err)
	return f
}

func TestAssignmentHandlers_ValidateBeforeAuthentication(t *testing.T) {
	f := newAssignmentHandlerFixture(t)
	_, err := f.handlers.DeleteAssignment(context.Background(), connect.NewRequest(&pmv1.DeleteAssignmentRequest{Id: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = f.handlers.DeleteAssignment(context.Background(), connect.NewRequest(&pmv1.DeleteAssignmentRequest{Id: newID()}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestAssignmentHandlers_CRUDAcrossEverySourceAndTarget(t *testing.T) {
	f := newAssignmentHandlerFixture(t)
	ctx := f.actor("CreateAssignment", "DeleteAssignment", "ListAssignments")
	types := []struct {
		source pmv1.AssignmentSourceType
		target pmv1.AssignmentTargetType
	}{
		{pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION, pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE},
		{pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION_SET, pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE_GROUP},
		{pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_DEFINITION, pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER},
		{pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_COMPLIANCE_POLICY, pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER_GROUP},
	}
	created := make([]*pmv1.Assignment, 0, len(types))
	for _, pair := range types {
		response, err := f.handlers.CreateAssignment(ctx, connect.NewRequest(&pmv1.CreateAssignmentRequest{
			SourceType: pair.source, SourceId: f.sources[pair.source],
			TargetType: pair.target, TargetId: f.targets[pair.target],
			Mode: pmv1.AssignmentMode_ASSIGNMENT_MODE_AVAILABLE,
		}))
		require.NoError(t, err)
		created = append(created, response.Msg.Assignment)
		assert.NotEmpty(t, response.Msg.Assignment.SourceName)
		assert.NotEmpty(t, response.Msg.Assignment.TargetName)
		assert.True(t, response.Msg.Assignment.CreatedAt.AsTime().Equal(f.now))
	}

	duplicate, err := f.handlers.CreateAssignment(ctx, connect.NewRequest(&pmv1.CreateAssignmentRequest{
		SourceType: created[0].SourceType, SourceId: created[0].SourceId,
		TargetType: created[0].TargetType, TargetId: created[0].TargetId,
	}))
	require.NoError(t, err)
	assert.Equal(t, created[0].Id, duplicate.Msg.Assignment.Id, "active duplicate is idempotent")

	listed, err := f.handlers.ListAssignments(ctx, connect.NewRequest(&pmv1.ListAssignmentsRequest{}))
	require.NoError(t, err)
	require.Len(t, listed.Msg.Assignments, 4)
	assert.Equal(t, int32(4), listed.Msg.TotalCount)

	filtered, err := f.handlers.ListAssignments(ctx, connect.NewRequest(&pmv1.ListAssignmentsRequest{
		SourceType: pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION_SET,
	}))
	require.NoError(t, err)
	require.Len(t, filtered.Msg.Assignments, 1)
	assert.Equal(t, f.sources[pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION_SET], filtered.Msg.Assignments[0].SourceId)

	page, err := f.handlers.ListAssignments(ctx, connect.NewRequest(&pmv1.ListAssignmentsRequest{PageSize: 1}))
	require.NoError(t, err)
	require.Len(t, page.Msg.Assignments, 1)
	assert.NotEmpty(t, page.Msg.NextPageToken)

	_, err = f.handlers.DeleteAssignment(ctx, connect.NewRequest(&pmv1.DeleteAssignmentRequest{Id: created[0].Id}))
	require.NoError(t, err)
	recreated, err := f.handlers.CreateAssignment(ctx, connect.NewRequest(&pmv1.CreateAssignmentRequest{
		SourceType: created[0].SourceType, SourceId: created[0].SourceId,
		TargetType: created[0].TargetType, TargetId: created[0].TargetId,
		Mode: pmv1.AssignmentMode_ASSIGNMENT_MODE_UNINSTALL,
	}))
	require.NoError(t, err)
	assert.Equal(t, created[0].Id, recreated.Msg.Assignment.Id, "soft-deleted tuple is reactivated")
	assert.Equal(t, pmv1.AssignmentMode_ASSIGNMENT_MODE_UNINSTALL, recreated.Msg.Assignment.Mode)

	for _, procedure := range []string{
		powermanagev1connect.ControlServiceCreateAssignmentProcedure,
		powermanagev1connect.ControlServiceDeleteAssignmentProcedure,
	} {
		operation, err := latestOperationFor(t, f.store, f.raw, procedure)
		require.NoError(t, err, procedure)
		effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
		require.NoError(t, err, procedure)
		assert.NotEmpty(t, effects, procedure)
	}
}

func TestAssignmentHandlers_RejectSystemAndMissingResources(t *testing.T) {
	f := newAssignmentHandlerFixture(t)
	ctx := f.actor("CreateAssignment")
	_, err := f.handlers.CreateAssignment(ctx, connect.NewRequest(&pmv1.CreateAssignmentRequest{
		SourceType: pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION, SourceId: f.systemID,
		TargetType: pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE,
		TargetId:   f.targets[pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE],
	}))
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))

	_, err = f.handlers.CreateAssignment(ctx, connect.NewRequest(&pmv1.CreateAssignmentRequest{
		SourceType: pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION, SourceId: newID(),
		TargetType: pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE,
		TargetId:   f.targets[pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE],
	}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	_, err = f.handlers.CreateAssignment(ctx, connect.NewRequest(&pmv1.CreateAssignmentRequest{
		SourceType: pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION,
		SourceId:   f.sources[pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION],
		TargetType: pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE, TargetId: newID(),
	}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestAssignmentHandlers_GetUserAssignmentsResolvesDirectAndGroupTargets(t *testing.T) {
	f := newAssignmentHandlerFixture(t)
	ctx := f.actor("CreateAssignment", "GetUserAssignments")
	userID := f.targets[pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER]
	groupID := f.targets[pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER_GROUP]
	_, err := f.raw.Exec(context.Background(),
		`INSERT INTO user_group_members (group_id, user_id, added_by) VALUES ($1, $2, $3)`,
		groupID, userID, f.actorID)
	require.NoError(t, err)

	direct, err := f.handlers.CreateAssignment(ctx, connect.NewRequest(&pmv1.CreateAssignmentRequest{
		SourceType: pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION,
		SourceId:   f.sources[pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION],
		TargetType: pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER,
		TargetId:   userID,
	}))
	require.NoError(t, err)
	group, err := f.handlers.CreateAssignment(ctx, connect.NewRequest(&pmv1.CreateAssignmentRequest{
		SourceType: pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION_SET,
		SourceId:   f.sources[pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION_SET],
		TargetType: pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER_GROUP,
		TargetId:   groupID,
	}))
	require.NoError(t, err)

	response, err := f.handlers.GetUserAssignments(ctx, connect.NewRequest(&pmv1.GetUserAssignmentsRequest{UserId: userID}))
	require.NoError(t, err)
	require.Len(t, response.Msg.Assignments, 2)
	assert.Equal(t, []string{direct.Msg.Assignment.Id, group.Msg.Assignment.Id}, []string{
		response.Msg.Assignments[0].Id, response.Msg.Assignments[1].Id,
	})
	for _, assignment := range response.Msg.Assignments {
		assert.NotEmpty(t, assignment.SourceName)
		assert.NotEmpty(t, assignment.TargetName)
	}
}

func TestAssignmentHandlers_AvailableSelectionIsAuditedDirectState(t *testing.T) {
	f := newAssignmentHandlerFixture(t)
	ctx := f.actor("CreateAssignment", "SetUserSelection", "ListAvailableActions", "ListDevices")
	deviceID := f.targets[pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE]
	actionID := f.sources[pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION]

	_, err := f.handlers.CreateAssignment(ctx, connect.NewRequest(&pmv1.CreateAssignmentRequest{
		SourceType: pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION,
		SourceId:   actionID,
		TargetType: pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE,
		TargetId:   deviceID,
		Mode:       pmv1.AssignmentMode_ASSIGNMENT_MODE_AVAILABLE,
	}))
	require.NoError(t, err)

	before, err := f.handlers.ListAvailableActions(ctx, connect.NewRequest(&pmv1.ListAvailableActionsRequest{DeviceId: deviceID}))
	require.NoError(t, err)
	require.Len(t, before.Msg.Items, 1)
	assert.Equal(t, actionID, before.Msg.Items[0].SourceId)
	assert.False(t, before.Msg.Items[0].Selected)
	require.Len(t, before.Msg.Items[0].Actions, 1)
	assert.Equal(t, actionID, before.Msg.Items[0].Actions[0].Id)

	selected, err := f.handlers.SetUserSelection(ctx, connect.NewRequest(&pmv1.SetUserSelectionRequest{
		DeviceId: deviceID, SourceType: pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION,
		SourceId: actionID, Selected: true,
	}))
	require.NoError(t, err)
	assert.True(t, selected.Msg.Selection.Selected)
	selectionID := selected.Msg.Selection.Id

	after, err := f.handlers.ListAvailableActions(ctx, connect.NewRequest(&pmv1.ListAvailableActionsRequest{DeviceId: deviceID}))
	require.NoError(t, err)
	require.Len(t, after.Msg.Items, 1)
	assert.True(t, after.Msg.Items[0].Selected)

	deselected, err := f.handlers.SetUserSelection(ctx, connect.NewRequest(&pmv1.SetUserSelectionRequest{
		DeviceId: deviceID, SourceType: pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION,
		SourceId: actionID, Selected: false,
	}))
	require.NoError(t, err)
	assert.Equal(t, selectionID, deselected.Msg.Selection.Id, "the source tuple owns one stable selection row")
	assert.False(t, deselected.Msg.Selection.Selected)

	operations := 0
	rows, err := f.raw.Query(context.Background(),
		`SELECT operation_id FROM audit_operations WHERE request_descriptor = $1 ORDER BY chain_seq`,
		powermanagev1connect.ControlServiceSetUserSelectionProcedure)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var operationID string
		require.NoError(t, rows.Scan(&operationID))
		effects, err := f.store.ListAuditEffects(context.Background(), operationID)
		require.NoError(t, err)
		require.Len(t, effects, 1)
		assert.Equal(t, "user_selection", effects[0].ResourceType)
		operations++
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, 2, operations)
}

func TestAssignmentHandlers_SelectionRequiresAnAvailableAssignmentAndDeviceAccess(t *testing.T) {
	f := newAssignmentHandlerFixture(t)
	deviceID := f.targets[pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE]
	actionID := f.sources[pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION]

	ctx := f.actor("SetUserSelection", "ListDevices")
	_, err := f.handlers.SetUserSelection(ctx, connect.NewRequest(&pmv1.SetUserSelectionRequest{
		DeviceId: deviceID, SourceType: pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION,
		SourceId: actionID, Selected: true,
	}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	assignedOnly := f.actor("SetUserSelection", "ListDevices:assigned")
	_, err = f.handlers.SetUserSelection(assignedOnly, connect.NewRequest(&pmv1.SetUserSelectionRequest{
		DeviceId: deviceID, SourceType: pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION,
		SourceId: actionID, Selected: true,
	}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "an unassigned actor gets no device existence oracle")
}

func TestAssignmentHandlers_AvailableSourcesResolveEveryTargetKind(t *testing.T) {
	f := newAssignmentHandlerFixture(t)
	ctx := f.actor("CreateAssignment", "ListAvailableActions", "ListDevices")
	deviceID := f.targets[pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE]
	deviceGroupID := f.targets[pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE_GROUP]
	userID := f.targets[pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER]
	userGroupID := f.targets[pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER_GROUP]

	_, err := f.raw.Exec(context.Background(),
		`INSERT INTO device_group_members (group_id, device_id) VALUES ($1, $2)`, deviceGroupID, deviceID)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(),
		`INSERT INTO device_assigned_users (device_id, user_id, assigned_by) VALUES ($1, $2, $3)`,
		deviceID, userID, f.actorID)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(),
		`INSERT INTO device_assigned_groups (device_id, group_id, assigned_by) VALUES ($1, $2, $3)`,
		deviceID, userGroupID, f.actorID)
	require.NoError(t, err)

	pairs := []struct {
		source pmv1.AssignmentSourceType
		target pmv1.AssignmentTargetType
	}{
		{pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION, pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE},
		{pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION_SET, pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE_GROUP},
		{pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_DEFINITION, pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER},
		{pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_COMPLIANCE_POLICY, pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER_GROUP},
	}
	for _, pair := range pairs {
		_, err := f.handlers.CreateAssignment(ctx, connect.NewRequest(&pmv1.CreateAssignmentRequest{
			SourceType: pair.source, SourceId: f.sources[pair.source],
			TargetType: pair.target, TargetId: f.targets[pair.target],
			Mode: pmv1.AssignmentMode_ASSIGNMENT_MODE_AVAILABLE,
		}))
		require.NoError(t, err)
	}

	response, err := f.handlers.ListAvailableActions(ctx, connect.NewRequest(&pmv1.ListAvailableActionsRequest{DeviceId: deviceID}))
	require.NoError(t, err)
	require.Len(t, response.Msg.Items, 4)
	for _, item := range response.Msg.Items {
		assert.Equal(t, f.sources[item.SourceType], item.SourceId)
		assert.NotEmpty(t, item.SourceName)
	}

	assignedCtx := auth.WithUser(context.Background(), &auth.UserContext{
		ID: userID, Kind: auth.PrincipalUser,
		Permissions: []string{"ListAvailableActions", "ListDevices:assigned"},
	})
	assigned, err := f.handlers.ListAvailableActions(assignedCtx,
		connect.NewRequest(&pmv1.ListAvailableActionsRequest{DeviceId: deviceID}))
	require.NoError(t, err)
	assert.Len(t, assigned.Msg.Items, 4)
}

func TestAssignmentHandlers_AvailableSourceIsHiddenByStrongerMode(t *testing.T) {
	f := newAssignmentHandlerFixture(t)
	ctx := f.actor("CreateAssignment", "ListAvailableActions", "ListDevices")
	deviceID := f.targets[pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE]
	groupID := f.targets[pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE_GROUP]
	actionID := f.sources[pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION]

	_, err := f.raw.Exec(context.Background(),
		`INSERT INTO device_group_members (group_id, device_id) VALUES ($1, $2)`, groupID, deviceID)
	require.NoError(t, err)
	for _, assignment := range []*pmv1.CreateAssignmentRequest{
		{
			SourceType: pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION, SourceId: actionID,
			TargetType: pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE, TargetId: deviceID,
			Mode: pmv1.AssignmentMode_ASSIGNMENT_MODE_AVAILABLE,
		},
		{
			SourceType: pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION, SourceId: actionID,
			TargetType: pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE_GROUP, TargetId: groupID,
			Mode: pmv1.AssignmentMode_ASSIGNMENT_MODE_REQUIRED,
		},
	} {
		_, err := f.handlers.CreateAssignment(ctx, connect.NewRequest(assignment))
		require.NoError(t, err)
	}

	response, err := f.handlers.ListAvailableActions(ctx,
		connect.NewRequest(&pmv1.ListAvailableActionsRequest{DeviceId: deviceID}))
	require.NoError(t, err)
	assert.Empty(t, response.Msg.Items, "a required source is not also an optional choice")
}

func TestAssignmentHandlers_GetDeviceAssignmentsExpandsLiveSources(t *testing.T) {
	f := newAssignmentHandlerFixture(t)
	ctx := f.actor("CreateAssignment", "GetDeviceAssignments", "SetUserSelection", "ListDevices")
	deviceID := f.targets[pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE]
	actionID := f.sources[pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION]
	setID := f.sources[pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION_SET]
	definitionID := f.sources[pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_DEFINITION]
	policyID := f.sources[pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_COMPLIANCE_POLICY]

	_, err := f.raw.Exec(context.Background(),
		`INSERT INTO action_set_members (set_id, action_id, sort_order) VALUES ($1, $2, 0)`, setID, actionID)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(),
		`INSERT INTO definition_members (definition_id, action_set_id, sort_order) VALUES ($1, $2, 0)`, definitionID, setID)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(),
		`INSERT INTO compliance_policy_rules (policy_id, action_id, action_name) VALUES ($1, $2, 'assigned action')`,
		policyID, actionID)
	require.NoError(t, err)

	for _, source := range []pmv1.AssignmentSourceType{
		pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION,
		pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION_SET,
		pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_DEFINITION,
		pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_COMPLIANCE_POLICY,
	} {
		_, err := f.handlers.CreateAssignment(ctx, connect.NewRequest(&pmv1.CreateAssignmentRequest{
			SourceType: source, SourceId: f.sources[source],
			TargetType: pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE,
			TargetId:   deviceID,
		}))
		require.NoError(t, err)
	}

	authoringState := authoring.New(authoring.Config{Store: f.store, Now: func() time.Time { return f.now }})
	availableID := createPolicyAction(t, authoringState, "selected optional action", false)
	excludedID := createPolicyAction(t, authoringState, "excluded action", false)
	uninstallID := createPolicyAction(t, authoringState, "uninstall action", false)
	for id, mode := range map[string]pmv1.AssignmentMode{
		availableID: pmv1.AssignmentMode_ASSIGNMENT_MODE_AVAILABLE,
		excludedID:  pmv1.AssignmentMode_ASSIGNMENT_MODE_EXCLUDED,
		uninstallID: pmv1.AssignmentMode_ASSIGNMENT_MODE_UNINSTALL,
	} {
		_, err := f.handlers.CreateAssignment(ctx, connect.NewRequest(&pmv1.CreateAssignmentRequest{
			SourceType: pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION, SourceId: id,
			TargetType: pmv1.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_DEVICE, TargetId: deviceID,
			Mode: mode,
		}))
		require.NoError(t, err)
	}
	_, err = f.handlers.SetUserSelection(ctx, connect.NewRequest(&pmv1.SetUserSelectionRequest{
		DeviceId: deviceID, SourceType: pmv1.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION,
		SourceId: availableID, Selected: true,
	}))
	require.NoError(t, err)

	response, err := f.handlers.GetDeviceAssignments(ctx,
		connect.NewRequest(&pmv1.GetDeviceAssignmentsRequest{DeviceId: deviceID}))
	require.NoError(t, err)
	require.Len(t, response.Msg.Actions, 3, "duplicates collapse, selected optional and uninstall remain, excluded is absent")
	actionsByID := make(map[string]*pmv1.ManagedAction, len(response.Msg.Actions))
	for _, action := range response.Msg.Actions {
		actionsByID[action.Id] = action
	}
	assert.Contains(t, actionsByID, actionID)
	assert.Contains(t, actionsByID, availableID)
	assert.NotContains(t, actionsByID, excludedID)
	require.Contains(t, actionsByID, uninstallID)
	assert.Equal(t, pmv1.DesiredState_DESIRED_STATE_ABSENT, actionsByID[uninstallID].DesiredState)
	require.Len(t, response.Msg.ActionSets, 1)
	assert.Equal(t, setID, response.Msg.ActionSets[0].Id)
	require.Len(t, response.Msg.ActionSetDetails, 1)
	require.Len(t, response.Msg.ActionSetDetails[0].Members, 1)
	require.Len(t, response.Msg.Definitions, 1)
	assert.Equal(t, definitionID, response.Msg.Definitions[0].Id)
	require.Len(t, response.Msg.DefinitionDetails, 1)
	require.Len(t, response.Msg.DefinitionDetails[0].Members, 1)
	require.Len(t, response.Msg.CompliancePolicies, 1)
	assert.Equal(t, policyID, response.Msg.CompliancePolicies[0].Id)
}

func TestAssignmentHandlers_MountExactCRUDSurface(t *testing.T) {
	f := newAssignmentHandlerFixture(t)
	mounted := f.handlers.Mount(http.NewServeMux())
	want := []string{
		powermanagev1connect.ControlServiceCreateAssignmentProcedure,
		powermanagev1connect.ControlServiceDeleteAssignmentProcedure,
		powermanagev1connect.ControlServiceListAssignmentsProcedure,
		powermanagev1connect.ControlServiceGetUserAssignmentsProcedure,
		powermanagev1connect.ControlServiceSetUserSelectionProcedure,
		powermanagev1connect.ControlServiceListAvailableActionsProcedure,
		powermanagev1connect.ControlServiceGetDeviceAssignmentsProcedure,
	}
	assert.Equal(t, want, mounted)
	assert.Equal(t, []string{want[0], want[1], want[4]}, assignment.MutationProcedures())
	assert.Equal(t, []string{want[2], want[3], want[5], want[6]}, assignment.ReadProcedures())

	sorted := append([]string(nil), mounted...)
	sort.Strings(sorted)
	assert.Len(t, sorted, 7)
}
