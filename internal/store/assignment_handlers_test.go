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
		VALUES ($1, 'assigned-device', decode(repeat('01', 32), 'hex'))`,
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

	for _, procedure := range assignment.MutationProcedures() {
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

func TestAssignmentHandlers_MountExactCRUDSurface(t *testing.T) {
	f := newAssignmentHandlerFixture(t)
	mounted := f.handlers.Mount(http.NewServeMux())
	want := []string{
		powermanagev1connect.ControlServiceCreateAssignmentProcedure,
		powermanagev1connect.ControlServiceDeleteAssignmentProcedure,
		powermanagev1connect.ControlServiceListAssignmentsProcedure,
		powermanagev1connect.ControlServiceGetUserAssignmentsProcedure,
	}
	assert.Equal(t, want, mounted)
	assert.Equal(t, []string{want[0], want[1]}, assignment.MutationProcedures())
	assert.Equal(t, []string{want[2], want[3]}, assignment.ReadProcedures())

	sorted := append([]string(nil), mounted...)
	sort.Strings(sorted)
	assert.Len(t, sorted, 4)
}
