package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestNew_RunsMigrations(t *testing.T) {
	st := testutil.SetupPostgres(t)
	assert.NotNil(t, st.Queries())
	assert.NotNil(t, st.Pool())
}

func TestAppendEvent_Basic(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	id := testutil.NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "test",
		StreamID:   id,
		EventType:  "TestCreated",
		Data:       map[string]any{"key": "value"},
		ActorType:  "system",
		ActorID:    "test",
	})
	require.NoError(t, err)

	var count int64
	err = st.Pool().QueryRow(ctx, "SELECT COUNT(*) FROM events WHERE stream_id = $1", id).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestAppendEvent_AutoVersioning(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	id := testutil.NewID()

	for i := 0; i < 5; i++ {
		err := st.AppendEvent(ctx, store.Event{
			StreamType: "test",
			StreamID:   id,
			EventType:  "TestEvent",
			Data:       map[string]any{"seq": i},
			ActorType:  "system",
			ActorID:    "test",
		})
		require.NoError(t, err)
	}

	var maxVersion int32
	err := st.Pool().QueryRow(ctx,
		"SELECT MAX(stream_version) FROM events WHERE stream_id = $1", id,
	).Scan(&maxVersion)
	require.NoError(t, err)
	assert.Equal(t, int32(5), maxVersion)
}

func TestAppendEvent_RequiresActor(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "test",
		StreamID:   testutil.NewID(),
		EventType:  "TestCreated",
		Data:       map[string]any{},
		ActorType:  "",
		ActorID:    "",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "actor_type and actor_id are required")
}

func TestAppendEventWithVersion_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	id := testutil.NewID()

	err := st.AppendEventWithVersion(ctx, store.Event{
		StreamType: "test",
		StreamID:   id,
		EventType:  "TestCreated",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	}, 1)
	require.NoError(t, err)
}

func TestAppendEventWithVersion_Conflict(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	id := testutil.NewID()

	err := st.AppendEventWithVersion(ctx, store.Event{
		StreamType: "test",
		StreamID:   id,
		EventType:  "TestCreated",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	}, 1)
	require.NoError(t, err)

	err = st.AppendEventWithVersion(ctx, store.Event{
		StreamType: "test",
		StreamID:   id,
		EventType:  "TestUpdated",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	}, 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "version conflict")
}

func TestWithTx_Commit(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass123", "admin")

	err := st.WithTx(ctx, func(q *store.Queries) error {
		user, err := q.GetUserByID(ctx, userID)
		if err != nil {
			return err
		}
		assert.Equal(t, userID, user.ID)
		return nil
	})
	require.NoError(t, err)
}

func TestWithTx_Rollback(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	email := testutil.NewID() + "@rollback.com"

	err := st.WithTx(ctx, func(q *store.Queries) error {
		return assert.AnError
	})
	assert.Error(t, err)

	_, err = st.Queries().GetUserByEmail(ctx, email)
	assert.ErrorIs(t, err, pgx.ErrNoRows)
}

func TestNotify(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	err := st.Notify(ctx, "test_channel", `{"key":"value"}`)
	require.NoError(t, err)
}

// --- Projection Tests ---

func TestProjection_UserCreated(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "password123", "admin")

	user, err := st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)

	assert.Equal(t, userID, user.ID)
	assert.Equal(t, email, user.Email)
	assert.Equal(t, "admin", user.Role)
	assert.False(t, user.Disabled)
	assert.False(t, user.IsDeleted)
	assert.True(t, user.CreatedAt.Valid)
}

func TestProjection_UserEmailChanged(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")

	newEmail := testutil.NewID() + "@new.com"
	err := st.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  "UserEmailChanged",
		Data:       map[string]any{"email": newEmail},
		ActorType:  "user",
		ActorID:    userID,
	})
	require.NoError(t, err)

	user, err := st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, newEmail, user.Email)
}

func TestProjection_UserDisabledEnabled(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  "UserDisabled",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	})
	require.NoError(t, err)

	user, err := st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.True(t, user.Disabled)

	err = st.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  "UserEnabled",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	})
	require.NoError(t, err)

	user, err = st.Queries().GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.False(t, user.Disabled)
}

func TestProjection_UserDeleted(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  "UserDeleted",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	})
	require.NoError(t, err)

	_, err = st.Queries().GetUserByID(ctx, userID)
	assert.ErrorIs(t, err, pgx.ErrNoRows)
}

func TestProjection_DeviceRegistered(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	var hostname, agentVersion string
	err := st.Pool().QueryRow(ctx,
		"SELECT hostname, agent_version FROM devices_projection WHERE id = $1",
		deviceID,
	).Scan(&hostname, &agentVersion)
	require.NoError(t, err)

	assert.Equal(t, "test-host", hostname)
	assert.Empty(t, agentVersion) // agent_version is only set on DeviceSeen/DeviceHeartbeat, not DeviceRegistered
}

func TestProjection_DeviceHeartbeat(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "DeviceHeartbeat",
		Data: map[string]any{
			"agent_version": "2.0.0",
		},
		ActorType: "device",
		ActorID:   deviceID,
	})
	require.NoError(t, err)

	var agentVersion string
	err = st.Pool().QueryRow(ctx,
		"SELECT agent_version FROM devices_projection WHERE id = $1",
		deviceID,
	).Scan(&agentVersion)
	require.NoError(t, err)
	assert.Equal(t, "2.0.0", agentVersion)
}

func TestProjection_ActionCreated(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, actorID, "Install nginx", 1)

	var name string
	var actionType int32
	err := st.Pool().QueryRow(ctx,
		"SELECT name, action_type FROM actions_projection WHERE id = $1",
		actionID,
	).Scan(&name, &actionType)
	require.NoError(t, err)

	assert.Equal(t, "Install nginx", name)
	assert.Equal(t, int32(1), actionType)
}

func TestProjection_ActionSetWithMembers(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setID := testutil.CreateTestActionSet(t, st, actorID, "Web Server Setup")
	actionID := testutil.CreateTestAction(t, st, actorID, "Test Action", 1)

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "action_set",
		StreamID:   setID,
		EventType:  "ActionSetMemberAdded",
		Data: map[string]any{
			"action_id":  actionID,
			"sort_order": 0,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	require.NoError(t, err)

	var memberCount int32
	err = st.Pool().QueryRow(ctx,
		"SELECT member_count FROM action_sets_projection WHERE id = $1",
		setID,
	).Scan(&memberCount)
	require.NoError(t, err)
	assert.Equal(t, int32(1), memberCount)
}

func TestProjection_DefinitionCreated(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	defID := testutil.CreateTestDefinition(t, st, actorID, "Full Deploy")

	var name string
	err := st.Pool().QueryRow(ctx,
		"SELECT name FROM definitions_projection WHERE id = $1",
		defID,
	).Scan(&name)
	require.NoError(t, err)
	assert.Equal(t, "Full Deploy", name)
}

func TestProjection_DeviceGroupCreated(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, actorID, "Production")

	var name string
	var isDynamic bool
	err := st.Pool().QueryRow(ctx,
		"SELECT name, is_dynamic FROM device_groups_projection WHERE id = $1",
		groupID,
	).Scan(&name, &isDynamic)
	require.NoError(t, err)
	assert.Equal(t, "Production", name)
	assert.False(t, isDynamic)
}

func TestProjection_DeviceLabelSet(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "DeviceLabelSet",
		Data: map[string]any{
			"key":   "environment",
			"value": "production",
		},
		ActorType: "system",
		ActorID:   "test",
	})
	require.NoError(t, err)

	var labels []byte
	err = st.Pool().QueryRow(ctx,
		"SELECT labels FROM devices_projection WHERE id = $1",
		deviceID,
	).Scan(&labels)
	require.NoError(t, err)
	assert.Contains(t, string(labels), "environment")
	assert.Contains(t, string(labels), "production")
}

func TestProjection_TokenCreated(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	tokenID := testutil.CreateTestToken(t, st, actorID, "Test Token", "hash123")

	var name string
	err := st.Pool().QueryRow(ctx,
		"SELECT name FROM tokens_projection WHERE id = $1",
		tokenID,
	).Scan(&name)
	require.NoError(t, err)
	assert.Equal(t, "Test Token", name)
}

func TestProjection_ExecutionLifecycle(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	deviceID := testutil.CreateTestDevice(t, st, "exec-host")
	execID := testutil.NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "execution",
		StreamID:   execID,
		EventType:  "ExecutionCreated",
		Data: map[string]any{
			"device_id":       deviceID,
			"action_type":     1,
			"desired_state":   1,
			"params":          map[string]any{"name": "nginx"},
			"timeout_seconds": 300,
		},
		ActorType: "user",
		ActorID:   "test-actor",
	})
	require.NoError(t, err)

	err = st.AppendEvent(ctx, store.Event{
		StreamType: "execution",
		StreamID:   execID,
		EventType:  "ExecutionDispatched",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	})
	require.NoError(t, err)

	var status string
	err = st.Pool().QueryRow(ctx,
		"SELECT status FROM executions_projection WHERE id = $1",
		execID,
	).Scan(&status)
	require.NoError(t, err)
	assert.Equal(t, "dispatched", status)

	completedAt := time.Now().Format(time.RFC3339Nano)
	err = st.AppendEvent(ctx, store.Event{
		StreamType: "execution",
		StreamID:   execID,
		EventType:  "ExecutionCompleted",
		Data: map[string]any{
			"duration_ms":  1500,
			"completed_at": completedAt,
			"changed":      true,
		},
		ActorType: "device",
		ActorID:   deviceID,
	})
	require.NoError(t, err)

	err = st.Pool().QueryRow(ctx,
		"SELECT status FROM executions_projection WHERE id = $1",
		execID,
	).Scan(&status)
	require.NoError(t, err)
	assert.Equal(t, "success", status)
}

func TestProjection_AssignmentCreated(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	assignmentID := testutil.NewID()
	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, actorID, "Test", 1)
	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "assignment",
		StreamID:   assignmentID,
		EventType:  "AssignmentCreated",
		Data: map[string]any{
			"source_type": "action",
			"source_id":   actionID,
			"target_type": "device",
			"target_id":   deviceID,
			"mode":        1,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	require.NoError(t, err)

	var sourceType, sourceID, targetType, targetID string
	err = st.Pool().QueryRow(ctx,
		"SELECT source_type, source_id, target_type, target_id FROM assignments_projection WHERE id = $1",
		assignmentID,
	).Scan(&sourceType, &sourceID, &targetType, &targetID)
	require.NoError(t, err)
	assert.Equal(t, "action", sourceType)
	assert.Equal(t, actionID, sourceID)
	assert.Equal(t, "device", targetType)
	assert.Equal(t, deviceID, targetID)
}
