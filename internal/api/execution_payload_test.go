package api

// WS1b #2 — ExecutionCreated / ExecutionScheduled are emitted as the
// typed payloads.ExecutionCreated / payloads.ExecutionScheduled structs,
// not an ad-hoc map[string]any. This test drives the REAL dispatch
// handlers and reads the emitted event back, decoding STRICTLY (unknown
// fields disallowed) into the typed payload the projector consumes — so a
// stray or renamed key (the twin-drift the payloads package exists to
// prevent) fails here. The field-value assertions pin that every field the
// projector needs is populated, not silently COALESCE'd to a default.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// decodeExecutionCreated decodes an event's data strictly into the typed
// ExecutionCreated payload; DisallowUnknownFields makes a drifted key a
// failure rather than a silently-ignored field.
func decodeExecutionCreated(t *testing.T, data []byte) payloads.ExecutionCreated {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p payloads.ExecutionCreated
	require.NoError(t, dec.Decode(&p), "ExecutionCreated must decode into the typed payload with no unknown fields")
	return p
}

func TestExecutionCreatedEmittedTyped(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := NewActionHandler(st, slog.Default(), NoOpSigner{})
	h.SetTaskQueueClient(&NoOpEnqueuer{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "exec-typed-host")

	t.Run("inline DispatchAction → typed ExecutionCreated", func(t *testing.T) {
		resp, err := h.DispatchAction(ctx, connect.NewRequest(&pm.DispatchActionRequest{
			DeviceId: deviceID,
			ActionSource: &pm.DispatchActionRequest_InlineAction{InlineAction: &pm.Action{
				Id:             &pm.ActionId{Value: testutil.NewID()},
				Type:           pm.ActionType_ACTION_TYPE_SHELL,
				DesiredState:   pm.DesiredState_DESIRED_STATE_ABSENT,
				TimeoutSeconds: 222,
				Params:         &pm.Action_Shell{Shell: &pm.ShellParams{Script: "echo typed"}},
			}},
		}))
		require.NoError(t, err)

		events := loadEvents(t, st, "execution", resp.Msg.Execution.Id)
		require.Len(t, events, 1)
		require.Equal(t, string(eventtypes.ExecutionCreated), events[0].EventType)

		p := decodeExecutionCreated(t, events[0].Data)
		assert.Equal(t, deviceID, p.DeviceID)
		require.NotNil(t, p.ActionType)
		assert.Equal(t, int32(pm.ActionType_ACTION_TYPE_SHELL), *p.ActionType)
		require.NotNil(t, p.DesiredState)
		assert.Equal(t, int32(pm.DesiredState_DESIRED_STATE_ABSENT), *p.DesiredState)
		require.NotNil(t, p.TimeoutSeconds)
		assert.Equal(t, int32(222), *p.TimeoutSeconds)
		assert.Nil(t, p.ActionID, "inline dispatch carries no stored action id")

		// params round-trips to the executed shell script.
		require.NotEmpty(t, p.Params)
		var shell pm.ShellParams
		require.NoError(t, protojson.Unmarshal(p.Params, &shell))
		assert.Equal(t, "echo typed", shell.Script)
	})

	t.Run("by-id DispatchAction → typed ExecutionCreated with action_id", func(t *testing.T) {
		actionID := testutil.CreateTestAction(t, st, adminID, "typed-by-id", int(pm.ActionType_ACTION_TYPE_SHELL))
		resp, err := h.DispatchAction(ctx, connect.NewRequest(&pm.DispatchActionRequest{
			DeviceId:     deviceID,
			ActionSource: &pm.DispatchActionRequest_ActionId{ActionId: actionID},
		}))
		require.NoError(t, err)

		events := loadEvents(t, st, "execution", resp.Msg.Execution.Id)
		require.Len(t, events, 1)
		require.Equal(t, string(eventtypes.ExecutionCreated), events[0].EventType)

		p := decodeExecutionCreated(t, events[0].Data)
		assert.Equal(t, deviceID, p.DeviceID)
		require.NotNil(t, p.ActionID, "by-id dispatch MUST carry the stored action id")
		assert.Equal(t, actionID, *p.ActionID)
		require.NotNil(t, p.ActionType)
		assert.Equal(t, int32(pm.ActionType_ACTION_TYPE_SHELL), *p.ActionType)
		require.NotNil(t, p.DesiredState)
		assert.Equal(t, int32(pm.DesiredState_DESIRED_STATE_PRESENT), *p.DesiredState, "ad-hoc by-id dispatch defaults to PRESENT")
	})

	t.Run("DispatchInstantAction → typed ExecutionCreated", func(t *testing.T) {
		resp, err := h.DispatchInstantAction(ctx, connect.NewRequest(&pm.DispatchInstantActionRequest{
			DeviceId:      deviceID,
			InstantAction: pm.ActionType_ACTION_TYPE_REBOOT,
		}))
		require.NoError(t, err)

		events := loadEvents(t, st, "execution", resp.Msg.Execution.Id)
		require.Len(t, events, 1)
		require.Equal(t, string(eventtypes.ExecutionCreated), events[0].EventType)

		p := decodeExecutionCreated(t, events[0].Data)
		assert.Equal(t, deviceID, p.DeviceID)
		require.NotNil(t, p.ActionType)
		assert.Equal(t, int32(pm.ActionType_ACTION_TYPE_REBOOT), *p.ActionType)
		require.NotNil(t, p.TimeoutSeconds)
		assert.Equal(t, int32(600), *p.TimeoutSeconds, "REBOOT instant action carries a 600s timeout")
	})

	t.Run("deferred DispatchAction → typed ExecutionScheduled", func(t *testing.T) {
		runAt := timestamppb.New(time.Now().Add(time.Hour))
		resp, err := h.DispatchAction(ctx, connect.NewRequest(&pm.DispatchActionRequest{
			DeviceId: deviceID,
			RunAt:    runAt,
			ActionSource: &pm.DispatchActionRequest_InlineAction{InlineAction: &pm.Action{
				Id:             &pm.ActionId{Value: testutil.NewID()},
				Type:           pm.ActionType_ACTION_TYPE_SHELL,
				DesiredState:   pm.DesiredState_DESIRED_STATE_PRESENT,
				TimeoutSeconds: 90,
				Params:         &pm.Action_Shell{Shell: &pm.ShellParams{Script: "echo later"}},
			}},
		}))
		require.NoError(t, err)

		events := loadEvents(t, st, "execution", resp.Msg.Execution.Id)
		require.Len(t, events, 1)
		require.Equal(t, string(eventtypes.ExecutionScheduled), events[0].EventType)

		dec := json.NewDecoder(bytes.NewReader(events[0].Data))
		dec.DisallowUnknownFields()
		var p payloads.ExecutionScheduled
		require.NoError(t, dec.Decode(&p), "ExecutionScheduled must decode into the typed payload with no unknown fields")
		assert.Equal(t, deviceID, p.DeviceID)
		require.NotNil(t, p.ActionType)
		assert.Equal(t, int32(pm.ActionType_ACTION_TYPE_SHELL), *p.ActionType)
		assert.NotEmpty(t, p.ScheduledFor, "ExecutionScheduled MUST carry scheduled_for")
	})
}
