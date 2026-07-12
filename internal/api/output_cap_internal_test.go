package api

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestLoadLiveOutput_BoundsFloodedOutput pins spec 29 S6: execution output is
// bounded on read by BOTH a row LIMIT (how many OutputChunk rows are loaded into
// memory) and a cumulative byte budget (how much is concatenated), so a chunk
// flood on one execution can't exhaust control memory. Uses the package-var
// seams to shrink the caps to test scale.
func TestLoadLiveOutput_BoundsFloodedOutput(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := NewActionHandler(st, slog.Default(), NoOpSigner{})
	h.SetTaskQueueClient(&NoOpEnqueuer{})
	admin := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(admin)
	device := testutil.CreateTestDevice(t, st, "output-host")

	// seed creates an execution and appends n stdout OutputChunk events of `data`.
	seed := func(n int, data string) string {
		execID := testutil.NewID()
		require.NoError(t, st.AppendEvent(context.Background(), store.Event{
			StreamType: "execution", StreamID: execID, EventType: "ExecutionCreated",
			Data: map[string]any{
				"device_id": device, "action_type": int(pm.ActionType_ACTION_TYPE_SHELL),
				"desired_state": 0, "params": map[string]any{}, "timeout_seconds": 300,
			},
			ActorType: "user", ActorID: admin,
		}))
		for i := 0; i < n; i++ {
			require.NoError(t, st.AppendEvent(context.Background(), store.Event{
				StreamType: "execution", StreamID: execID, EventType: "OutputChunk",
				Data:      map[string]any{"stream": "stdout", "data": data, "sequence": i},
				ActorType: "device", ActorID: device,
			}))
		}
		return execID
	}

	liveOut := func(execID string) *pm.CommandOutput {
		resp, err := h.GetExecution(ctx, connect.NewRequest(&pm.GetExecutionRequest{Id: execID}))
		require.NoError(t, err)
		return resp.Msg.Execution.LiveOutput
	}

	t.Run("row limit bounds the chunks read", func(t *testing.T) {
		origRows, origBytes := maxOutputChunkRows, maxLiveOutputBytes
		t.Cleanup(func() { maxOutputChunkRows, maxLiveOutputBytes = origRows, origBytes })
		maxOutputChunkRows, maxLiveOutputBytes = 5, 1<<20 // large byte budget so only the row limit bites

		out := liveOut(seed(12, "X"))
		require.NotNil(t, out)
		assert.Len(t, out.Stdout, 5, "only maxOutputChunkRows (5) chunks should be read, not all 12")
		assert.Contains(t, out.Stderr, "truncated", "hitting the row limit must mark the output truncated")
	})

	t.Run("byte budget bounds the concatenation", func(t *testing.T) {
		origRows, origBytes := maxOutputChunkRows, maxLiveOutputBytes
		t.Cleanup(func() { maxOutputChunkRows, maxLiveOutputBytes = origRows, origBytes })
		maxOutputChunkRows, maxLiveOutputBytes = 1000, 10 // large row limit so only the byte budget bites

		out := liveOut(seed(20, "ABC")) // 60 bytes total, budget 10
		require.NotNil(t, out)
		assert.LessOrEqual(t, len(out.Stdout), 10, "concatenation must stop at the byte budget")
		assert.Contains(t, out.Stderr, "truncated")
	})

	t.Run("output within the caps is returned in full, no truncation marker", func(t *testing.T) {
		origRows, origBytes := maxOutputChunkRows, maxLiveOutputBytes
		t.Cleanup(func() { maxOutputChunkRows, maxLiveOutputBytes = origRows, origBytes })
		maxOutputChunkRows, maxLiveOutputBytes = 1000, 1<<20

		out := liveOut(seed(3, "hello"))
		require.NotNil(t, out)
		assert.Equal(t, "hellohellohello", out.Stdout)
		assert.NotContains(t, out.Stderr, "truncated", "output within the caps must not be marked truncated")
	})
}
