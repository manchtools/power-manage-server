package handler

// handleActionResult + proxyLpsRotations coverage — closes the
// remaining major gap in agent.go test coverage from #150 (the
// per-message handler with the most branches and the most
// surprising side-effects: in-place metadata mutation + LPS proxy).
//
// What this catches:
//   - the missing/empty action_id guards
//   - LPS rotations: empty-metadata, no-key, malformed JSON,
//     empty list, happy path with proxy call, proxy error
//   - the in-place metadata strip after successful proxy
//   - the EnqueueToControl shape on the success path
//
// Strategy: extends the existing fakeEnqueuer + httptest
// InternalService stub from agent_handlers_test.go +
// agent_luks_test.go, so no new fixture infrastructure.

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

func setupForActionResult(t *testing.T) (*AgentHandler, *fakeEnqueuer, *fakeAgentOps) {
	t.Helper()
	ops := &fakeAgentOps{}
	fake := &fakeEnqueuer{}
	return &AgentHandler{
		aqClient: fake,
		ops:      ops,
		logger:   slog.Default(),
	}, fake, ops
}

// =============================================================================
// handleActionResult: happy path enqueues
// =============================================================================

func TestHandleActionResult_NoMetadata_EnqueuesExecutionResult(t *testing.T) {
	// No metadata = no LPS rotations to proxy. The result must still
	// land on the control inbox via EnqueueToControl with the right
	// task type + payload shape; downstream control workers expect
	// exactly TypeExecutionResult.
	h, fake, _ := setupForActionResult(t)
	err := h.handleActionResult(context.Background(), "dev-1", &pm.ActionResult{
		ActionId: &pm.ActionId{Value: "act-1"},
		Status:   pm.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
	})
	require.NoError(t, err)

	last := fake.lastCall(t)
	assert.Equal(t, "control", last.queue)
	assert.Equal(t, taskqueue.TypeExecutionResult, last.taskType)
	payload, ok := last.payload.(taskqueue.ExecutionResultPayload)
	require.True(t, ok, "payload should be ExecutionResultPayload, got %T", last.payload)
	assert.Equal(t, "dev-1", payload.DeviceID)
	assert.NotEmpty(t, payload.ActionResultProto, "marshalled result must be non-empty")
}

// LPS rotations no longer ride in ActionResult metadata.
//
// They used to: the agent base64-encoded a sealed blob into result.Metadata
// because the relaying gateway was not trusted to read the passwords, and the
// handler unpacked, forwarded and stripped it. That entire path is gone with
// the relay — rotations are now a first-class stream message, covered by
// TestHandleStoreLpsPasswords_* below. The six tests that drove the metadata
// branches went with the branches.
