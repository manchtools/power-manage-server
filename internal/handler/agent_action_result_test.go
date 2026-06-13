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
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// recordingInternalForLps captures ProxyStoreLpsPasswords calls so
// tests can assert the exact rotations forwarded to the control
// plane and flip the response between success / error.
type recordingInternalForLps struct {
	pmv1connect.UnimplementedInternalServiceHandler
	mu        sync.Mutex
	lastReq   *pm.InternalStoreLpsPasswordsRequest
	returnErr error
}

func (r *recordingInternalForLps) ProxyStoreLpsPasswords(_ context.Context, req *connect.Request[pm.InternalStoreLpsPasswordsRequest]) (*connect.Response[pm.InternalStoreLpsPasswordsResponse], error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastReq = req.Msg
	if r.returnErr != nil {
		return nil, r.returnErr
	}
	return connect.NewResponse(&pm.InternalStoreLpsPasswordsResponse{}), nil
}

func setupForActionResult(t *testing.T) (*AgentHandler, *fakeEnqueuer, *recordingInternalForLps) {
	t.Helper()
	stub := &recordingInternalForLps{}
	mux := http.NewServeMux()
	path, h := pmv1connect.NewInternalServiceHandler(stub)
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	fake := &fakeEnqueuer{}
	hh := &AgentHandler{
		aqClient:     fake,
		controlProxy: NewControlProxy(srv.Client(), srv.URL, "test-gateway"),
		logger:       slog.Default(),
	}
	return hh, fake, stub
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
	assert.NotEmpty(t, payload.ActionResultJSON, "marshalled result must be non-empty")
}

// =============================================================================
// proxyLpsRotations branches (exercised through handleActionResult)
// =============================================================================

func TestHandleActionResult_LpsKeyMissing_NoProxyCall(t *testing.T) {
	// Metadata exists but doesn't carry the lps.rotations key.
	// proxyLpsRotations must early-return without touching the proxy
	// — calling StoreLpsPasswords with no rotations would generate
	// a phantom audit event for "rotated zero passwords."
	h, _, stub := setupForActionResult(t)
	err := h.handleActionResult(context.Background(), "dev-1", &pm.ActionResult{
		ActionId: &pm.ActionId{Value: "act-2"},
		Metadata: map[string]string{"some.other.key": "value"},
	})
	require.NoError(t, err)
	assert.Nil(t, stub.lastReq, "controlProxy.StoreLpsPasswords MUST NOT be called when lps.rotations key is absent")
}

func TestHandleActionResult_LpsRotationsMalformed_StripsAndContinues(t *testing.T) {
	// Malformed JSON in lps.rotations: strip the metadata key
	// (no point in retrying a payload the agent will keep sending
	// in the same broken shape) and continue the enqueue. The
	// stripped metadata must not appear on the wire — Valkey-side
	// inspection of the payload would otherwise leak the broken
	// JSON to operators.
	h, fake, stub := setupForActionResult(t)
	err := h.handleActionResult(context.Background(), "dev-1", &pm.ActionResult{
		ActionId: &pm.ActionId{Value: "act-3"},
		Metadata: map[string]string{"lps.rotations": "{not valid json"},
	})
	require.NoError(t, err)
	assert.Nil(t, stub.lastReq, "malformed JSON must not reach the proxy")

	// The enqueue still happens — no LPS to forward, but the
	// execution result still needs to land on control.
	last := fake.lastCall(t)
	assert.Equal(t, taskqueue.TypeExecutionResult, last.taskType)
}

func TestHandleActionResult_LpsRotationsEmpty_StripsNoProxyCall(t *testing.T) {
	// Empty rotations array is well-formed but has nothing to do.
	// Strip the key (so the payload going to control is clean) and
	// skip the proxy call.
	h, _, stub := setupForActionResult(t)
	err := h.handleActionResult(context.Background(), "dev-1", &pm.ActionResult{
		ActionId: &pm.ActionId{Value: "act-4"},
		Metadata: map[string]string{"lps.rotations": "[]"},
	})
	require.NoError(t, err)
	assert.Nil(t, stub.lastReq, "empty rotations array must not reach the proxy")
}

func TestHandleActionResult_LpsRotationsHappyPath_ProxiesAndStrips(t *testing.T) {
	// Critical contract: the LPS password is encrypted in transit
	// via the controlProxy — it must NOT also leak to Valkey via
	// the EnqueueToControl payload. Verify both sides:
	//   1) the proxy call carries the rotation
	//   2) the metadata key is stripped from the result before enqueue
	h, fake, stub := setupForActionResult(t)
	result := &pm.ActionResult{
		ActionId: &pm.ActionId{Value: "act-5"},
		Metadata: map[string]string{
			"lps.rotations": `[{"username":"alice","password":"s3cret","rotated_at":"2026-05-11T10:00:00Z","reason":"scheduled"}]`,
			"keep.this":     "yes",
		},
	}
	err := h.handleActionResult(context.Background(), "dev-1", result)
	require.NoError(t, err)

	require.NotNil(t, stub.lastReq, "controlProxy.StoreLpsPasswords MUST be called when lps.rotations is non-empty")
	assert.Equal(t, "dev-1", stub.lastReq.DeviceId)
	assert.Equal(t, "act-5", stub.lastReq.ActionId)
	require.Len(t, stub.lastReq.Rotations, 1)
	assert.Equal(t, "alice", stub.lastReq.Rotations[0].Username)
	assert.Equal(t, "s3cret", stub.lastReq.Rotations[0].Password,
		"the proxy MUST receive the cleartext password — encryption happens server-side via the InternalService impl")

	// Metadata key MUST be gone after a successful proxy call so
	// the credential doesn't double-back through Valkey.
	_, ok := result.Metadata["lps.rotations"]
	assert.False(t, ok, "lps.rotations key MUST be stripped after proxy succeeds — must not leak via Valkey payload")
	_, ok = result.Metadata["keep.this"]
	assert.True(t, ok, "non-LPS metadata keys must be preserved")

	last := fake.lastCall(t)
	assert.Equal(t, taskqueue.TypeExecutionResult, last.taskType)
}

func TestHandleActionResult_LpsRotationsProxyError_PreservesMetadataAndReturnsError(t *testing.T) {
	// On a proxy failure (transient control outage), the handler
	// MUST surface the error and NOT strip the metadata. The agent
	// will resend the result on reconnect — stripping prematurely
	// would silently lose the rotation history.
	h, fake, stub := setupForActionResult(t)
	stub.returnErr = connect.NewError(connect.CodeUnavailable, errors.New("control unreachable"))

	result := &pm.ActionResult{
		ActionId: &pm.ActionId{Value: "act-6"},
		Metadata: map[string]string{
			"lps.rotations": `[{"username":"bob","password":"x"}]`,
		},
	}
	err := h.handleActionResult(context.Background(), "dev-1", result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store lps passwords")

	_, stillThere := result.Metadata["lps.rotations"]
	assert.True(t, stillThere,
		"on proxy error, lps.rotations MUST remain in metadata so the agent can resend the rotation on reconnect — stripping would silently lose history")

	// EnqueueToControl must NOT be reached when the proxy fails —
	// otherwise control would commit the execution result without
	// the rotations ever landing.
	assert.Empty(t, fake.recorded, "EnqueueToControl MUST NOT be called when LPS proxy fails — execution-result commit blocks until rotations are stored")
}
