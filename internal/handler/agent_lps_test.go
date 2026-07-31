package handler

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/connection"
)

// The dispatch case for StoreLpsPasswords, tested directly.
//
// Review found this path had NO test at all, while a comment elsewhere claimed
// it did — deleting the dispatch case left `go test ./...` green. That is the
// worst version of a coverage gap: a reader who checks is told the property is
// guarded, so nobody looks again.
//
// The stakes are why it matters. LPS rotation is irreversible — the agent has
// already run chpasswd — and the agent blocks on this reply before clearing its
// pending state. A dropped batch destroys the only copy of the new password.

func setupForLps(t *testing.T) (*AgentHandler, *fakeAgentOps) {
	t.Helper()
	ops := &fakeAgentOps{}
	return &AgentHandler{
		manager: connection.NewManager(),
		ops:     ops,
		logger:  slog.Default(),
	}, ops
}

func lpsRequest() *pm.StoreLpsPasswordsRequest {
	return &pm.StoreLpsPasswordsRequest{
		ActionId: "01J0000000000000000000ACTX",
		Rotations: []*pm.LpsPasswordRotation{{
			Username: "alice",
			Password: "pw-alice",
			Reason:   pm.RotationReason_ROTATION_REASON_SCHEDULED,
		}},
	}
}

// The batch must reach control, carrying the device id from the STREAM rather
// than from any request field.
func TestHandleStoreLpsPasswords_ReachesOpsWithStreamDevice(t *testing.T) {
	h, ops := setupForLps(t)

	err := h.handleStoreLpsPasswords(context.Background(), "dev-1", "msg-1", lpsRequest())
	require.Error(t, err, "no agent registered → manager.Send returns ErrAgentNotConnected")
	assert.ErrorIs(t, err, connection.ErrAgentNotConnected)

	require.NotNil(t, ops.lastStoreLps, "the batch must reach control, or the rotation is lost silently")
	assert.Equal(t, "dev-1", ops.storeLpsDev, "device identity comes from the stream, never the request")
	require.Len(t, ops.lastStoreLps.Rotations, 1)
	assert.Equal(t, "alice", ops.lastStoreLps.Rotations[0].Username)
	assert.Equal(t, "pw-alice", ops.lastStoreLps.Rotations[0].Password)
}

// A failure must still answer the agent. Returning silently looks identical to
// a lost batch, and the agent is blocked waiting.
func TestHandleStoreLpsPasswords_FailureStillAnswersTheAgent(t *testing.T) {
	h, ops := setupForLps(t)
	ops.storeLpsErr = connect.NewError(connect.CodeInternal, errors.New("append failed"))

	err := h.handleStoreLpsPasswords(context.Background(), "dev-1", "msg-1", lpsRequest())
	require.Error(t, err, "the handler must attempt a reply on the error path too")
	assert.ErrorIs(t, err, connection.ErrAgentNotConnected,
		"the error is from the reply attempt, proving the failure path sends rather than returning quietly")
	require.NotNil(t, ops.lastStoreLps, "ops was still called even though it returned an error")
}

// The dispatch switch must route the message. Without a case it falls through
// to "unknown message type" and the batch vanishes.
func TestHandleAgentMessage_RoutesStoreLpsPasswords(t *testing.T) {
	h, ops := setupForLps(t)

	err := h.handleAgentMessage(context.Background(), "dev-1", &pm.AgentMessage{
		Id:      "msg-1",
		Payload: &pm.AgentMessage_StoreLpsPasswords{StoreLpsPasswords: lpsRequest()},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, connection.ErrAgentNotConnected,
		"reaching the send path proves the message was routed, not dropped as unknown")
	require.NotNil(t, ops.lastStoreLps,
		"StoreLpsPasswords was not dispatched — an agent's irreversible rotation would be discarded")
}
