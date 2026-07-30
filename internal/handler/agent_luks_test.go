package handler

// LUKS handler coverage for AgentHandler — completes the agent.go
// test gap from manchtools/power-manage-server#150 by covering
// handleGetLuksKey + handleStoreLuksKey, the two handlers the
// PARTIAL PR (#212) intentionally left at 0%.
//
// Strategy: stand up an httptest.Server with a recording stub of
// InternalService (same shape as #160's ControlProxy tests), wire
// it into a real ControlProxy, and inject that into AgentHandler.
// connection.Manager is real but with no agent registered — Send
// returns ErrAgentNotConnected so we can verify the handler reaches
// the Send call regardless of which message variant it built.
//
// What this catches: the controlProxy interaction (the credential-
// bearing path) is fully tested. What it doesn't: which message
// variant the handler tried to send (Error vs GetLuksKey/StoreLuksKey).
// That requires a captureable Stream which is connect.BidiStream —
// non-trivial to construct outside the bidi-stream handler itself.
// Documented as a follow-up.

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

// setupAgentForLuksTest wires the handler to a recording AgentOps double and a
// real connection manager. The httptest InternalService this used to stand up
// is gone with the RPC boundary — the call is in-process now.
func setupAgentForLuksTest(t *testing.T) (*AgentHandler, *fakeAgentOps) {
	t.Helper()
	ops := &fakeAgentOps{}
	return &AgentHandler{
		manager: connection.NewManager(),
		ops:     ops,
		logger:  slog.Default(),
	}, ops
}

// =============================================================================
// handleGetLuksKey
// =============================================================================

func TestHandleGetLuksKey_PassesStreamDeviceAndRequest(t *testing.T) {
	h, stub := setupAgentForLuksTest(t)
	stub.getResp = &pm.GetLuksKeyResponse{Passphrase: "decrypted-pass"}

	// No agent registered → Send returns ErrAgentNotConnected. We
	// only care that the controlProxy was called with the right
	// args; the Send error is the test's stop signal.
	err := h.handleGetLuksKey(context.Background(), "dev-1", "msg-1", &pm.GetLuksKeyRequest{ActionId: "act-2"})
	require.Error(t, err, "no agent registered → manager.Send must surface ErrAgentNotConnected")
	assert.ErrorIs(t, err, connection.ErrAgentNotConnected)

	require.NotNil(t, stub.lastGet)
	assert.Equal(t, "dev-1", stub.getDev,
		"controlProxy.GetLuksKey MUST be called with the deviceID from the bidi-stream context, NOT from the request — wrong device_id leaks LUKS keys cross-tenant")
	assert.Equal(t, "act-2", stub.lastGet.ActionId)
}

func TestHandleGetLuksKey_OpsErrorReachesSendPath(t *testing.T) {
	// When controlProxy fails (e.g. NotFound), the handler builds an
	// Error message and routes it through manager.Send. The Send
	// itself fails (no agent), but the proxy was still called — which
	// is the contract we care about.
	h, stub := setupAgentForLuksTest(t)
	stub.getErr = connect.NewError(connect.CodeNotFound, errors.New("no LUKS key"))

	err := h.handleGetLuksKey(context.Background(), "dev-1", "msg-1", &pm.GetLuksKeyRequest{ActionId: "missing-act"})
	require.Error(t, err)
	assert.ErrorIs(t, err, connection.ErrAgentNotConnected,
		"on an ops error the handler still attempts manager.Send with the Error variant — the error path stays wired")
	require.NotNil(t, stub.lastGet)
	assert.Equal(t, "missing-act", stub.lastGet.ActionId)
}

// =============================================================================
// handleStoreLuksKey
// =============================================================================

func TestHandleStoreLuksKey_PassesStreamDeviceAndRequest(t *testing.T) {
	// Critical: every field on the StoreLuksKey request MUST land on
	// the proxy call. A missing DevicePath or RotationReason would
	// silently store the wrong metadata and the operator-visible
	// LUKS rotation history would be unreliable.
	h, stub := setupAgentForLuksTest(t)
	stub.storeLuksResp = &pm.StoreLuksKeyResponse{Success: true}

	const passphrase = "a-real-luks-passphrase"
	err := h.handleStoreLuksKey(context.Background(), "dev-1", "msg-1", &pm.StoreLuksKeyRequest{
		ActionId:       "act-2",
		DevicePath:     "/dev/sda1",
		Passphrase:     passphrase,
		RotationReason: pm.RotationReason_ROTATION_REASON_SCHEDULED,
	})
	require.Error(t, err, "no agent registered → manager.Send returns ErrAgentNotConnected")
	assert.ErrorIs(t, err, connection.ErrAgentNotConnected)

	require.NotNil(t, stub.lastStoreLuks)
	assert.Equal(t, "dev-1", stub.storeLuksDev)
	assert.Equal(t, "act-2", stub.lastStoreLuks.ActionId)
	assert.Equal(t, "/dev/sda1", stub.lastStoreLuks.DevicePath)
	assert.Equal(t, passphrase, stub.lastStoreLuks.Passphrase,
		"the passphrase must reach control unmodified; the stream mTLS is what protects it now")
	assert.Equal(t, pm.RotationReason_ROTATION_REASON_SCHEDULED, stub.lastStoreLuks.RotationReason,
		"RotationReason MUST round-trip — the audit log keys on this for 'why was this LUKS key rotated'")
}

func TestHandleStoreLuksKey_OpsErrorReachesSendPath(t *testing.T) {
	h, stub := setupAgentForLuksTest(t)
	stub.storeLuksErr = connect.NewError(connect.CodeInternal, errors.New("encrypt failed"))

	err := h.handleStoreLuksKey(context.Background(), "dev-1", "msg-1", &pm.StoreLuksKeyRequest{
		ActionId: "act-2", DevicePath: "/dev/sda1", Passphrase: "pw",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, connection.ErrAgentNotConnected)
	require.NotNil(t, stub.lastStoreLuks, "ops was still called even though it returned an error")
}
