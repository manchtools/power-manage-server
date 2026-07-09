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
	"bytes"
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

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/connection"
)

// recordingInternal is a minimal stub of InternalServiceHandler that
// captures GetLuksKey + StoreLuksKey calls and returns canned
// responses or errors. Other RPCs are unimplemented.
type recordingInternal struct {
	pmv1connect.UnimplementedInternalServiceHandler

	mu               sync.Mutex
	lastGetLuksKey   *pm.InternalGetLuksKeyRequest
	lastStoreLuksKey *pm.InternalStoreLuksKeyRequest
	getLuksKeyResp   *pm.GetLuksKeyResponse
	getLuksKeyErr    error
	storeLuksKeyResp *pm.StoreLuksKeyResponse
	storeLuksKeyErr  error
}

func (r *recordingInternal) ProxyGetLuksKey(_ context.Context, req *connect.Request[pm.InternalGetLuksKeyRequest]) (*connect.Response[pm.GetLuksKeyResponse], error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastGetLuksKey = req.Msg
	if r.getLuksKeyErr != nil {
		return nil, r.getLuksKeyErr
	}
	resp := r.getLuksKeyResp
	if resp == nil {
		resp = &pm.GetLuksKeyResponse{}
	}
	return connect.NewResponse(resp), nil
}

func (r *recordingInternal) ProxyStoreLuksKey(_ context.Context, req *connect.Request[pm.InternalStoreLuksKeyRequest]) (*connect.Response[pm.StoreLuksKeyResponse], error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastStoreLuksKey = req.Msg
	if r.storeLuksKeyErr != nil {
		return nil, r.storeLuksKeyErr
	}
	resp := r.storeLuksKeyResp
	if resp == nil {
		resp = &pm.StoreLuksKeyResponse{}
	}
	return connect.NewResponse(resp), nil
}

// setupAgentForLuksTest stands up the httptest InternalService stub,
// wires a real ControlProxy + connection.Manager, and returns the
// handler + the stub so tests can assert recorded calls.
func setupAgentForLuksTest(t *testing.T) (*AgentHandler, *recordingInternal) {
	t.Helper()
	stub := &recordingInternal{}
	mux := http.NewServeMux()
	path, h := pmv1connect.NewInternalServiceHandler(stub)
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	proxy := NewControlProxy(srv.Client(), srv.URL, "test-gateway")
	mgr := connection.NewManager()
	return &AgentHandler{
		manager:      mgr,
		controlProxy: proxy,
		logger:       slog.Default(),
	}, stub
}

// =============================================================================
// handleGetLuksKey
// =============================================================================

func TestHandleGetLuksKey_CallsControlProxyWithRequestArgs(t *testing.T) {
	h, stub := setupAgentForLuksTest(t)
	stub.getLuksKeyResp = &pm.GetLuksKeyResponse{Passphrase: "decrypted-pass"}

	// No agent registered → Send returns ErrAgentNotConnected. We
	// only care that the controlProxy was called with the right
	// args; the Send error is the test's stop signal.
	err := h.handleGetLuksKey(context.Background(), "dev-1", "msg-1", &pm.GetLuksKeyRequest{ActionId: "act-2"})
	require.Error(t, err, "no agent registered → manager.Send must surface ErrAgentNotConnected")
	assert.ErrorIs(t, err, connection.ErrAgentNotConnected)

	require.NotNil(t, stub.lastGetLuksKey)
	assert.Equal(t, "dev-1", stub.lastGetLuksKey.DeviceId,
		"controlProxy.GetLuksKey MUST be called with the deviceID from the bidi-stream context, NOT from the request — wrong device_id leaks LUKS keys cross-tenant")
	assert.Equal(t, "act-2", stub.lastGetLuksKey.ActionId)
}

func TestHandleGetLuksKey_ProxyErrorReachesSendPath(t *testing.T) {
	// When controlProxy fails (e.g. NotFound), the handler builds an
	// Error message and routes it through manager.Send. The Send
	// itself fails (no agent), but the proxy was still called — which
	// is the contract we care about.
	h, stub := setupAgentForLuksTest(t)
	stub.getLuksKeyErr = connect.NewError(connect.CodeNotFound, errors.New("no LUKS key"))

	err := h.handleGetLuksKey(context.Background(), "dev-1", "msg-1", &pm.GetLuksKeyRequest{ActionId: "missing-act"})
	require.Error(t, err)
	assert.ErrorIs(t, err, connection.ErrAgentNotConnected,
		"on proxy error, handler still attempts manager.Send (with the Error variant) — verifies the error path is wired")
	require.NotNil(t, stub.lastGetLuksKey)
	assert.Equal(t, "missing-act", stub.lastGetLuksKey.ActionId)
}

// =============================================================================
// handleStoreLuksKey
// =============================================================================

func TestHandleStoreLuksKey_PropagatesAllRequestFieldsToProxy(t *testing.T) {
	// Critical: every field on the StoreLuksKey request MUST land on
	// the proxy call. A missing DevicePath or RotationReason would
	// silently store the wrong metadata and the operator-visible
	// LUKS rotation history would be unreliable.
	h, stub := setupAgentForLuksTest(t)
	stub.storeLuksKeyResp = &pm.StoreLuksKeyResponse{Success: true}

	sealed := bytes.Repeat([]byte{0xAB}, 61) // shaped like a minimal sealed blob
	err := h.handleStoreLuksKey(context.Background(), "dev-1", "msg-1", &pm.StoreLuksKeyRequest{
		ActionId:         "act-2",
		DevicePath:       "/dev/sda1",
		SealedPassphrase: sealed,
		RotationReason:   pm.RotationReason_ROTATION_REASON_SCHEDULED,
	})
	require.Error(t, err, "no agent registered → manager.Send returns ErrAgentNotConnected")
	assert.ErrorIs(t, err, connection.ErrAgentNotConnected)

	require.NotNil(t, stub.lastStoreLuksKey)
	assert.Equal(t, "dev-1", stub.lastStoreLuksKey.DeviceId)
	assert.Equal(t, "act-2", stub.lastStoreLuksKey.ActionId)
	assert.Equal(t, "/dev/sda1", stub.lastStoreLuksKey.DevicePath)
	assert.Equal(t, sealed, stub.lastStoreLuksKey.SealedPassphrase,
		"the sealed bytes must pass through the gateway untouched — it relays opaquely (spec 25)")
	assert.Equal(t, pm.RotationReason_ROTATION_REASON_SCHEDULED, stub.lastStoreLuksKey.RotationReason,
		"RotationReason MUST round-trip — the audit log keys on this for 'why was this LUKS key rotated'")
}

func TestHandleStoreLuksKey_ProxyErrorReachesSendPath(t *testing.T) {
	h, stub := setupAgentForLuksTest(t)
	stub.storeLuksKeyErr = connect.NewError(connect.CodeInternal, errors.New("encrypt failed"))

	err := h.handleStoreLuksKey(context.Background(), "dev-1", "msg-1", &pm.StoreLuksKeyRequest{
		ActionId: "act-2", DevicePath: "/dev/sda1", SealedPassphrase: bytes.Repeat([]byte{0xCD}, 61),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, connection.ErrAgentNotConnected)
	require.NotNil(t, stub.lastStoreLuksKey, "proxy was still called even though it returned error")
}

// TestHandleStoreLuksKey_DropsLegacyCleartext pins the spec 25 compatibility
// row: a pre-sealed-transport agent's cleartext passphrase (anything shorter
// than a minimal sealed blob) is dropped at the gateway with a loud error —
// NEVER proxied toward control.
func TestHandleStoreLuksKey_DropsLegacyCleartext(t *testing.T) {
	h, stub := setupAgentForLuksTest(t)

	err := h.handleStoreLuksKey(context.Background(), "dev-1", "msg-1", &pm.StoreLuksKeyRequest{
		ActionId:         "act-2",
		DevicePath:       "/dev/sda1",
		SealedPassphrase: []byte("legacy-cleartext-pw"),
		RotationReason:   pm.RotationReason_ROTATION_REASON_SCHEDULED,
	})
	require.Error(t, err, "the error-response send path is exercised (no agent connected)")
	assert.ErrorIs(t, err, connection.ErrAgentNotConnected)
	assert.Nil(t, stub.lastStoreLuksKey, "legacy cleartext must never reach the proxy")
}
