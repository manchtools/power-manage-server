package handler_test

// Test coverage for ControlProxy and GatewayServiceHandler
// (manchtools/power-manage-server#160 / audit F044). The control
// proxy is the security-critical client used for credential-bearing
// proxy operations (LpsPasswords, LuksKey, ValidateTerminalToken);
// a misuse there leaks LUKS keys, so the call-shape and error
// propagation contracts deserve explicit tests.
//
// Strategy: stand up an httptest server with a fake InternalService
// implementation that records each call's parameters and returns
// canned responses or errors. Then invoke ControlProxy methods and
// assert the recorded params + return values match the contract.
//
// No real network, no real TLS — httptest only.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/handler"
)

// fakeInternalService is a recording stub of InternalServiceServer.
// Each method records the request it received and returns a canned
// response (or err if set). Tests inspect the recorded calls to
// assert the proxy passed the right parameters through.
type fakeInternalService struct {
	pmv1connect.UnimplementedInternalServiceHandler

	mu sync.Mutex

	// Recorded last-call params per method.
	lastVerifyDevice      *pm.VerifyDeviceRequest
	lastSyncActions       *pm.InternalSyncActionsRequest
	lastValidateLuksToken *pm.InternalValidateLuksTokenRequest
	lastGetLuksKey        *pm.InternalGetLuksKeyRequest
	lastStoreLuksKey      *pm.InternalStoreLuksKeyRequest
	lastStoreLpsPasswords *pm.InternalStoreLpsPasswordsRequest
	lastValidateTerminal  *pm.InternalValidateTerminalTokenRequest

	// Per-method canned responses + errors. err takes precedence.
	verifyDeviceErr           error
	syncActionsResp           *pm.SyncActionsResponse
	syncActionsErr            error
	validateLuksTokenResp     *pm.ValidateLuksTokenResponse
	validateLuksTokenErr      error
	getLuksKeyResp            *pm.GetLuksKeyResponse
	getLuksKeyErr             error
	storeLuksKeyResp          *pm.StoreLuksKeyResponse
	storeLuksKeyErr           error
	storeLpsPasswordsResp     *pm.InternalStoreLpsPasswordsResponse
	storeLpsPasswordsErr      error
	validateTerminalTokenResp *pm.InternalValidateTerminalTokenResponse
	validateTerminalTokenErr  error
}

func (f *fakeInternalService) VerifyDevice(_ context.Context, req *connect.Request[pm.VerifyDeviceRequest]) (*connect.Response[pm.VerifyDeviceResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastVerifyDevice = req.Msg
	if f.verifyDeviceErr != nil {
		return nil, f.verifyDeviceErr
	}
	return connect.NewResponse(&pm.VerifyDeviceResponse{}), nil
}

func (f *fakeInternalService) ProxySyncActions(_ context.Context, req *connect.Request[pm.InternalSyncActionsRequest]) (*connect.Response[pm.SyncActionsResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastSyncActions = req.Msg
	if f.syncActionsErr != nil {
		return nil, f.syncActionsErr
	}
	resp := f.syncActionsResp
	if resp == nil {
		resp = &pm.SyncActionsResponse{}
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeInternalService) ProxyValidateLuksToken(_ context.Context, req *connect.Request[pm.InternalValidateLuksTokenRequest]) (*connect.Response[pm.ValidateLuksTokenResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastValidateLuksToken = req.Msg
	if f.validateLuksTokenErr != nil {
		return nil, f.validateLuksTokenErr
	}
	resp := f.validateLuksTokenResp
	if resp == nil {
		resp = &pm.ValidateLuksTokenResponse{}
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeInternalService) ProxyGetLuksKey(_ context.Context, req *connect.Request[pm.InternalGetLuksKeyRequest]) (*connect.Response[pm.GetLuksKeyResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastGetLuksKey = req.Msg
	if f.getLuksKeyErr != nil {
		return nil, f.getLuksKeyErr
	}
	resp := f.getLuksKeyResp
	if resp == nil {
		resp = &pm.GetLuksKeyResponse{}
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeInternalService) ProxyStoreLuksKey(_ context.Context, req *connect.Request[pm.InternalStoreLuksKeyRequest]) (*connect.Response[pm.StoreLuksKeyResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastStoreLuksKey = req.Msg
	if f.storeLuksKeyErr != nil {
		return nil, f.storeLuksKeyErr
	}
	resp := f.storeLuksKeyResp
	if resp == nil {
		resp = &pm.StoreLuksKeyResponse{}
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeInternalService) ProxyStoreLpsPasswords(_ context.Context, req *connect.Request[pm.InternalStoreLpsPasswordsRequest]) (*connect.Response[pm.InternalStoreLpsPasswordsResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastStoreLpsPasswords = req.Msg
	if f.storeLpsPasswordsErr != nil {
		return nil, f.storeLpsPasswordsErr
	}
	resp := f.storeLpsPasswordsResp
	if resp == nil {
		resp = &pm.InternalStoreLpsPasswordsResponse{}
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeInternalService) ProxyValidateTerminalToken(_ context.Context, req *connect.Request[pm.InternalValidateTerminalTokenRequest]) (*connect.Response[pm.InternalValidateTerminalTokenResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastValidateTerminal = req.Msg
	if f.validateTerminalTokenErr != nil {
		return nil, f.validateTerminalTokenErr
	}
	resp := f.validateTerminalTokenResp
	if resp == nil {
		resp = &pm.InternalValidateTerminalTokenResponse{}
	}
	return connect.NewResponse(resp), nil
}

// setupProxy stands up the fake service and returns a ControlProxy
// pointing at it, plus the fake so the test can configure responses
// and inspect recorded calls.
func setupProxy(t *testing.T) (*handler.ControlProxy, *fakeInternalService) {
	t.Helper()
	fake := &fakeInternalService{}
	mux := http.NewServeMux()
	path, h := pmv1connect.NewInternalServiceHandler(fake)
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return handler.NewControlProxy(srv.Client(), srv.URL, "test-gateway"), fake
}

// =============================================================================
// VerifyDevice
// =============================================================================

func TestControlProxy_VerifyDevice_HappyPath(t *testing.T) {
	p, fake := setupProxy(t)
	require.NoError(t, p.VerifyDevice(context.Background(), "dev-123"))
	require.NotNil(t, fake.lastVerifyDevice)
	assert.Equal(t, "dev-123", fake.lastVerifyDevice.DeviceId)
}

func TestControlProxy_VerifyDevice_PropagatesError(t *testing.T) {
	p, fake := setupProxy(t)
	fake.verifyDeviceErr = connect.NewError(connect.CodeNotFound, errors.New("device not found"))

	err := p.VerifyDevice(context.Background(), "dev-missing")
	require.Error(t, err)

	connectErr := new(connect.Error)
	require.ErrorAs(t, err, &connectErr)
	assert.Equal(t, connect.CodeNotFound, connectErr.Code())
}

// =============================================================================
// SyncActions
// =============================================================================

func TestControlProxy_SyncActions_HappyPath(t *testing.T) {
	p, fake := setupProxy(t)
	fake.syncActionsResp = &pm.SyncActionsResponse{SyncIntervalMinutes: 15}

	resp, err := p.SyncActions(context.Background(), "dev-1")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, int32(15), resp.SyncIntervalMinutes)
	assert.Equal(t, "dev-1", fake.lastSyncActions.DeviceId)
}

func TestControlProxy_SyncActions_ErrorReturnsNilResponse(t *testing.T) {
	p, fake := setupProxy(t)
	fake.syncActionsErr = connect.NewError(connect.CodeInternal, errors.New("boom"))

	resp, err := p.SyncActions(context.Background(), "dev-1")
	require.Error(t, err, "transport error must propagate")
	assert.Nil(t, resp, "no response on error — caller must not see partial Msg")
}

// =============================================================================
// LUKS key + LPS password — credential paths
// =============================================================================

func TestControlProxy_GetLuksKey_HappyPath(t *testing.T) {
	p, fake := setupProxy(t)
	fake.getLuksKeyResp = &pm.GetLuksKeyResponse{Passphrase: "decrypted-pass"}

	resp, err := p.GetLuksKey(context.Background(), "dev-1", "act-2")
	require.NoError(t, err)
	assert.Equal(t, "decrypted-pass", resp.Passphrase)
	assert.Equal(t, "dev-1", fake.lastGetLuksKey.DeviceId)
	assert.Equal(t, "act-2", fake.lastGetLuksKey.ActionId)
}

func TestControlProxy_GetLuksKey_NotFoundPropagates(t *testing.T) {
	p, fake := setupProxy(t)
	fake.getLuksKeyErr = connect.NewError(connect.CodeNotFound, errors.New("no key for action"))

	resp, err := p.GetLuksKey(context.Background(), "dev-1", "missing-act")
	require.Error(t, err)
	assert.Nil(t, resp, "credential RPC must fail closed — no partial response")
	connectErr := new(connect.Error)
	require.ErrorAs(t, err, &connectErr)
	assert.Equal(t, connect.CodeNotFound, connectErr.Code())
}

func TestControlProxy_StoreLuksKey_HappyPath(t *testing.T) {
	p, fake := setupProxy(t)
	fake.storeLuksKeyResp = &pm.StoreLuksKeyResponse{Success: true}

	resp, err := p.StoreLuksKey(context.Background(), "dev-1", "act-2", "/dev/sda1", "passphrase", pm.RotationReason_ROTATION_REASON_INITIAL)
	require.NoError(t, err)
	assert.True(t, resp.Success)

	require.NotNil(t, fake.lastStoreLuksKey)
	assert.Equal(t, "dev-1", fake.lastStoreLuksKey.DeviceId)
	assert.Equal(t, "act-2", fake.lastStoreLuksKey.ActionId)
	assert.Equal(t, "/dev/sda1", fake.lastStoreLuksKey.DevicePath)
	assert.Equal(t, "passphrase", fake.lastStoreLuksKey.Passphrase)
	assert.Equal(t, pm.RotationReason_ROTATION_REASON_INITIAL, fake.lastStoreLuksKey.RotationReason)
}

func TestControlProxy_ValidateLuksToken_HappyPath(t *testing.T) {
	p, fake := setupProxy(t)
	fake.validateLuksTokenResp = &pm.ValidateLuksTokenResponse{ActionId: "act-1", DevicePath: "/dev/sda1"}

	resp, err := p.ValidateLuksToken(context.Background(), "dev-1", "tok")
	require.NoError(t, err)
	assert.Equal(t, "act-1", resp.ActionId)
	assert.Equal(t, "tok", fake.lastValidateLuksToken.Token)
}

func TestControlProxy_StoreLpsPasswords_HappyPath(t *testing.T) {
	p, fake := setupProxy(t)
	rots := []*pm.LpsPasswordRotation{{Username: "alice", Password: "raw-pass-the-control-server-encrypts"}}

	require.NoError(t, p.StoreLpsPasswords(context.Background(), "dev-1", "act-2", rots))
	require.NotNil(t, fake.lastStoreLpsPasswords)
	assert.Equal(t, "dev-1", fake.lastStoreLpsPasswords.DeviceId)
	assert.Equal(t, "act-2", fake.lastStoreLpsPasswords.ActionId)
	require.Len(t, fake.lastStoreLpsPasswords.Rotations, 1)
	assert.Equal(t, "alice", fake.lastStoreLpsPasswords.Rotations[0].Username)
}

func TestControlProxy_StoreLpsPasswords_ErrorPropagates(t *testing.T) {
	p, fake := setupProxy(t)
	fake.storeLpsPasswordsErr = connect.NewError(connect.CodeInternal, errors.New("store failed"))

	err := p.StoreLpsPasswords(context.Background(), "dev-1", "act-2", nil)
	require.Error(t, err, "LPS rotation is irreversible — failure to persist MUST surface to caller, not silently swallow")
}

// =============================================================================
// ValidateTerminalToken
// =============================================================================

func TestControlProxy_ValidateTerminalToken_HappyPath(t *testing.T) {
	p, fake := setupProxy(t)
	fake.validateTerminalTokenResp = &pm.InternalValidateTerminalTokenResponse{
		UserId: "user-1", DeviceId: "dev-1", TtyUser: "alice", Cols: 80, Rows: 24,
	}

	resp, err := p.ValidateTerminalToken(context.Background(), "sess-1", "tok-abc")
	require.NoError(t, err)
	assert.Equal(t, "user-1", resp.UserId)
	assert.Equal(t, "alice", resp.TtyUser)
	assert.Equal(t, "sess-1", fake.lastValidateTerminal.SessionId)
	assert.Equal(t, "tok-abc", fake.lastValidateTerminal.Token)
}

func TestControlProxy_ValidateTerminalToken_UnauthenticatedPropagates(t *testing.T) {
	p, fake := setupProxy(t)
	fake.validateTerminalTokenErr = connect.NewError(connect.CodeUnauthenticated, errors.New("token expired"))

	resp, err := p.ValidateTerminalToken(context.Background(), "sess-1", "stale")
	require.Error(t, err)
	assert.Nil(t, resp)
	connectErr := new(connect.Error)
	require.ErrorAs(t, err, &connectErr)
	assert.Equal(t, connect.CodeUnauthenticated, connectErr.Code())
}

// =============================================================================
// Connection failure (control endpoint unreachable) propagates
// =============================================================================

func TestControlProxy_TransportError_Propagates(t *testing.T) {
	// Point the proxy at a URL no server is listening on. The Connect
	// client should surface a transport-class error rather than a
	// silent zero-value response.
	p := handler.NewControlProxy(http.DefaultClient, "http://127.0.0.1:1", "test-gateway") // port 1 — never listening
	_, err := p.SyncActions(context.Background(), "dev-1")
	require.Error(t, err, "transport-level failure must propagate; a zero-value response would be silently bad")
}

// TestNewControlProxy_PanicsOnEmptyGatewayID pins the fail-fast: a gateway that
// stamps an empty gateway_id onto every device-origin request has control reject
// ALL of them, a total silent outage. The constructor must crash loudly instead.
func TestNewControlProxy_PanicsOnEmptyGatewayID(t *testing.T) {
	require.Panics(t, func() {
		handler.NewControlProxy(http.DefaultClient, "https://control.invalid", "")
	}, "an empty gatewayID must fail fast at construction")
}

// =============================================================================
// GatewayServiceHandler smoke tests — list / terminate via the
// in-memory TerminalSessionRegistry. The handler is otherwise a thin
// shell over the registry; one happy path per RPC plus the
// not-found shape covers it.
// =============================================================================

func TestGatewayService_ListGatewayTerminalSessions_Empty(t *testing.T) {
	registry := connection.NewTerminalSessionRegistry()
	h := handler.NewGatewayServiceHandler(registry, nil, slog.Default())

	resp, err := h.ListGatewayTerminalSessions(context.Background(),
		connect.NewRequest(&pm.ListGatewayTerminalSessionsRequest{}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.Sessions, "fresh registry must report zero sessions")
}

func TestGatewayService_ListGatewayTerminalSessions_PopulatedSnapshot(t *testing.T) {
	registry := connection.NewTerminalSessionRegistry()
	registry.Register(&connection.TerminalSession{
		SessionID: "sess-1", UserID: "user-A", DeviceID: "dev-1",
		TtyUser: "alice", Cols: 80, Rows: 24,
		StartedAt: time.Now(),
		OutputCh:  make(chan *pm.AgentMessage, 1),
	})
	registry.Register(&connection.TerminalSession{
		SessionID: "sess-2", UserID: "user-B", DeviceID: "dev-2",
		TtyUser: "bob", Cols: 120, Rows: 40,
		StartedAt: time.Now(),
		OutputCh:  make(chan *pm.AgentMessage, 1),
	})
	h := handler.NewGatewayServiceHandler(registry, nil, slog.Default())

	resp, err := h.ListGatewayTerminalSessions(context.Background(),
		connect.NewRequest(&pm.ListGatewayTerminalSessionsRequest{}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Sessions, 2)

	// Map by session id since List() makes no ordering guarantee.
	byID := map[string]*pm.GatewayTerminalSessionInfo{}
	for _, s := range resp.Msg.Sessions {
		byID[s.SessionId] = s
	}
	require.Contains(t, byID, "sess-1")
	require.Contains(t, byID, "sess-2")
	assert.Equal(t, "alice", byID["sess-1"].TtyUser)
	assert.Equal(t, "dev-2", byID["sess-2"].DeviceId)
}

func TestGatewayService_TerminateGatewayTerminalSession_NotOnThisGateway(t *testing.T) {
	// not-found shape: no session registered, found=false (NOT an error).
	// The control server fans out to every gateway and merges the result;
	// returning an error from the wrong gateway would short-circuit the
	// fan-out and leave the session running on whichever gateway DID own it.
	registry := connection.NewTerminalSessionRegistry()
	h := handler.NewGatewayServiceHandler(registry, nil, slog.Default())

	resp, err := h.TerminateGatewayTerminalSession(context.Background(),
		connect.NewRequest(&pm.TerminateGatewayTerminalSessionRequest{
			SessionId: "sess-not-here",
			Reason:    "test",
		}))
	require.NoError(t, err, "missing-on-this-gateway must NOT be an error — control fans out across gateways")
	assert.False(t, resp.Msg.Found, "found=false signals 'not on this gateway' to the fan-out caller")
}

func TestGatewayService_TerminateGatewayTerminalSession_HappyPath(t *testing.T) {
	registry := connection.NewTerminalSessionRegistry()
	registry.Register(&connection.TerminalSession{
		SessionID: "sess-doomed", UserID: "user-A", DeviceID: "dev-1",
		TtyUser:   "alice",
		StartedAt: time.Now(),
		OutputCh:  make(chan *pm.AgentMessage, 1),
	})
	h := handler.NewGatewayServiceHandler(registry, nil, slog.Default())

	resp, err := h.TerminateGatewayTerminalSession(context.Background(),
		connect.NewRequest(&pm.TerminateGatewayTerminalSessionRequest{
			SessionId: "sess-doomed",
			Reason:    "admin terminate",
		}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Found)

	// Post-condition: session is gone (Unregister closed the channel).
	assert.Nil(t, registry.Get("sess-doomed"), "session must be unregistered after terminate")
}
