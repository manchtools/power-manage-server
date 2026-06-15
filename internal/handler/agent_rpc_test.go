package handler

// Coverage for the two top-level non-bidi RPCs on AgentHandler
// (ValidateLuksToken, SyncActions) plus the small but uncovered
// rotationReasonFromAgentString helper. Closes the remaining big
// coverage gaps in agent.go from #150.
//
// Strategy: extends the existing httptest InternalService stub
// pattern. The proxy paths are exercised against a recording fake
// of the InternalService handler, so the test verifies both the
// happy and error mappings end-to-end.

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
)

type recordingInternalForRPC struct {
	pmv1connect.UnimplementedInternalServiceHandler
	mu                       sync.Mutex
	lastValidateLuksDeviceID string
	lastValidateLuksToken    string
	validateLuksResp         *pm.ValidateLuksTokenResponse
	validateLuksErr          error
	lastSyncActionsDeviceID  string
	syncActionsResp          *pm.SyncActionsResponse
	syncActionsErr           error
}

func (r *recordingInternalForRPC) ProxyValidateLuksToken(_ context.Context, req *connect.Request[pm.InternalValidateLuksTokenRequest]) (*connect.Response[pm.ValidateLuksTokenResponse], error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastValidateLuksDeviceID = req.Msg.DeviceId
	r.lastValidateLuksToken = req.Msg.Token
	if r.validateLuksErr != nil {
		return nil, r.validateLuksErr
	}
	resp := r.validateLuksResp
	if resp == nil {
		resp = &pm.ValidateLuksTokenResponse{}
	}
	return connect.NewResponse(resp), nil
}

func (r *recordingInternalForRPC) ProxySyncActions(_ context.Context, req *connect.Request[pm.InternalSyncActionsRequest]) (*connect.Response[pm.SyncActionsResponse], error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastSyncActionsDeviceID = req.Msg.DeviceId
	if r.syncActionsErr != nil {
		return nil, r.syncActionsErr
	}
	resp := r.syncActionsResp
	if resp == nil {
		resp = &pm.SyncActionsResponse{}
	}
	return connect.NewResponse(resp), nil
}

func setupAgentForRPCTest(t *testing.T) (*AgentHandler, *recordingInternalForRPC) {
	t.Helper()
	stub := &recordingInternalForRPC{}
	mux := http.NewServeMux()
	path, h := pmv1connect.NewInternalServiceHandler(stub)
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	hh := &AgentHandler{
		controlProxy: NewControlProxy(srv.Client(), srv.URL, "test-gateway"),
		logger:       slog.Default(),
	}
	return hh, stub
}

// =============================================================================
// ValidateLuksToken
// =============================================================================

func TestValidateLuksToken_EmptyDeviceID_Rejected(t *testing.T) {
	h, _ := setupAgentForRPCTest(t)
	_, err := h.ValidateLuksToken(context.Background(), connect.NewRequest(&pm.ValidateLuksTokenRequest{DeviceId: "", Token: "tok"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestValidateLuksToken_EmptyToken_Rejected(t *testing.T) {
	h, _ := setupAgentForRPCTest(t)
	_, err := h.ValidateLuksToken(context.Background(), connect.NewRequest(&pm.ValidateLuksTokenRequest{DeviceId: "dev-1", Token: ""}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestValidateLuksToken_HappyPath_PropagatesToProxy(t *testing.T) {
	h, stub := setupAgentForRPCTest(t)
	stub.validateLuksResp = &pm.ValidateLuksTokenResponse{
		ActionId:   "act-1",
		DevicePath: "/dev/sda1",
		MinLength:  16,
	}

	resp, err := h.ValidateLuksToken(context.Background(), connect.NewRequest(&pm.ValidateLuksTokenRequest{
		DeviceId: "dev-1",
		Token:    "the-token",
	}))
	require.NoError(t, err)
	assert.Equal(t, "act-1", resp.Msg.ActionId)
	assert.Equal(t, "/dev/sda1", resp.Msg.DevicePath)
	assert.Equal(t, "dev-1", stub.lastValidateLuksDeviceID)
	assert.Equal(t, "the-token", stub.lastValidateLuksToken,
		"token MUST round-trip verbatim — control's TTL store keys on this exact byte sequence")
}

func TestValidateLuksToken_ProxyError_MappedToNotFound(t *testing.T) {
	// Whatever the proxy returns (Internal, Unavailable, etc.), the
	// handler MUST surface CodeNotFound — leaking the underlying
	// failure mode to the agent would let an attacker probe for
	// "control unreachable" vs "wrong token" timing differences.
	h, stub := setupAgentForRPCTest(t)
	stub.validateLuksErr = connect.NewError(connect.CodeUnavailable, errors.New("control unreachable"))

	_, err := h.ValidateLuksToken(context.Background(), connect.NewRequest(&pm.ValidateLuksTokenRequest{
		DeviceId: "dev-1",
		Token:    "tok",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err),
		"proxy error MUST be re-mapped to CodeNotFound — leaking the upstream code would enable timing-side-channel probes against the control plane")
}

func TestValidateLuksToken_TLS_DeviceIDMismatch_PermissionDenied(t *testing.T) {
	// requireTLS=true: the cert's device-ID context MUST match the request's
	// device_id, exactly as SyncActions enforces. A mismatch lets a compromised
	// agent redeem a one-time LUKS token issued for a DIFFERENT device — the
	// token unlocks that other device's encrypted volume. The guard must run
	// BEFORE the proxy is touched.
	h, stub := setupAgentForRPCTest(t)
	h.requireTLS = true
	ctx := contextWithDeviceID(context.Background(), "cert-dev-1")
	_, err := h.ValidateLuksToken(ctx, connect.NewRequest(&pm.ValidateLuksTokenRequest{
		DeviceId: "different-dev-2",
		Token:    "the-token",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err),
		"cert/request device-ID mismatch MUST be CodePermissionDenied — anything else lets a device redeem another's LUKS token")
	assert.Empty(t, stub.lastValidateLuksToken,
		"the control proxy MUST NOT be called on a cert mismatch — the guard runs before the work")
}

func TestValidateLuksToken_TLS_NoDeviceIDInContext_Unauthenticated(t *testing.T) {
	h, stub := setupAgentForRPCTest(t)
	h.requireTLS = true
	_, err := h.ValidateLuksToken(context.Background(), connect.NewRequest(&pm.ValidateLuksTokenRequest{
		DeviceId: "dev-1",
		Token:    "tok",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	assert.Empty(t, stub.lastValidateLuksToken, "no proxy call without an authenticated cert identity")
}

func TestValidateLuksToken_TLS_MatchingDeviceID_PropagatesToProxy(t *testing.T) {
	h, stub := setupAgentForRPCTest(t)
	h.requireTLS = true
	stub.validateLuksResp = &pm.ValidateLuksTokenResponse{ActionId: "act-1"}
	ctx := contextWithDeviceID(context.Background(), "dev-1")
	resp, err := h.ValidateLuksToken(ctx, connect.NewRequest(&pm.ValidateLuksTokenRequest{
		DeviceId: "dev-1",
		Token:    "the-token",
	}))
	require.NoError(t, err)
	assert.Equal(t, "act-1", resp.Msg.ActionId)
	assert.Equal(t, "the-token", stub.lastValidateLuksToken, "a matching cert identity proceeds to the proxy")
}

// =============================================================================
// SyncActions
// =============================================================================

func TestSyncActions_HappyPath_NonTLS_PropagatesToProxy(t *testing.T) {
	h, stub := setupAgentForRPCTest(t)
	stub.syncActionsResp = &pm.SyncActionsResponse{
		StandaloneActions:   []*pm.Action{{Id: &pm.ActionId{Value: "act-1"}}},
		SyncIntervalMinutes: 15,
	}

	resp, err := h.SyncActions(context.Background(), connect.NewRequest(&pm.SyncActionsRequest{
		DeviceId: &pm.DeviceId{Value: "dev-1"},
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(15), resp.Msg.SyncIntervalMinutes)
	assert.Equal(t, "dev-1", stub.lastSyncActionsDeviceID)
}

func TestSyncActions_TLS_DeviceIDMismatch_PermissionDenied(t *testing.T) {
	// requireTLS=true: the cert's device-ID context MUST match the
	// request's device_id. A mismatch lets one device sync another's
	// actions — would expose the entire fleet's action assignments to
	// any compromised agent.
	h, _ := setupAgentForRPCTest(t)
	h.requireTLS = true
	ctx := contextWithDeviceID(context.Background(), "cert-dev-1")
	_, err := h.SyncActions(ctx, connect.NewRequest(&pm.SyncActionsRequest{
		DeviceId: &pm.DeviceId{Value: "different-dev-2"},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err),
		"cert/request device-ID mismatch MUST be CodePermissionDenied — anything else lets one device exfiltrate another's action assignments")
}

func TestSyncActions_TLS_NoDeviceIDInContext_Unauthenticated(t *testing.T) {
	// requireTLS=true but no cert in context. Should never happen
	// in production (mTLS gateway terminates first), but the handler
	// must fail-closed if it ever does.
	h, _ := setupAgentForRPCTest(t)
	h.requireTLS = true
	_, err := h.SyncActions(context.Background(), connect.NewRequest(&pm.SyncActionsRequest{
		DeviceId: &pm.DeviceId{Value: "dev-1"},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestSyncActions_EmptyDeviceID_Rejected(t *testing.T) {
	h, _ := setupAgentForRPCTest(t)
	_, err := h.SyncActions(context.Background(), connect.NewRequest(&pm.SyncActionsRequest{
		DeviceId: &pm.DeviceId{Value: ""},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestSyncActions_ProxyError_MappedToInternal(t *testing.T) {
	h, stub := setupAgentForRPCTest(t)
	stub.syncActionsErr = connect.NewError(connect.CodeUnavailable, errors.New("control down"))

	_, err := h.SyncActions(context.Background(), connect.NewRequest(&pm.SyncActionsRequest{
		DeviceId: &pm.DeviceId{Value: "dev-1"},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
}

// =============================================================================
// rotationReasonFromAgentString
// =============================================================================

func TestRotationReasonFromAgentString_KnownValues(t *testing.T) {
	cases := map[string]pm.RotationReason{
		"initial":    pm.RotationReason_ROTATION_REASON_INITIAL,
		"scheduled":  pm.RotationReason_ROTATION_REASON_SCHEDULED,
		"auth_grace": pm.RotationReason_ROTATION_REASON_AUTH_GRACE,
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			assert.Equal(t, want, rotationReasonFromAgentString(in))
		})
	}
}

func TestRotationReasonFromAgentString_UnknownCollapsesToUnspecified(t *testing.T) {
	// An unknown value (including empty string from older agents)
	// MUST map to UNSPECIFIED. Downstream the projector defaults
	// UNSPECIFIED to "scheduled" — matching the historical
	// PL/pgSQL COALESCE behaviour. Returning a different known
	// value here would silently rewrite history.
	assert.Equal(t, pm.RotationReason_ROTATION_REASON_UNSPECIFIED,
		rotationReasonFromAgentString(""))
	assert.Equal(t, pm.RotationReason_ROTATION_REASON_UNSPECIFIED,
		rotationReasonFromAgentString("totally-unknown-value"))
}

// contextWithDeviceID injects a device ID into the test ctx so
// DeviceIDFromContext returns it. Mirrors the production mTLS
// middleware (MTLSMiddleware) which puts the cert-derived device
// ID on the ctx before the RPC handler runs.
func contextWithDeviceID(ctx context.Context, deviceID string) context.Context {
	return context.WithValue(ctx, DeviceIDContextKey, deviceID)
}
