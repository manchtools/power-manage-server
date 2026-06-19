package handler

// End-to-end coverage for AgentHandler.Stream — closes the
// "Stream() needs a client-stream fixture" follow-up from
// manchtools/power-manage-server#150. Together with the
// per-handler tests in agent_handlers_test.go + agent_luks_test.go +
// agent_dispatch_test.go, every gate that lives BEFORE the per-message
// dispatcher (Hello validation, mTLS device-ID match, controlProxy
// VerifyDevice gate) now has direct coverage from a real bidi stream.
//
// Strategy: stand up a real Connect-RPC handler over h2c (HTTP/2 over
// cleartext) on httptest.Server, and exercise it through a real
// AgentServiceClient bidi stream. The fixture uses recording fakes for
// the task queue and per-device worker manager so the post-register
// happy path is covered without depending on Valkey.

import (
	"context"
	"errors"
	"io"
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
)

// recordingControlForStream is the AgentService end's view of the
// upstream Internal API — only VerifyDevice matters for these tests
// (StoreLuksKey etc. are exercised by agent_luks_test.go). Returning
// an error here forces Stream to bail at the device-verification gate.
type recordingControlForStream struct {
	pmv1connect.UnimplementedInternalServiceHandler
	mu               sync.Mutex
	verifyDeviceErr  error
	lastVerifyDevice string
}

func (r *recordingControlForStream) VerifyDevice(_ context.Context, req *connect.Request[pm.VerifyDeviceRequest]) (*connect.Response[pm.VerifyDeviceResponse], error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastVerifyDevice = req.Msg.DeviceId
	if r.verifyDeviceErr != nil {
		return nil, r.verifyDeviceErr
	}
	return connect.NewResponse(&pm.VerifyDeviceResponse{}), nil
}

type fakeStreamWorkerManager struct {
	mu      sync.Mutex
	started []string
	stopped []string
}

func (f *fakeStreamWorkerManager) StartWorker(deviceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = append(f.started, deviceID)
	return nil
}

func (f *fakeStreamWorkerManager) StopWorker(deviceID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = append(f.stopped, deviceID)
}

func (f *fakeStreamWorkerManager) snapshot() (started, stopped []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.started...), append([]string(nil), f.stopped...)
}

// streamFixture wires AgentHandler into an h2c httptest.Server and
// returns an AgentServiceClient pointed at it, plus the recording
// control stub so tests can flip the VerifyDevice outcome.
type streamFixture struct {
	client      pmv1connect.AgentServiceClient
	internalSrv *httptest.Server
	control     *recordingControlForStream
	worker      *fakeStreamWorkerManager
	server      *httptest.Server
}

func newStreamFixture(t *testing.T, requireTLS bool) *streamFixture {
	return newStreamFixtureWithCert(t, requireTLS, "")
}

// newStreamFixtureWithCert is newStreamFixture plus an mTLS-cert-derived device
// id stamped into the server-side request context (mimicking MTLSMiddleware), so
// the cert/Hello device-id mismatch gate can be driven. certDeviceID == ""
// injects nothing — the requireTLS path then sees no cert identity.
func newStreamFixtureWithCert(t *testing.T, requireTLS bool, certDeviceID string) *streamFixture {
	t.Helper()

	// 1) httptest InternalService stub for ControlProxy.VerifyDevice.
	control := &recordingControlForStream{}
	internalMux := http.NewServeMux()
	internalPath, internalH := pmv1connect.NewInternalServiceHandler(control)
	internalMux.Handle(internalPath, internalH)
	internalSrv := httptest.NewServer(internalMux)
	t.Cleanup(internalSrv.Close)

	// 2) Real ControlProxy + connection.Manager + recording fakes for
	// the queue and per-device worker manager.
	proxy := NewControlProxy(internalSrv.Client(), internalSrv.URL, "test-gateway")
	mgr := connection.NewManager()
	worker := &fakeStreamWorkerManager{}
	h := &AgentHandler{
		manager:           mgr,
		aqClient:          &fakeEnqueuer{},
		controlProxy:      proxy,
		workerMgr:         worker,
		logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		serverVersion:     "test",
		heartbeatInterval: 30 * time.Second,
		requireTLS:        requireTLS,
	}

	// 3) AgentService over h2c httptest server. Both server and
	// client opt into UnencryptedHTTP2 via http.Protocols (Go 1.24+
	// first-party h2c support). Mixing the new server-side opt-in
	// with the deprecated x/net http2.Transport on the client side
	// produced trailer-less terminations that the client wrapped as
	// CodeUnknown "EOF" on clean shutdown — using the same primitive
	// on both ends lets the client see plain io.EOF when the
	// handler's Stream() returns nil.
	mux := http.NewServeMux()
	path, hh := pmv1connect.NewAgentServiceHandler(h)
	mux.Handle(path, hh)
	var agentHandler http.Handler = mux
	if certDeviceID != "" {
		agentHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), DeviceIDContextKey, certDeviceID)
			mux.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	srv := httptest.NewUnstartedServer(agentHandler)
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	srv.Config.Protocols = protocols
	srv.Start()
	t.Cleanup(srv.Close)

	httpClient := &http.Client{
		Transport: &http.Transport{
			Protocols: protocols,
		},
	}
	// No protocol option → defaults to Connect, matching the
	// production agent's NewAgentServiceClient call.
	client := pmv1connect.NewAgentServiceClient(httpClient, srv.URL)

	return &streamFixture{
		client:      client,
		internalSrv: internalSrv,
		control:     control,
		worker:      worker,
		server:      srv,
	}
}

// recvErr drives the bidi stream's Receive loop until it returns the
// terminal error from the server's Stream() return — the BidiStream
// API surfaces server-side errors only on the next Receive after the
// handler has returned. Clean shutdown is io.EOF; anything else
// (including Connect-wrapped errors with the handler's actual reason)
// is propagated to the caller.
func recvErr(stream interface {
	Receive() (*pm.ServerMessage, error)
}) error {
	for {
		_, err := stream.Receive()
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
}

// =============================================================================
// Stream() early-bail validation gates
// =============================================================================

func TestStream_FirstMessageMustBeHello(t *testing.T) {
	// Sending Heartbeat as the first message MUST be rejected with
	// CodeInvalidArgument. The contract is that every connection's
	// first frame is Hello so the gateway can identify the device
	// before any state changes happen — accepting a non-Hello first
	// frame would let an agent skip identity verification.
	f := newStreamFixture(t, false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream := f.client.Stream(ctx)
	require.NoError(t, stream.Send(&pm.AgentMessage{
		Payload: &pm.AgentMessage_Heartbeat{Heartbeat: &pm.Heartbeat{}},
	}))
	require.NoError(t, stream.CloseRequest())

	err := recvErr(stream)
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err),
		"non-Hello first message MUST surface CodeInvalidArgument — accepting it would skip identity verification")
}

func TestStream_HelloWithEmptyDeviceIDIsRejected(t *testing.T) {
	// Hello must carry a non-empty device_id. An empty string would
	// later be used as the registry key + the Asynq queue name; both
	// would silently merge connections from misconfigured agents into
	// one shared session.
	f := newStreamFixture(t, false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream := f.client.Stream(ctx)
	require.NoError(t, stream.Send(&pm.AgentMessage{
		Payload: &pm.AgentMessage_Hello{Hello: &pm.Hello{
			Hostname:     "test-host",
			AgentVersion: "test",
			// DeviceId omitted → empty
		}},
	}))
	require.NoError(t, stream.CloseRequest())

	err := recvErr(stream)
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err),
		"Hello with empty device_id MUST be rejected — the empty key would collide across agents")
}

func TestStream_NoCertDeviceIDWhenTLSRequiredIsUnauthenticated(t *testing.T) {
	// requireTLS=true but no mTLS-derived device id in context (the gateway
	// terminating mTLS should always set it; if it ever doesn't, the handler
	// must fail closed rather than stream unauthenticated).
	f := newStreamFixture(t, true)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream := f.client.Stream(ctx)
	require.NoError(t, stream.Send(&pm.AgentMessage{
		Payload: &pm.AgentMessage_Hello{Hello: &pm.Hello{
			DeviceId: &pm.DeviceId{Value: "01HZX9ABCD0000000000000000"},
			Hostname: "h", AgentVersion: "v",
		}},
	}))
	require.NoError(t, stream.CloseRequest())

	err := recvErr(stream)
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	assert.Empty(t, f.control.lastVerifyDevice, "VerifyDevice must not run without a cert identity")
	started, _ := f.worker.snapshot()
	assert.Empty(t, started, "no worker started")
}

func TestStream_CertHelloDeviceIDMismatchRejected(t *testing.T) {
	// The cert identifies deviceA; the Hello claims deviceB. A compromised agent
	// presenting another device's certificate must not register or stream as
	// that other device — the gate must reject before VerifyDevice/StartWorker.
	const certID = "01HZX9ABCD000000000000000A"
	const helloID = "01HZX9ABCD000000000000000B"
	f := newStreamFixtureWithCert(t, true, certID)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream := f.client.Stream(ctx)
	require.NoError(t, stream.Send(&pm.AgentMessage{
		Payload: &pm.AgentMessage_Hello{Hello: &pm.Hello{
			DeviceId: &pm.DeviceId{Value: helloID},
			Hostname: "h", AgentVersion: "v",
		}},
	}))
	require.NoError(t, stream.CloseRequest())

	err := recvErr(stream)
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err),
		"cert/Hello device-ID mismatch MUST be CodePermissionDenied")
	assert.Empty(t, f.control.lastVerifyDevice, "VerifyDevice must not run on a cert/Hello mismatch")
	started, _ := f.worker.snapshot()
	assert.Empty(t, started, "no worker started on a mismatch")
}

func TestStream_VerifyDeviceFailureRejectsConnection(t *testing.T) {
	// controlProxy.VerifyDevice is the device-existence gate. If the
	// control server has soft-deleted the device but its agent is
	// still running, this gate refuses the connection so dead devices
	// can't keep streaming heartbeats. Coverage of the
	// CodePermissionDenied branch is critical for compliance review.
	f := newStreamFixture(t, false)
	f.control.verifyDeviceErr = connect.NewError(connect.CodeNotFound, errors.New("device deleted"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream := f.client.Stream(ctx)
	require.NoError(t, stream.Send(&pm.AgentMessage{
		Payload: &pm.AgentMessage_Hello{Hello: &pm.Hello{
			DeviceId:     &pm.DeviceId{Value: "01HZX9ABCD0000000000000000"},
			Hostname:     "test-host",
			AgentVersion: "test",
		}},
	}))
	require.NoError(t, stream.CloseRequest())

	err := recvErr(stream)
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err),
		"deleted/unknown device MUST surface CodePermissionDenied — agents whose record was removed must not retain a stream")
	assert.Equal(t, "01HZX9ABCD0000000000000000", f.control.lastVerifyDevice,
		"VerifyDevice must be called with the Hello-supplied device_id")
}

func TestStream_HappyPathRegistersStartsWorkerAndSendsWelcome(t *testing.T) {
	f := newStreamFixture(t, false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream := f.client.Stream(ctx)
	require.NoError(t, stream.Send(&pm.AgentMessage{
		Payload: &pm.AgentMessage_Hello{Hello: &pm.Hello{
			DeviceId:     &pm.DeviceId{Value: "01HZX9DEFGH000000000000000"},
			Hostname:     "happy-host",
			AgentVersion: "happy",
		}},
	}))

	msg, err := stream.Receive()
	require.NoError(t, err)
	require.NotNil(t, msg.GetWelcome(), "successful stream setup must send Welcome to the agent")
	assert.Equal(t, "test", msg.GetWelcome().ServerVersion)
	assert.Equal(t, "01HZX9DEFGH000000000000000", f.control.lastVerifyDevice)

	started, stopped := f.worker.snapshot()
	assert.Equal(t, []string{"01HZX9DEFGH000000000000000"}, started)
	assert.Empty(t, stopped)

	require.NoError(t, stream.CloseRequest())
	// Drain the response side so the handler's Stream() goroutine observes the
	// request-side EOF and unwinds before we snapshot worker state below.
	// WS16 server#331: the handler now classifies the clean shutdown (which
	// connect-go v1.18.1 surfaces to the server as *connect.Error{CodeUnknown,
	// "EOF"}) as graceful and returns nil, so the client sees a clean io.EOF
	// terminal status rather than an inherited error.
	// recvErr maps a clean io.EOF terminal status to nil, so a graceful close
	// surfaces as no error here; the pre-fix handler returned the raw
	// CodeUnknown/"EOF" error, which recvErr would surface as non-nil.
	termErr := recvErr(stream)
	assert.NoError(t, termErr,
		"a clean agent shutdown must terminate the stream gracefully (handler returns nil), not re-emit an error (#331)")

	_, stopped = f.worker.snapshot()
	assert.Equal(t, []string{"01HZX9DEFGH000000000000000"}, stopped)
}
