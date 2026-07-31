// Package handler implements the Connect-RPC service handlers.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/mtls"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// contextKey is a custom type for context keys.
type contextKey string

const (
	// DeviceIDContextKey is the context key for the device ID extracted from mTLS.
	DeviceIDContextKey contextKey = "device_id"
)

// AgentOps is the control-side logic the stream handler invokes on behalf of a
// connected agent. It is an interface here rather than a concrete type so this
// package does not depend on internal/api, and so tests can drive the handler
// without a database.
//
// Every method takes deviceID as its own argument, sourced from the stream's
// mTLS identity. Passing it separately rather than reading it from the request
// is what prevents one device naming another; api.AgentOps guards that shape
// with a reflection test.
type AgentOps interface {
	VerifyDevice(ctx context.Context, deviceID string) error
	SyncActions(ctx context.Context, deviceID string) (*pm.SyncActionsResponse, error)
	ValidateLuksToken(ctx context.Context, deviceID string, req *pm.ValidateLuksTokenRequest) (*pm.ValidateLuksTokenResponse, error)
	GetLuksKey(ctx context.Context, deviceID string, req *pm.GetLuksKeyRequest) (*pm.GetLuksKeyResponse, error)
	StoreLuksKey(ctx context.Context, deviceID string, req *pm.StoreLuksKeyRequest) (*pm.StoreLuksKeyResponse, error)
	StoreLpsPasswords(ctx context.Context, deviceID string, req *pm.StoreLpsPasswordsRequest) (*pm.StoreLpsPasswordsResponse, error)
}

type deviceWorkerManager interface {
	StartWorker(deviceID string) error
	StopWorker(deviceID string)
}

// AgentHandler implements the AgentService.
type AgentHandler struct {
	pmv1connect.UnimplementedAgentServiceHandler

	manager *connection.Manager
	// aqClient is the taskqueue.Enqueuer interface so tests can swap in
	// a recording fake without standing up Asynq + Valkey. Production
	// wiring still passes the concrete *taskqueue.Client which
	// implements the interface.
	aqClient          taskqueue.Enqueuer
	ops               AgentOps
	workerMgr         deviceWorkerManager
	logger            *slog.Logger
	serverVersion     string
	heartbeatInterval time.Duration
	requireTLS        bool

	// terminalSessions is the gateway-side registry of active
	// WebSocket terminal bridge sessions. Set via
	// SetTerminalSessions at startup. When the bidi stream handler
	// receives TerminalOutput/TerminalStateChange from an agent,
	// it routes the message to the matching bridge goroutine via
	// this registry. nil means no terminal bridge is configured.
	terminalSessions *connection.TerminalSessionRegistry
}

// NewAgentHandler creates a new agent handler.
func NewAgentHandler(
	manager *connection.Manager,
	aqClient taskqueue.Enqueuer,
	ops AgentOps,
	workerMgr deviceWorkerManager,
	serverVersion string,
	heartbeatInterval time.Duration,
	logger *slog.Logger,
) *AgentHandler {
	// A nil *DeviceWorkerManager arrives here as a NON-nil interface value
	// holding a nil pointer, so every later `h.workerMgr == nil` check would be
	// false and the first Hello would dereference it. Normalise it once, here,
	// so the guard downstream is real rather than decorative.
	if workerMgr != nil {
		if v := reflect.ValueOf(workerMgr); v.Kind() == reflect.Ptr && v.IsNil() {
			workerMgr = nil
		}
	}
	return &AgentHandler{
		manager:           manager,
		aqClient:          aqClient,
		ops:               ops,
		workerMgr:         workerMgr,
		serverVersion:     serverVersion,
		heartbeatInterval: heartbeatInterval,
		logger:            logger,
		requireTLS:        false,
	}
}

// NewAgentHandlerWithTLS creates a new agent handler that requires mTLS.
func NewAgentHandlerWithTLS(
	manager *connection.Manager,
	aqClient taskqueue.Enqueuer,
	ops AgentOps,
	workerMgr deviceWorkerManager,
	serverVersion string,
	heartbeatInterval time.Duration,
	logger *slog.Logger,
) *AgentHandler {
	// A nil *DeviceWorkerManager arrives here as a NON-nil interface value
	// holding a nil pointer, so every later `h.workerMgr == nil` check would be
	// false and the first Hello would dereference it. Normalise it once, here,
	// so the guard downstream is real rather than decorative.
	if workerMgr != nil {
		if v := reflect.ValueOf(workerMgr); v.Kind() == reflect.Ptr && v.IsNil() {
			workerMgr = nil
		}
	}
	return &AgentHandler{
		manager:           manager,
		aqClient:          aqClient,
		ops:               ops,
		workerMgr:         workerMgr,
		serverVersion:     serverVersion,
		heartbeatInterval: heartbeatInterval,
		logger:            logger,
		requireTLS:        true,
	}
}

// SetTerminalSessions wires the terminal session registry so the
// bidi stream handler can route TerminalOutput/TerminalStateChange
// messages from agents to the matching WebSocket bridge goroutine.
func (h *AgentHandler) SetTerminalSessions(reg *connection.TerminalSessionRegistry) {
	h.terminalSessions = reg
}

// MTLSMiddleware extracts the device ID from the client certificate
// and adds it to the context. It also refuses any peer whose cert
// does not carry the "agent" peer-class URI SAN — the AgentService
// listener is for managed devices only, and a leaked gateway or
// control cert must not be usable here.
// MTLSMiddleware gates the gateway's AgentService listener. The revocation
// checker is mtls.RevocationChecker (the gateway's *crl.Cache satisfies it); a
// nil or not-yet-loaded checker fails CLOSED — see mtls.RevocationChecker and
// the fail-closed block below. There is no permissive opt-out: without a loaded
// CRL every call is rejected (the gateway refuses to boot without one).
func MTLSMiddleware(next http.Handler, revocation mtls.RevocationChecker, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip TLS check for health endpoints
		if r.URL.Path == "/health" || r.URL.Path == "/ready" {
			next.ServeHTTP(w, r)
			return
		}

		// Carry the transport's write-deadline control down to the stream
		// handler. connect gives the handler no access to the ResponseWriter,
		// and without a deadline a write to a device that stopped reading
		// blocks with nothing able to interrupt it.
		r = r.WithContext(withWriteDeadliner(r.Context(), http.NewResponseController(w)))

		// Extract device ID from client certificate
		deviceID, err := mtls.DeviceIDFromRequest(r)
		if err != nil {
			logger.Warn("mTLS authentication failed",
				"error", err,
				"remote_addr", r.RemoteAddr,
			)
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}

		// Enforce peer class. Agent certs issued by the internal CA
		// carry a spiffe://power-manage/agent URI SAN; gateway /
		// control certs carry a different class and must be
		// rejected before reaching AgentService.
		//
		// No r.TLS nil-guard: DeviceIDFromRequest above already
		// rejects requests with no TLS state (returns "no TLS
		// connection"), so r.TLS is guaranteed non-nil here. A
		// defensive `if r.TLS != nil` would let a future reorder
		// of this middleware silently bypass the peer-class check;
		// better to rely on the invariant and fail loudly than
		// fail-open.
		class, err := mtls.PeerClassFromTLS(r.TLS)
		if err != nil {
			logger.Warn("mTLS peer-class missing",
				"error", err,
				"device_id", deviceID,
				"remote_addr", r.RemoteAddr,
			)
			http.Error(w, "peer class required", http.StatusForbidden)
			return
		}
		if class != mtls.PeerClassAgent {
			logger.Warn("mTLS peer-class mismatch on AgentService",
				"device_id", deviceID,
				"remote_addr", r.RemoteAddr,
				"presented", class,
			)
			http.Error(w, "peer class not allowed", http.StatusForbidden)
			return
		}

		// Revocation gate (fail CLOSED). The chain already verified against the CA
		// above; this is what makes a leaked or superseded cert stop working
		// before its (1-year) natural expiry. r.TLS.PeerCertificates[0] is the
		// same leaf the peer-class check used, so it's non-nil here.
		//
		// A nil checker, or a lookup that ERRORS, means we CANNOT prove this cert
		// is unrevoked → reject, never admit. There is no opt-out from this gate.
		if revocation == nil {
			logger.Warn("mTLS rejected: no revocation checker configured (fail-closed)",
				"device_id", deviceID, "remote_addr", r.RemoteAddr)
			http.Error(w, "client certificate revocation unavailable", http.StatusForbidden)
			return
		}
		fp := ca.FingerprintFromCert(r.TLS.PeerCertificates[0])
		revoked, rerr := revocation.IsRevoked(r.Context(), fp)
		if rerr != nil {
			logger.Error("mTLS rejected: revocation lookup failed (fail-closed)",
				"device_id", deviceID, "remote_addr", r.RemoteAddr, "error", rerr)
			http.Error(w, "client certificate revocation unavailable", http.StatusForbidden)
			return
		}
		if revoked {
			logger.Warn("mTLS rejected: certificate revoked",
				"device_id", deviceID,
				"remote_addr", r.RemoteAddr,
			)
			http.Error(w, "client certificate revoked", http.StatusForbidden)
			return
		}

		// Add device ID to context
		ctx := context.WithValue(r.Context(), DeviceIDContextKey, deviceID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// DeviceIDFromContext extracts the device ID from the context.
func DeviceIDFromContext(ctx context.Context) (string, bool) {
	deviceID, ok := ctx.Value(DeviceIDContextKey).(string)
	return deviceID, ok
}

// BootstrapRedirectMiddleware returns HTTP 307 redirects when an
// agent connects to the wildcard root hostname (bootstrapHost), so
// the agent reconnects directly to this gateway's per-instance
// hostname (assignedHost) for all subsequent connections. The path
// and query are preserved verbatim, and only requests to
// bootstrapHost are intercepted — requests already addressed to
// assignedHost (or any other host) pass through unchanged.
//
// In multi-gateway HA, the load balancer routes wildcard-root
// connections to any gateway. The first gateway that receives the
// agent issues this redirect to its own hostname; the agent
// follows it (Connect-RPC's HTTP/2 client follows 307s
// transparently) and from then on every connection lands on the
// same gateway, so the connection manager has a stable
// device→gateway mapping the control server can route terminal
// sessions through.
//
// Both bootstrapHost and assignedHost are bare hostnames (no
// scheme, no port). Empty bootstrapHost disables the middleware
// entirely — single-gateway deployments don't need it. Empty
// assignedHost is a programming error and panics at construction
// time so we never silently emit redirects to an empty Location.
func BootstrapRedirectMiddleware(next http.Handler, bootstrapHost, assignedHost string, logger *slog.Logger) http.Handler {
	if bootstrapHost == "" {
		// Bootstrap not configured — pass through unchanged.
		return next
	}
	if assignedHost == "" {
		panic("handler: BootstrapRedirectMiddleware: assignedHost must not be empty when bootstrapHost is set")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// r.Host is the value of the Host header (or HTTP/2
		// :authority pseudo-header). Strip any port so we compare
		// just the hostname — the agent may include the port,
		// the bootstrap config typically doesn't.
		//
		// net.SplitHostPort handles bracketed IPv6 authorities
		// ([2001:db8::1]:443) correctly; falling back to the raw
		// r.Host when there is no port keeps unbracketed IPv4 /
		// hostname inputs working unchanged. Audit / CR catch:
		// strings.IndexByte(':') broke IPv6 by truncating at the
		// first internal colon and producing reqHost == "[".
		reqHost := r.Host
		if h, _, err := net.SplitHostPort(reqHost); err == nil {
			reqHost = h
		}
		if reqHost != bootstrapHost {
			next.ServeHTTP(w, r)
			return
		}
		target := "https://" + assignedHost + r.URL.RequestURI()
		logger.Debug("bootstrap redirect",
			"from", reqHost,
			"to", assignedHost,
			"path", r.URL.Path,
		)
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
	})
}

// Stream handles the bidirectional stream between agent and server.
func (h *AgentHandler) Stream(ctx context.Context, stream *connect.BidiStream[pm.AgentMessage, pm.ServerMessage]) (err error) {
	// Recover from panics to prevent server crashes. The wire-side
	// error message is intentionally bland — the panic value is
	// recorded in the operator log via h.logger.Error so it doesn't
	// leak across the agent connection (audit N018).
	defer func() {
		if r := recover(); r != nil {
			h.logger.Error("panic in stream handler", "panic", r)
			err = connect.NewError(connect.CodeInternal, errors.New("internal error"))
		}
	}()

	// Get device ID from mTLS context (if TLS is enabled)
	var certDeviceID string
	if h.requireTLS {
		var ok bool
		certDeviceID, ok = DeviceIDFromContext(ctx)
		if !ok {
			return connect.NewError(connect.CodeUnauthenticated, errors.New("mTLS authentication required"))
		}
	}

	// Wait for Hello message
	msg, err := stream.Receive()
	if err != nil {
		return fmt.Errorf("receive hello: %w", err)
	}

	hello := msg.GetHello()
	if hello == nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("first message must be Hello"))
	}

	deviceID := hello.DeviceId.GetValue()
	if deviceID == "" {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("device ID required"))
	}

	// If mTLS is enabled, verify that the device ID in the Hello matches the certificate
	if h.requireTLS && certDeviceID != deviceID {
		h.logger.Warn("device ID mismatch",
			"cert_device_id", certDeviceID,
			"hello_device_id", deviceID,
		)
		return connect.NewError(connect.CodePermissionDenied, errors.New("device ID does not match certificate"))
	}

	// Verify the device exists and is not deleted on the control server.
	if err := h.ops.VerifyDevice(ctx, deviceID); err != nil {
		h.logger.Warn("device verification failed, rejecting connection",
			"device_id", deviceID,
			"error", err,
		)
		return connect.NewError(connect.CodePermissionDenied, errors.New("device not found or deleted"))
	}

	h.logger.Info("agent connected",
		"device_id", deviceID,
		"hostname", hello.Hostname,
		"version", hello.AgentVersion,
		"mtls", h.requireTLS,
	)

	// Register the agent connection
	agent := h.manager.Register(ctx, deviceID, hello.Hostname, hello.AgentVersion, stream)

	// Bound writes to this device on the transport itself. Without this a send
	// to a device that has stopped reading blocks forever, wedging every later
	// send to it — including the frame that terminates a live root shell.
	if wd := writeDeadlinerFrom(ctx); wd != nil {
		agent.SetWriteDeadlineFunc(wd.SetWriteDeadline)
	} else {
		h.logger.Warn("no transport write-deadline control on this stream; writes to this device are unbounded",
			"device_id", deviceID)
	}

	// Start per-device Asynq worker to process action dispatches
	// Defence in depth against the wiring that main.go now refuses: a handler
	// built without a worker manager must reject the stream rather than panic
	// on the device's first frame, which would kill the process with the
	// connection already registered.
	if h.workerMgr == nil {
		h.logger.Error("agent stream refused: no device worker manager (no task queue configured)",
			"device_id", deviceID)
		return connect.NewError(connect.CodeUnavailable, errors.New("server cannot dispatch to devices"))
	}
	if err := h.workerMgr.StartWorker(deviceID); err != nil {
		h.logger.Warn("failed to start device worker", "device_id", deviceID, "error", err)
	}

	defer func() {
		// Remove OUR registration, and only ours. Both the identity check and
		// the delete happen under the manager's lock, so a device reconnecting
		// while this handler unwinds either wins the map before this runs — in
		// which case nothing is removed — or after it, in which case the
		// newcomer is untouched.
		//
		// The previous shape was Get-then-Unregister, twice, with the lock
		// released in between: a reconnect landing in either gap had its fresh
		// registration deleted and its worker stopped by the departing handler.
		// The device believed it was connected while the server had no route to
		// it, until whatever made it reconnect happened again.
		if !h.manager.UnregisterIfCurrent(deviceID, agent) {
			// Superseded — the replacement owns the worker now.
			h.logger.Info("agent disconnected (superseded by a newer connection)", "device_id", deviceID)
			return
		}
		// Ours was the live registration and is now gone, so the shared
		// per-device worker belongs to nobody. Stopping it AFTER the removal is
		// what keeps this safe: a reconnect racing us re-registers and starts
		// its own worker, and StartWorker on an already-running worker is the
		// idempotent case, whereas stopping first could halt the newcomer's.
		if h.workerMgr != nil {
			h.workerMgr.StopWorker(deviceID)
		}
		h.logger.Info("agent disconnected", "device_id", deviceID)
	}()

	// Notify control server about agent connection so it can dispatch pending actions
	if err := h.aqClient.EnqueueToControl(taskqueue.TypeDeviceHello, taskqueue.DeviceHelloPayload{
		DeviceID:     deviceID,
		Hostname:     hello.Hostname,
		AgentVersion: hello.AgentVersion,
	}); err != nil {
		h.logger.Warn("failed to enqueue device hello", "error", err)
	}

	// Send Welcome message to agent with server version. Populate
	// HeartbeatInterval only when configured — the agent SDK falls back
	// to its built-in default if the field is zero / unset, so older
	// agents that ignore the field keep working unchanged.
	welcome := &pm.Welcome{
		ServerVersion: h.serverVersion,
	}
	if h.heartbeatInterval > 0 {
		welcome.HeartbeatInterval = durationpb.New(h.heartbeatInterval)
	}

	if err := h.manager.Send(deviceID, &pm.ServerMessage{
		Payload: &pm.ServerMessage_Welcome{Welcome: welcome},
	}); err != nil {
		h.logger.Warn("failed to send Welcome", "device_id", deviceID, "error", err)
	}

	// Process incoming messages from the agent.
	//
	// Receive is drained on its own goroutine so the loop can also watch the
	// AGENT's context, which the manager cancels on Unregister — the path
	// certificate revocation takes. Blocking directly in Receive would ignore
	// that cancellation entirely: the call only returns when the client sends
	// or the RPC context dies, so a revoked agent that simply stays quiet would
	// keep its authenticated stream open indefinitely, and a chatty one would
	// keep having its frames dispatched. Returning here ends the RPC, which is
	// what actually closes the connection.
	//
	// The channel is buffered so a Receive that lands after the loop has
	// returned does not park the goroutine forever; the stream is torn down as
	// this handler returns, so the pending Receive then fails and it exits.
	type recvResult struct {
		msg *pm.AgentMessage
		err error
	}
	recvCh := make(chan recvResult, 1)
	go func() {
		for {
			msg, err := stream.Receive()
			select {
			case recvCh <- recvResult{msg: msg, err: err}:
			case <-agent.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-agent.Done():
			// Revoked, superseded by a newer connection for this device, or the
			// RPC itself ending. Either way this stream is no longer entitled to
			// deliver anything.
			h.logger.Info("agent stream terminated", "device_id", deviceID)
			return nil

		case r := <-recvCh:
			if r.err != nil {
				// WS16 server#331: classify a clean agent shutdown as graceful
				// instead of re-emitting it up the stack as an error (which logged
				// every normal disconnect at error severity).
				if isStreamClosed(r.err) {
					h.logger.Info("agent stream closed", "device_id", deviceID)
					return nil
				}
				return r.err
			}

			// Re-check before dispatching: a revocation may have landed while
			// this frame was in flight, and a frame accepted after revocation
			// would reach AgentOps and the inbox under an identity control has
			// already withdrawn.
			if agent.Terminated() {
				h.logger.Info("dropping frame from a terminated agent stream", "device_id", deviceID)
				return nil
			}

			h.manager.UpdateLastSeen(deviceID)

			if err := h.handleAgentMessage(ctx, deviceID, r.msg); err != nil {
				h.logger.Warn("handle agent message",
					"device_id", deviceID,
					"error", err,
				)
			}
		}
	}
}

// isStreamClosed reports whether a bidi-stream Receive error represents a
// clean end-of-stream / cancellation rather than a real transport fault.
// connect-go v1.18.1 wraps a clean agent shutdown over h2c as
// *connect.Error{CodeUnknown, "EOF"} instead of plain io.EOF (server#331), so
// that shape is classified too — otherwise every graceful disconnect would be
// re-emitted up the stack as an error.
func isStreamClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return true
	}
	var ce *connect.Error
	if errors.As(err, &ce) {
		if ce.Code() == connect.CodeCanceled {
			return true
		}
		if ce.Code() == connect.CodeUnknown && strings.Contains(ce.Message(), "EOF") {
			return true
		}
	}
	return false
}

// handleAgentMessage processes messages from the agent.
// All state changes are forwarded to the control server via Asynq or Connect-RPC proxy.
func (h *AgentHandler) handleAgentMessage(ctx context.Context, deviceID string, msg *pm.AgentMessage) error {
	switch p := msg.Payload.(type) {
	case *pm.AgentMessage_Heartbeat:
		return h.handleHeartbeat(ctx, deviceID, p.Heartbeat)
	case *pm.AgentMessage_ActionResult:
		return h.handleActionResult(ctx, deviceID, p.ActionResult)
	case *pm.AgentMessage_OutputChunk:
		return h.handleOutputChunk(ctx, deviceID, p.OutputChunk)
	case *pm.AgentMessage_QueryResult:
		return h.handleQueryResult(deviceID, p.QueryResult)
	case *pm.AgentMessage_Inventory:
		return h.handleInventory(deviceID, p.Inventory)
	case *pm.AgentMessage_SecurityAlert:
		return h.handleSecurityAlert(ctx, deviceID, p.SecurityAlert)
	case *pm.AgentMessage_GetLuksKey:
		return h.handleGetLuksKey(ctx, deviceID, msg.Id, p.GetLuksKey)
	case *pm.AgentMessage_StoreLuksKey:
		return h.handleStoreLuksKey(ctx, deviceID, msg.Id, p.StoreLuksKey)
	case *pm.AgentMessage_StoreLpsPasswords:
		return h.handleStoreLpsPasswords(ctx, deviceID, msg.Id, p.StoreLpsPasswords)
	case *pm.AgentMessage_RevokeLuksDeviceKeyResult:
		return h.handleRevokeLuksResult(deviceID, p.RevokeLuksDeviceKeyResult)
	case *pm.AgentMessage_LogQueryResult:
		return h.handleLogQueryResult(deviceID, p.LogQueryResult)
	case *pm.AgentMessage_TerminalOutput:
		if h.terminalSessions != nil {
			sid := p.TerminalOutput.SessionId
			sess := h.terminalSessions.Get(sid)
			if sess == nil {
				h.logger.Debug("terminal output for unknown session",
					"device_id", deviceID, "session_id", sid)
			} else if sess.DeviceID != deviceID {
				// A compromised agent is trying to inject output into
				// a session belonging to a different device. Drop it.
				h.logger.Warn("terminal output device mismatch — dropping",
					"device_id", deviceID, "session_device", sess.DeviceID, "session_id", sid)
			} else {
				h.terminalSessions.RouteAgentMessage(sid, msg)
			}
		}
		return nil
	case *pm.AgentMessage_TerminalStateChange:
		if h.terminalSessions != nil {
			sid := p.TerminalStateChange.SessionId
			sess := h.terminalSessions.Get(sid)
			if sess == nil {
				h.logger.Debug("terminal state change for unknown session",
					"device_id", deviceID, "session_id", sid,
					"state", p.TerminalStateChange.State.String())
			} else if sess.DeviceID != deviceID {
				h.logger.Warn("terminal state change device mismatch — dropping",
					"device_id", deviceID, "session_device", sess.DeviceID, "session_id", sid)
			} else {
				h.terminalSessions.RouteAgentMessage(sid, msg)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown message type: %T", msg.Payload)
	}
}

func (h *AgentHandler) handleHeartbeat(ctx context.Context, deviceID string, hb *pm.Heartbeat) error {
	// hb.Uptime / CpuPercent / MemoryPercent / DiskPercent are
	// intentionally NOT propagated downstream (audit N008): the inbox
	// worker terminus only writes the payload's AgentVersion into
	// devices_projection; the four metrics fields had no consumer and
	// were dead writes into the event store. Live metrics will need a
	// dedicated DeviceMetricsPayload + projection if we ever want them.
	_ = hb
	payload := taskqueue.DeviceHeartbeatPayload{DeviceID: deviceID}
	// Refresh the device→gateway TTL on every heartbeat. Best-effort:
	// a Valkey failure here is logged but does not refuse the
	// heartbeat — the existing UpdateLastSeen path is the source of
	// truth for connection liveness. Inherits the bidi-stream ctx so
	// the refresh aborts when the agent stream tears down (audit N006).
	return h.aqClient.EnqueueToControl(taskqueue.TypeDeviceHeartbeat, payload)
}

func (h *AgentHandler) handleActionResult(ctx context.Context, deviceID string, result *pm.ActionResult) error {
	if result.ActionId == nil {
		return fmt.Errorf("action result missing action ID")
	}
	resultID := result.ActionId.GetValue()
	if resultID == "" {
		return fmt.Errorf("action result has empty action ID")
	}

	h.logger.Info("received action result",
		"device_id", deviceID,
		"result_id", resultID,
		"status", result.Status.String(),
		"duration_ms", result.DurationMs,
	)

	// Binary protobuf, not protojson: no proto message is serialized as JSON over
	// the gateway→control queue (the result rides as binary inside the task).
	resultProto, err := proto.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal action result: %w", err)
	}
	return h.aqClient.EnqueueToControl(taskqueue.TypeExecutionResult, taskqueue.ExecutionResultPayload{
		DeviceID:          deviceID,
		ActionResultProto: resultProto,
	})
}

// maxOutputChunkBytes is the per-chunk ceiling enforced by the
// gateway before enqueueing the chunk to the control inbox. Agents
// are expected to fragment large output internally; a chunk larger
// than this is either a buggy or compromised agent (audit F-13). The
// 64 KiB cap matches a single sane terminal/log line and keeps the
// projection's `executions.output` JSONB column from being filled
// with megabytes of data via a flood from one stream.
const maxOutputChunkBytes = 64 * 1024

func (h *AgentHandler) handleOutputChunk(ctx context.Context, deviceID string, chunk *pm.OutputChunk) error {
	if chunk.ExecutionId == "" {
		return fmt.Errorf("output chunk missing execution ID")
	}
	streamType := "stdout"
	if chunk.Stream == pm.OutputStreamType_OUTPUT_STREAM_TYPE_STDERR {
		streamType = "stderr"
	}
	// Drop oversized chunks rather than enqueue them. A noisy agent
	// will repeatedly hit the cap and surface via the WARN log; the
	// alternative (silently truncating) would corrupt the displayed
	// output for legitimate cases the agent later fixes by chunking
	// correctly.
	if len(chunk.Data) > maxOutputChunkBytes {
		h.logger.Warn("output chunk exceeds size cap; dropping",
			"device_id", deviceID,
			"execution_id", chunk.ExecutionId,
			"stream", streamType,
			"sequence", chunk.Sequence,
			"size", len(chunk.Data),
			"limit", maxOutputChunkBytes,
		)
		return nil
	}
	h.logger.Debug("received output chunk",
		"device_id", deviceID,
		"execution_id", chunk.ExecutionId,
		"stream", streamType,
		"sequence", chunk.Sequence,
		"size", len(chunk.Data),
	)
	return h.aqClient.EnqueueToControl(taskqueue.TypeExecutionOutputChunk, taskqueue.ExecutionOutputChunkPayload{
		DeviceID:    deviceID,
		ExecutionID: chunk.ExecutionId,
		Stream:      streamType,
		Data:        string(chunk.Data),
		Sequence:    int64(chunk.Sequence),
	})
}

func (h *AgentHandler) handleQueryResult(deviceID string, result *pm.OSQueryResult) error {
	h.logger.Info("received query result",
		"device_id", deviceID,
		"query_id", result.QueryId,
		"success", result.Success,
	)
	var rowsJSON []map[string]string
	for _, row := range result.Rows {
		rowsJSON = append(rowsJSON, row.Data)
	}
	rowsBytes, err := json.Marshal(rowsJSON)
	if err != nil {
		rowsBytes = []byte("[]")
	}
	return h.aqClient.EnqueueToControl(taskqueue.TypeOSQueryResult, taskqueue.OSQueryResultPayload{
		DeviceID: deviceID,
		QueryID:  result.QueryId,
		Success:  result.Success,
		Error:    result.Error,
		RowsJSON: rowsBytes,
	})
}

func (h *AgentHandler) handleInventory(deviceID string, inventory *pm.DeviceInventory) error {
	h.logger.Info("received device inventory",
		"device_id", deviceID,
		"tables", len(inventory.Tables),
	)
	tables := make([]taskqueue.InventoryTable, 0, len(inventory.Tables))
	for _, table := range inventory.Tables {
		var rowsJSON []map[string]string
		for _, row := range table.Rows {
			rowsJSON = append(rowsJSON, row.Data)
		}
		rowsBytes, err := json.Marshal(rowsJSON)
		if err != nil {
			continue
		}
		tables = append(tables, taskqueue.InventoryTable{
			TableName: table.TableName,
			RowsJSON:  rowsBytes,
		})
	}
	return h.aqClient.EnqueueToControl(taskqueue.TypeInventoryUpdate, taskqueue.InventoryUpdatePayload{
		DeviceID: deviceID,
		Tables:   tables,
	})
}

func (h *AgentHandler) handleSecurityAlert(ctx context.Context, deviceID string, alert *pm.SecurityAlert) error {
	h.logger.Warn("received security alert from device",
		"device_id", deviceID,
		"alert_type", alert.Type.String(),
		"message", alert.Message,
		"details", alert.Details,
	)
	return h.aqClient.EnqueueToControl(taskqueue.TypeSecurityAlert, taskqueue.SecurityAlertPayload{
		DeviceID:  deviceID,
		AlertType: alert.Type.String(),
		Message:   alert.Message,
		Details:   alert.Details,
	})
}

func (h *AgentHandler) handleGetLuksKey(ctx context.Context, deviceID, msgID string, req *pm.GetLuksKeyRequest) error {
	resp, err := h.ops.GetLuksKey(ctx, deviceID, req)
	if err != nil {
		return h.manager.Send(deviceID, &pm.ServerMessage{
			Id: msgID,
			Payload: &pm.ServerMessage_Error{
				Error: &pm.Error{
					Code:    connect.CodeNotFound.String(),
					Message: "no LUKS key found for this action",
				},
			},
		})
	}
	return h.manager.Send(deviceID, &pm.ServerMessage{
		Id: msgID,
		Payload: &pm.ServerMessage_GetLuksKey{
			GetLuksKey: resp,
		},
	})
}

func (h *AgentHandler) handleStoreLuksKey(ctx context.Context, deviceID, msgID string, req *pm.StoreLuksKeyRequest) error {
	// The sealed-blob length guard is gone with the seal itself: the passphrase
	// now arrives as plaintext over the stream's own mTLS, and control encrypts
	// it at rest. There is no relay left to withhold it from.
	resp, err := h.ops.StoreLuksKey(ctx, deviceID, req)
	if err != nil {
		return h.manager.Send(deviceID, &pm.ServerMessage{
			Id: msgID,
			Payload: &pm.ServerMessage_Error{
				Error: &pm.Error{
					Code:    connect.CodeInternal.String(),
					Message: fmt.Sprintf("failed to store LUKS key: %v", err),
				},
			},
		})
	}
	return h.manager.Send(deviceID, &pm.ServerMessage{
		Id: msgID,
		Payload: &pm.ServerMessage_StoreLuksKey{
			StoreLuksKey: resp,
		},
	})
}

// handleStoreLpsPasswords persists a batch of rotated local passwords.
//
// The agent used to smuggle these through ActionResult metadata as sealed
// base64, because the gateway relaying the result was not trusted to read them.
// They are now a first-class stream message carrying plaintext over mTLS.
//
// The reply is not optional. LPS rotation is irreversible — the agent has
// already changed the passwords locally — and the agent blocks on this response
// before clearing its pending state. A missing reply looks to it exactly like a
// lost batch, which is why the failure path answers with an error rather than
// returning silently.
func (h *AgentHandler) handleStoreLpsPasswords(ctx context.Context, deviceID, msgID string, req *pm.StoreLpsPasswordsRequest) error {
	resp, err := h.ops.StoreLpsPasswords(ctx, deviceID, req)
	if err != nil {
		h.logger.Error("failed to store LPS passwords", "device_id", deviceID, "error", err)
		return h.manager.Send(deviceID, &pm.ServerMessage{
			Id: msgID,
			Payload: &pm.ServerMessage_Error{
				Error: &pm.Error{
					Code:    connect.CodeInternal.String(),
					Message: "failed to store LPS passwords",
				},
			},
		})
	}
	return h.manager.Send(deviceID, &pm.ServerMessage{
		Id: msgID,
		Payload: &pm.ServerMessage_StoreLpsPasswords{
			StoreLpsPasswords: resp,
		},
	})
}

func (h *AgentHandler) handleRevokeLuksResult(deviceID string, result *pm.RevokeLuksDeviceKeyResult) error {
	h.logger.Info("received LUKS device key revocation result",
		"device_id", deviceID,
		"action_id", result.ActionId,
		"success", result.Success,
		"error", result.Error,
	)
	return h.aqClient.EnqueueToControl(taskqueue.TypeRevokeLuksDeviceKeyResult, taskqueue.RevokeLuksDeviceKeyResultPayload{
		DeviceID: deviceID,
		ActionID: result.ActionId,
		Success:  result.Success,
		Error:    result.Error,
	})
}

func (h *AgentHandler) handleLogQueryResult(deviceID string, result *pm.LogQueryResult) error {
	h.logger.Info("received log query result",
		"device_id", deviceID,
		"query_id", result.QueryId,
		"success", result.Success,
	)
	return h.aqClient.EnqueueToControl(taskqueue.TypeLogQueryResult, taskqueue.LogQueryResultPayload{
		DeviceID: deviceID,
		QueryID:  result.QueryId,
		Success:  result.Success,
		Error:    result.Error,
		Logs:     result.Logs,
	})
}

// assertDeviceMatchesCert enforces that the mTLS client-certificate identity
// matches the device_id a device-scoped RPC claims to act on. It must run
// before any work so a compromised agent presenting device A's certificate
// cannot drive an operation against device B. When mTLS is not required
// (dev/test without a terminating gateway) it is a no-op. Shared by every
// device-scoped agent RPC so the binding cannot drift between them.
func (h *AgentHandler) assertDeviceMatchesCert(ctx context.Context, deviceID string) error {
	if !h.requireTLS {
		return nil
	}
	certDeviceID, ok := DeviceIDFromContext(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("mTLS authentication required"))
	}
	if certDeviceID != deviceID {
		h.logger.Warn("agent RPC device ID mismatch", "cert_device_id", certDeviceID, "requested_device_id", deviceID)
		return connect.NewError(connect.CodePermissionDenied, errors.New("device ID does not match certificate"))
	}
	return nil
}

// ValidateLuksToken validates and consumes a one-time LUKS token via the control server.
func (h *AgentHandler) ValidateLuksToken(ctx context.Context, req *connect.Request[pm.ValidateLuksTokenRequest]) (*connect.Response[pm.ValidateLuksTokenResponse], error) {
	if req.Msg.DeviceId == "" || req.Msg.Token == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("device_id and token are required"))
	}

	// Bind to the mTLS cert exactly as SyncActions does — without this a
	// compromised agent could redeem a LUKS token issued for another device.
	if err := h.assertDeviceMatchesCert(ctx, req.Msg.DeviceId); err != nil {
		return nil, err
	}

	resp, err := h.ops.ValidateLuksToken(ctx, req.Msg.DeviceId, req.Msg)
	if err != nil {
		h.logger.Warn("LUKS token validation failed", "device_id", req.Msg.DeviceId, "error", err)
		return nil, connect.NewError(connect.CodeNotFound, errors.New("token is invalid or has expired"))
	}

	return connect.NewResponse(resp), nil
}

// SyncActions returns all actions currently assigned to a device via the control server.
func (h *AgentHandler) SyncActions(ctx context.Context, req *connect.Request[pm.SyncActionsRequest]) (*connect.Response[pm.SyncActionsResponse], error) {
	deviceID := req.Msg.DeviceId.GetValue()
	if deviceID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("device_id is required"))
	}

	// Verify mTLS certificate matches requested device ID.
	if err := h.assertDeviceMatchesCert(ctx, deviceID); err != nil {
		return nil, err
	}

	h.logger.Info("agent syncing actions", "device_id", deviceID)

	resp, err := h.ops.SyncActions(ctx, deviceID)
	if err != nil {
		h.logger.Error("failed to proxy sync actions", "device_id", deviceID, "error", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get assigned actions"))
	}

	h.logger.Info("returning synced actions", "device_id", deviceID,
		"standalone_count", len(resp.StandaloneActions),
		"group_count", len(resp.GroupedActions),
		"sync_interval_minutes", resp.SyncIntervalMinutes)

	return connect.NewResponse(resp), nil
}
