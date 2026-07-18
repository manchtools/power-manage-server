// Package handler implements the Connect-RPC service handlers.
package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	sdkcrypto "github.com/manchtools/power-manage-sdk/crypto"
	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/gateway/registry"
	"github.com/manchtools/power-manage/server/internal/mtls"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// contextKey is a custom type for context keys.
type contextKey string

const (
	// DeviceIDContextKey is the context key for the device ID extracted from mTLS.
	DeviceIDContextKey contextKey = "device_id"
)

const registryDetachTimeout = 5 * time.Second

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
	controlProxy      *ControlProxy
	workerMgr         deviceWorkerManager
	logger            *slog.Logger
	serverVersion     string
	heartbeatInterval time.Duration
	requireTLS        bool

	// Multi-gateway routing. registry and gatewayID are set via
	// SetGatewayRouting at startup. nil registry means single-
	// gateway mode: device→gateway entries are not published and
	// the control server falls back to its static gateway URL.
	registry  *registry.Registry
	gatewayID string

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
	controlProxy *ControlProxy,
	workerMgr deviceWorkerManager,
	serverVersion string,
	heartbeatInterval time.Duration,
	logger *slog.Logger,
) *AgentHandler {
	return &AgentHandler{
		manager:           manager,
		aqClient:          aqClient,
		controlProxy:      controlProxy,
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
	controlProxy *ControlProxy,
	workerMgr deviceWorkerManager,
	serverVersion string,
	heartbeatInterval time.Duration,
	logger *slog.Logger,
) *AgentHandler {
	return &AgentHandler{
		manager:           manager,
		aqClient:          aqClient,
		controlProxy:      controlProxy,
		workerMgr:         workerMgr,
		serverVersion:     serverVersion,
		heartbeatInterval: heartbeatInterval,
		logger:            logger,
		requireTLS:        true,
	}
}

// SetGatewayRouting wires the multi-gateway registry into the
// handler. Called from cmd/gateway/main.go at startup. After this
// is set, every agent connect / heartbeat / disconnect publishes
// the device→gateway mapping to Valkey so the control server can
// route terminal sessions to the correct gateway. nil registry
// disables routing (single-gateway deployments).
func (h *AgentHandler) SetGatewayRouting(reg *registry.Registry, gatewayID string) {
	h.registry = reg
	h.gatewayID = gatewayID
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
		// A nil checker or one whose list has not loaded means we CANNOT prove
		// this cert is unrevoked → reject, never admit. There is no opt-out from
		// this gate — a deployment without a loaded CRL rejects every call here.
		if revocation == nil || !revocation.Loaded() {
			logger.Warn("mTLS rejected: certificate revocation unavailable (fail-closed)",
				"device_id", deviceID,
				"remote_addr", r.RemoteAddr,
				"checker_nil", revocation == nil,
			)
			http.Error(w, "client certificate revocation unavailable", http.StatusForbidden)
			return
		}
		fp := ca.FingerprintFromCert(r.TLS.PeerCertificates[0])
		if revocation.IsRevoked(fp) {
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
	if err := h.controlProxy.VerifyDevice(ctx, deviceID); err != nil {
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

	// Publish the device→gateway mapping in the multi-gateway
	// registry so ControlService.StartTerminal can route the user's
	// WebSocket to this specific gateway. Best-effort: a Valkey
	// failure here is logged but does not refuse the connection,
	// because terminal sessions are an optional feature on top of
	// the existing agent stream.
	if h.registry != nil {
		if err := h.registry.AttachDevice(ctx, deviceID, h.gatewayID, registry.DefaultDeviceTTL); err != nil {
			h.logger.Warn("failed to publish device→gateway mapping",
				"device_id", deviceID, "gateway_id", h.gatewayID, "error", err)
		}
	}

	// Start per-device Asynq worker to process action dispatches
	if err := h.workerMgr.StartWorker(deviceID); err != nil {
		h.logger.Warn("failed to start device worker", "device_id", deviceID, "error", err)
	}

	defer func() {
		// Only clean up if this is still the current agent connection.
		// A newer connection may have already replaced us via Register(),
		// and we must not stop its worker or unregister it.
		if current, ok := h.manager.Get(deviceID); ok && current == agent {
			h.workerMgr.StopWorker(deviceID)
		}
		// Re-check after StopWorker because it blocks during Shutdown().
		// The agent may have reconnected and replaced us while we waited.
		if current, ok := h.manager.Get(deviceID); ok && current == agent {
			h.manager.Unregister(deviceID)
			// Detach from the registry too. Same race-aware pattern:
			// only delete if we're still the current connection,
			// otherwise we'd evict a freshly-attached entry from a
			// reconnect that already happened. The detach context is
			// derived from the stream context but detached from its
			// cancellation so cleanup can finish after the RPC ends.
			if h.registry != nil {
				detachCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), registryDetachTimeout)
				defer cancel()
				if err := h.registry.DetachDevice(detachCtx, deviceID, h.gatewayID); err != nil {
					h.logger.Warn("failed to remove device→gateway mapping",
						"device_id", deviceID, "error", err)
				}
			}
		}
		h.logger.Info("agent disconnected", "device_id", deviceID)
	}()

	// Notify control server about agent connection so it can dispatch pending actions
	if err := h.aqClient.EnqueueToControl(taskqueue.TypeDeviceHello, taskqueue.DeviceHelloPayload{
		DeviceID:     deviceID,
		Hostname:     hello.Hostname,
		AgentVersion: hello.AgentVersion,
		GatewayID:    h.gatewayID,
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

	// Process incoming messages from agent
	for {
		msg, err := stream.Receive()
		if err != nil {
			// WS16 server#331: classify a clean agent shutdown as graceful
			// instead of re-emitting it up the stack as an error (which logged
			// every normal disconnect at error severity).
			if isStreamClosed(err) {
				h.logger.Info("agent stream closed", "device_id", deviceID)
				return nil
			}
			return err
		}

		h.manager.UpdateLastSeen(deviceID)

		if err := h.handleAgentMessage(ctx, deviceID, msg); err != nil {
			h.logger.Warn("handle agent message",
				"device_id", deviceID,
				"error", err,
			)
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
	payload := taskqueue.DeviceHeartbeatPayload{DeviceID: deviceID, GatewayID: h.gatewayID}
	// Refresh the device→gateway TTL on every heartbeat. Best-effort:
	// a Valkey failure here is logged but does not refuse the
	// heartbeat — the existing UpdateLastSeen path is the source of
	// truth for connection liveness. Inherits the bidi-stream ctx so
	// the refresh aborts when the agent stream tears down (audit N006).
	if h.registry != nil {
		if err := h.registry.RefreshDevice(ctx, deviceID, h.gatewayID, registry.DefaultDeviceTTL); err != nil {
			h.logger.Warn("failed to refresh device→gateway mapping",
				"device_id", deviceID, "error", err)
		}
	}
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

	if err := h.proxyLpsRotations(ctx, deviceID, resultID, result); err != nil {
		return err
	}

	// Binary protobuf, not protojson: no proto message is serialized as JSON over
	// the gateway→control queue (the result rides as binary inside the task).
	resultProto, err := proto.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal action result: %w", err)
	}
	return h.aqClient.EnqueueToControl(taskqueue.TypeExecutionResult, taskqueue.ExecutionResultPayload{
		DeviceID:          deviceID,
		ActionResultProto: resultProto,
		GatewayID:         h.gatewayID,
	})
}

// proxyLpsRotations extracts LPS password rotations from metadata, proxies them
// via internal RPC, and strips the key before the result is enqueued to Valkey.
// The gateway relays each rotation's SEALED password opaquely: the agent sealed
// it to control's LPS public key (spec 18), so the gateway — the least-trusted
// server-side actor — can no longer read rotated passwords. Unmarshal failures
// strip immediately (malformed, retry won't help). StoreLpsPasswords failures
// return an error — the agent will resend the result on reconnect, preserving
// the metadata for retry.
func (h *AgentHandler) proxyLpsRotations(ctx context.Context, deviceID, resultID string, result *pm.ActionResult) error {
	if result.Metadata == nil {
		return nil
	}
	rotationsJSON, ok := result.Metadata["lps.rotations"]
	if !ok || rotationsJSON == "" {
		return nil
	}

	// sealed_password is base64 of the agent's crypto.SealLpsPassword output.
	// A legacy agent (pre-sealed-transport) emits the old `password` cleartext
	// field instead; those entries are dropped loudly below — the gateway must
	// never proxy or enqueue a cleartext password.
	var rotations []struct {
		Username       string `json:"username"`
		SealedPassword string `json:"sealed_password"`
		RotatedAt      string `json:"rotated_at"`
		Reason         string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(rotationsJSON), &rotations); err != nil {
		delete(result.Metadata, "lps.rotations")
		h.logger.Error("failed to unmarshal lps.rotations metadata", "error", err)
		return nil
	}
	if len(rotations) == 0 {
		delete(result.Metadata, "lps.rotations")
		return nil
	}

	protoRotations := make([]*pm.LpsPasswordRotation, 0, len(rotations))
	for _, r := range rotations {
		if r.SealedPassword == "" {
			// Legacy cleartext entry (or a malformed one): the agent predates
			// sealed LPS transport. The local rotation already happened; it
			// becomes centrally recoverable again at the next post-upgrade
			// rotation. Drop it — never proxy cleartext.
			h.logger.Error("dropping LPS rotation without a sealed password (agent predates sealed LPS transport)",
				"device_id", deviceID)
			continue
		}
		sealed, err := base64.StdEncoding.DecodeString(r.SealedPassword)
		if err != nil {
			h.logger.Error("dropping LPS rotation with undecodable sealed password",
				"device_id", deviceID, "error", err)
			continue
		}
		protoRotations = append(protoRotations, &pm.LpsPasswordRotation{
			Username:       r.Username,
			SealedPassword: sealed,
			RotatedAt:      r.RotatedAt,
			Reason:         rotationReasonFromAgentString(r.Reason),
		})
	}
	// Every entry was legacy/malformed and dropped: nothing to proxy, but the
	// metadata must still be stripped before the result is enqueued to Valkey.
	if len(protoRotations) == 0 {
		delete(result.Metadata, "lps.rotations")
		return nil
	}
	if err := h.controlProxy.StoreLpsPasswords(ctx, deviceID, resultID, protoRotations); err != nil {
		return fmt.Errorf("store lps passwords: %w", err)
	}
	delete(result.Metadata, "lps.rotations")
	return nil
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
		GatewayID:   h.gatewayID,
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
		DeviceID:  deviceID,
		QueryID:   result.QueryId,
		Success:   result.Success,
		Error:     result.Error,
		RowsJSON:  rowsBytes,
		GatewayID: h.gatewayID,
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
		DeviceID:  deviceID,
		Tables:    tables,
		GatewayID: h.gatewayID,
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
		GatewayID: h.gatewayID,
	})
}

func (h *AgentHandler) handleGetLuksKey(ctx context.Context, deviceID, msgID string, req *pm.GetLuksKeyRequest) error {
	resp, err := h.controlProxy.GetLuksKey(ctx, deviceID, req.ActionId)
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
	// Legacy-cleartext guard (spec 25): a pre-sealed-transport agent puts a
	// cleartext passphrase where sealed bytes belong (string→bytes is
	// wire-compatible). Anything shorter than a minimal sealed blob cannot
	// be one — drop it loudly and never proxy. Control's unseal is the
	// authority for the remainder; the gateway just refuses the obvious.
	if len(req.SealedPassphrase) < sdkcrypto.MinSealedLen {
		h.logger.Error("dropping LUKS key store without a sealed passphrase (agent predates sealed LUKS transport)",
			"device_id", deviceID, "action_id", req.ActionId)
		return h.manager.Send(deviceID, &pm.ServerMessage{
			Id: msgID,
			Payload: &pm.ServerMessage_Error{
				Error: &pm.Error{
					Code:    connect.CodeInvalidArgument.String(),
					Message: "sealed passphrase required: update the agent (sealed LUKS transport, spec 25)",
				},
			},
		})
	}

	resp, err := h.controlProxy.StoreLuksKey(ctx, deviceID, req.ActionId, req.DevicePath, req.SealedPassphrase, req.RotationReason)
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

func (h *AgentHandler) handleRevokeLuksResult(deviceID string, result *pm.RevokeLuksDeviceKeyResult) error {
	h.logger.Info("received LUKS device key revocation result",
		"device_id", deviceID,
		"action_id", result.ActionId,
		"success", result.Success,
		"error", result.Error,
	)
	return h.aqClient.EnqueueToControl(taskqueue.TypeRevokeLuksDeviceKeyResult, taskqueue.RevokeLuksDeviceKeyResultPayload{
		DeviceID:  deviceID,
		ActionID:  result.ActionId,
		Success:   result.Success,
		Error:     result.Error,
		GatewayID: h.gatewayID,
	})
}

func (h *AgentHandler) handleLogQueryResult(deviceID string, result *pm.LogQueryResult) error {
	h.logger.Info("received log query result",
		"device_id", deviceID,
		"query_id", result.QueryId,
		"success", result.Success,
	)
	return h.aqClient.EnqueueToControl(taskqueue.TypeLogQueryResult, taskqueue.LogQueryResultPayload{
		DeviceID:  deviceID,
		QueryID:   result.QueryId,
		Success:   result.Success,
		Error:     result.Error,
		Logs:      result.Logs,
		GatewayID: h.gatewayID,
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

	resp, err := h.controlProxy.ValidateLuksToken(ctx, req.Msg.DeviceId, req.Msg.Token)
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

	resp, err := h.controlProxy.SyncActions(ctx, deviceID)
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

// rotationReasonFromAgentString maps the lowercase string the agent
// puts into the lps.rotations metadata JSON ("initial" / "scheduled")
// to the wire enum the gateway forwards to control. Unknown values
// (including the empty string an older agent might emit) collapse to
// UNSPECIFIED — the projector defaults UNSPECIFIED-equivalent rows to
// "scheduled" downstream, matching the historical PL/pgSQL COALESCE
// behaviour. Inverse of api.rotationReasonToString in
// server/internal/api/internal_handler.go; kept here in handler so
// the gateway package does not gain an api dependency.
func rotationReasonFromAgentString(s string) pm.RotationReason {
	switch s {
	case "initial":
		return pm.RotationReason_ROTATION_REASON_INITIAL
	case "scheduled":
		return pm.RotationReason_ROTATION_REASON_SCHEDULED
	case "auth_grace":
		return pm.RotationReason_ROTATION_REASON_AUTH_GRACE
	default:
		return pm.RotationReason_ROTATION_REASON_UNSPECIFIED
	}
}
