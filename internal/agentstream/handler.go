// Package agentstream terminates the authenticated device connection directly
// in control. Frames are applied to SQLite-backed services without a relay,
// broker, or application-signature layer.
package agentstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/durationpb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/delivery"
	"github.com/manchtools/power-manage/server/internal/execution"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

type frameClass string

const (
	frameState     frameClass = "state"
	frameHello     frameClass = "hello"
	frameTelemetry frameClass = "telemetry"
	frameAudit     frameClass = "audit"
	frameBulk      frameClass = "bulk"
	frameTerminal  frameClass = "terminal"
)

const frameRateWindow = time.Minute

// DeviceResults is the direct sink for device-owned result frames.
type DeviceResults interface {
	CompleteOSQueryResult(context.Context, string, *pmv1.OSQueryResult) error
	CompleteLogQueryResult(context.Context, string, *pmv1.LogQueryResult) error
	StoreDeviceInventory(context.Context, string, *pmv1.DeviceInventory) error
	CompleteLuksKeyRevocation(context.Context, string, *pmv1.RevokeLuksDeviceKeyResult) error
}

// DeliveryState advances the durable delivery state machine.
type DeliveryState interface {
	AcknowledgeReceipt(context.Context, string, string) (bool, error)
	Complete(context.Context, string, string, string, string, string) (bool, error)
}

// ExecutionResults commits per-occurrence results and streamed output.
type ExecutionResults interface {
	ApplyActionResult(context.Context, string, *pmv1.ActionResult) error
	AppendOutputChunk(context.Context, string, *pmv1.OutputChunk) error
}

// Secrets owns the narrow feature sinks for sealed LUKS and LPS fields.
type Secrets interface {
	ValidateLuksToken(context.Context, string, *pmv1.ValidateLuksTokenRequest) (*pmv1.ValidateLuksTokenResponse, error)
	GetLuksKey(context.Context, string, *pmv1.GetLuksKeyRequest) (*pmv1.GetLuksKeyResponse, error)
	StoreLuksKey(context.Context, string, *pmv1.StoreLuksKeyRequest) (*pmv1.StoreLuksKeyResponse, error)
	StoreLpsPasswords(context.Context, string, *pmv1.StoreLpsPasswordsRequest) (*pmv1.StoreLpsPasswordsResponse, error)
}

// SyncSource returns the durable delivery backlog and current scheduling policy
// for the authenticated device.
type SyncSource interface {
	Sync(context.Context, string) (*pmv1.SyncState, error)
}

// DeviceWaker queues a reconnect's durable delivery backlog. The database
// sweep remains the correctness path when this best-effort wake is missed.
type DeviceWaker interface {
	WakeDevice(context.Context, string) error
}

// Config supplies the direct services used by AgentService.
type Config struct {
	Store             *store.Store
	Manager           *connection.Manager
	Deliveries        DeliveryState
	Executions        ExecutionResults
	DeviceResults     DeviceResults
	Secrets           Secrets
	Sync              SyncSource
	Waker             DeviceWaker
	TerminalSessions  *connection.TerminalSessionRegistry
	Logger            *slog.Logger
	ServerVersion     string
	DeviceLoginURL    string
	HeartbeatInterval time.Duration
	Now               func() time.Time
}

// Handler implements the target AgentService without legacy transport paths.
type Handler struct {
	powermanagev1connect.UnimplementedAgentServiceHandler

	store             *store.Store
	manager           *connection.Manager
	deliveries        DeliveryState
	executions        ExecutionResults
	deviceResults     DeviceResults
	secrets           Secrets
	sync              SyncSource
	waker             DeviceWaker
	terminalSessions  *connection.TerminalSessionRegistry
	logger            *slog.Logger
	serverVersion     string
	deviceLoginURL    string
	heartbeatInterval time.Duration
	now               func() time.Time
	validator         interface{ Struct(any) error }
	frameLimiters     map[frameClass]*auth.RateLimiter
	frameDropAudits   *auth.RateLimiter
}

// New constructs the direct AgentService handler.
func New(cfg Config) *Handler {
	if cfg.Store == nil || cfg.Manager == nil || cfg.Deliveries == nil || cfg.Executions == nil ||
		cfg.DeviceResults == nil || cfg.Secrets == nil || cfg.Sync == nil || cfg.Waker == nil || cfg.TerminalSessions == nil {
		panic("agentstream: complete direct service wiring is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Handler{
		store: cfg.Store, manager: cfg.Manager, deliveries: cfg.Deliveries, executions: cfg.Executions,
		deviceResults: cfg.DeviceResults, secrets: cfg.Secrets, sync: cfg.Sync, waker: cfg.Waker,
		terminalSessions: cfg.TerminalSessions, logger: cfg.Logger,
		serverVersion: cfg.ServerVersion, deviceLoginURL: cfg.DeviceLoginURL,
		heartbeatInterval: cfg.HeartbeatInterval, now: cfg.Now,
		validator: sdkvalidate.NewValidator(),
		// These are deliberately generous ingestion ceilings, not ordinary
		// operating rates. A healthy agent stays far below every budget.
		frameLimiters: map[frameClass]*auth.RateLimiter{
			frameState:     auth.NewRateLimiter(600, frameRateWindow),
			frameHello:     auth.NewRateLimiter(10, frameRateWindow),
			frameTelemetry: auth.NewRateLimiter(12, frameRateWindow),
			frameAudit:     auth.NewRateLimiter(30, frameRateWindow),
			frameBulk:      auth.NewRateLimiter(4097, frameRateWindow),
			frameTerminal:  auth.NewRateLimiter(6000, frameRateWindow),
		},
		frameDropAudits: auth.NewRateLimiter(1, frameRateWindow),
	}
}

// Close stops the process-local frame-budget cleanup loops.
func (h *Handler) Close() {
	if h == nil {
		return
	}
	for _, limiter := range h.frameLimiters {
		limiter.Stop()
	}
	if h.frameDropAudits != nil {
		h.frameDropAudits.Stop()
	}
}

// Stream owns one authenticated device connection.
func (h *Handler) Stream(ctx context.Context, stream *connect.BidiStream[pmv1.AgentMessage, pmv1.ServerMessage]) error {
	deviceID, ok := DeviceIDFromContext(ctx)
	if !ok || !validID(deviceID) {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("authenticated device identity required"))
	}
	first, err := stream.Receive()
	if err != nil {
		return normalizeStreamClose(err)
	}
	if err := h.validator.Struct(first); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("invalid hello frame"))
	}
	hello := first.GetHello()
	if hello == nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("first frame must be hello"))
	}
	if hello.GetDeviceId().GetValue() != deviceID {
		return connect.NewError(connect.CodePermissionDenied, errors.New("device identity mismatch"))
	}
	if !h.allowFrame(deviceID, first) {
		h.recordFrameDrop(ctx, deviceID, first)
		return connect.NewError(connect.CodeResourceExhausted, errors.New("agent connection rate limit exceeded"))
	}
	if err := h.recordHello(ctx, deviceID, hello); err != nil {
		if store.IsNotFound(err) {
			return connect.NewError(connect.CodePermissionDenied, errors.New("device is not registered"))
		}
		h.logger.Error("record agent hello", "device_id", deviceID, "error", err)
		return connect.NewError(connect.CodeInternal, errors.New("could not establish device session"))
	}

	agent := h.manager.Register(ctx, deviceID, hello.Hostname, hello.AgentVersion, stream)
	if deadliner := writeDeadlinerFrom(ctx); deadliner != nil {
		agent.SetWriteDeadlineFunc(deadliner.SetWriteDeadline)
	}
	defer func() {
		h.manager.UnregisterIfCurrent(deviceID, agent)
		agent.Close()
		agent.WaitForInFlightSend()
	}()

	welcome := &pmv1.Welcome{
		ServerVersion: h.serverVersion, DeviceLoginUrl: h.deviceLoginURL,
	}
	if h.heartbeatInterval > 0 {
		welcome.HeartbeatInterval = durationpb.New(h.heartbeatInterval)
	}
	if err := agent.Send(&pmv1.ServerMessage{
		Id: ulid.Make().String(), Payload: &pmv1.ServerMessage_Welcome{Welcome: welcome},
	}); err != nil {
		return fmt.Errorf("send welcome: %w", err)
	}
	if err := h.waker.WakeDevice(ctx, deviceID); err != nil {
		h.logger.Warn("wake device delivery backlog", "device_id", deviceID, "error", err)
	}

	type received struct {
		message *pmv1.AgentMessage
		err     error
	}
	receivedCh := make(chan received, 1)
	go func() {
		for {
			message, err := stream.Receive()
			select {
			case receivedCh <- received{message: message, err: err}:
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
			return nil
		case received := <-receivedCh:
			if received.err != nil {
				return normalizeStreamClose(received.err)
			}
			if agent.Terminated() {
				return nil
			}
			if err := h.validator.Struct(received.message); err != nil {
				return connect.NewError(connect.CodeInvalidArgument, errors.New("invalid agent frame"))
			}
			if !h.allowFrame(deviceID, received.message) {
				h.recordFrameDrop(ctx, deviceID, received.message)
				continue
			}
			h.manager.UpdateLastSeen(deviceID)
			if err := h.handleAgentMessage(ctx, agent, received.message); err != nil {
				h.logger.Warn("apply agent frame", "device_id", deviceID,
					"frame", fmt.Sprintf("%T", received.message.Payload), "error", err)
				if frameNotAuthorized(err) {
					return connect.NewError(connect.CodePermissionDenied,
						errors.New("agent frame claimed a resource it does not own"))
				}
				continue
			}
		}
	}
}

func (h *Handler) recordFrameDrop(ctx context.Context, deviceID string, message *pmv1.AgentMessage) {
	class := frameClassOf(message)
	if h.frameDropAudits != nil && !h.frameDropAudits.Allow(deviceID) {
		return
	}
	op := agentOperation(deviceID, "FrameRateLimit/"+string(class))
	op.AuthorizationOutcome = store.AuthorizationDenied
	op.AuthorizationDetail = "device_frame_budget"
	op.Result = store.ResultRejected
	// The dropped frame's class rides the result code. It is not a row
	// reference, so it must not go in an effect's after_ref: that column
	// only accepts a ULID and the rejected INSERT rolls the operation row
	// back with it, leaving an abusive device no durable trace at all.
	op.ResultCode = "RATE_LIMITED." + string(class)
	_, err := h.store.RecordOperation(ctx, op, store.AuditEffect{
		ResourceType: "device", ResourceID: deviceID, Action: "FRAME_RATE_LIMIT",
		Outcome: store.EffectRejected,
	})
	if err != nil {
		h.logger.Error("record agent frame rate limit", "device_id", deviceID, "class", class, "error", err)
	}
	h.logger.Warn("agent frame rate limit exceeded", "device_id", deviceID, "class", class)
}

func (h *Handler) handleAgentMessage(ctx context.Context, agent *connection.Agent, message *pmv1.AgentMessage) error {
	deviceID := agent.DeviceID
	switch payload := message.Payload.(type) {
	case *pmv1.AgentMessage_Heartbeat:
		return nil
	case *pmv1.AgentMessage_SyncRequest:
		response, err := h.sync.Sync(ctx, deviceID)
		return h.sendResponse(agent, message.Id, response, err)
	case *pmv1.AgentMessage_DeliveryReceipt:
		_, err := h.deliveries.AcknowledgeReceipt(ctx, payload.DeliveryReceipt.DeliveryId, deviceID)
		return err
	case *pmv1.AgentMessage_ManifestResult:
		state, code, err := manifestResultState(payload.ManifestResult)
		if err != nil {
			return err
		}
		_, err = h.deliveries.Complete(ctx, payload.ManifestResult.DeliveryId, deviceID,
			payload.ManifestResult.ManifestId, state, code)
		return err
	case *pmv1.AgentMessage_ActionResult:
		return h.executions.ApplyActionResult(ctx, deviceID, payload.ActionResult)
	case *pmv1.AgentMessage_OutputChunk:
		return h.executions.AppendOutputChunk(ctx, deviceID, payload.OutputChunk)
	case *pmv1.AgentMessage_QueryResult:
		return h.deviceResults.CompleteOSQueryResult(ctx, deviceID, payload.QueryResult)
	case *pmv1.AgentMessage_LogQueryResult:
		return h.deviceResults.CompleteLogQueryResult(ctx, deviceID, payload.LogQueryResult)
	case *pmv1.AgentMessage_Inventory:
		return h.deviceResults.StoreDeviceInventory(ctx, deviceID, payload.Inventory)
	case *pmv1.AgentMessage_RevokeLuksDeviceKeyResult:
		return h.deviceResults.CompleteLuksKeyRevocation(ctx, deviceID, payload.RevokeLuksDeviceKeyResult)
	case *pmv1.AgentMessage_SecurityAlert:
		return h.recordSecurityAlert(ctx, deviceID, payload.SecurityAlert)
	case *pmv1.AgentMessage_GetLuksKey:
		response, err := h.secrets.GetLuksKey(ctx, deviceID, payload.GetLuksKey)
		return h.sendResponse(agent, message.Id, response, err)
	case *pmv1.AgentMessage_StoreLuksKey:
		response, err := h.secrets.StoreLuksKey(ctx, deviceID, payload.StoreLuksKey)
		return h.sendResponse(agent, message.Id, response, err)
	case *pmv1.AgentMessage_StoreLpsPasswords:
		response, err := h.secrets.StoreLpsPasswords(ctx, deviceID, payload.StoreLpsPasswords)
		return h.sendResponse(agent, message.Id, response, err)
	case *pmv1.AgentMessage_ValidateLuksToken:
		response, err := h.secrets.ValidateLuksToken(ctx, deviceID, payload.ValidateLuksToken)
		return h.sendResponse(agent, message.Id, response, err)
	case *pmv1.AgentMessage_TerminalOutput:
		return h.routeTerminal(deviceID, payload.TerminalOutput.SessionId, message)
	case *pmv1.AgentMessage_TerminalStateChange:
		return h.routeTerminal(deviceID, payload.TerminalStateChange.SessionId, message)
	case *pmv1.AgentMessage_Hello:
		return errors.New("hello is only valid as the first frame")
	default:
		return errors.New("unsupported agent frame")
	}
}

func (h *Handler) allowFrame(deviceID string, message *pmv1.AgentMessage) bool {
	if h == nil || h.frameLimiters == nil {
		return true
	}
	limiter := h.frameLimiters[frameClassOf(message)]
	return limiter == nil || limiter.Allow(deviceID)
}

func frameClassOf(message *pmv1.AgentMessage) frameClass {
	if message == nil {
		return frameState
	}
	switch message.Payload.(type) {
	case *pmv1.AgentMessage_Hello:
		return frameHello
	case *pmv1.AgentMessage_Heartbeat:
		return frameTelemetry
	case *pmv1.AgentMessage_SecurityAlert:
		return frameAudit
	case *pmv1.AgentMessage_OutputChunk:
		return frameBulk
	case *pmv1.AgentMessage_TerminalOutput, *pmv1.AgentMessage_TerminalStateChange:
		return frameTerminal
	default:
		return frameState
	}
}

func (h *Handler) sendResponse(agent *connection.Agent, messageID string, response any, operationErr error) error {
	if operationErr != nil {
		h.logger.Warn("agent request failed", "device_id", agent.DeviceID, "error", operationErr)
		return agent.Send(&pmv1.ServerMessage{
			Id: messageID,
			Payload: &pmv1.ServerMessage_Error{Error: &pmv1.Error{
				Code: connect.CodeFailedPrecondition.String(), Message: "secret operation failed",
			}},
		})
	}
	message := &pmv1.ServerMessage{Id: messageID}
	switch response := response.(type) {
	case *pmv1.GetLuksKeyResponse:
		message.Payload = &pmv1.ServerMessage_GetLuksKey{GetLuksKey: response}
	case *pmv1.StoreLuksKeyResponse:
		message.Payload = &pmv1.ServerMessage_StoreLuksKey{StoreLuksKey: response}
	case *pmv1.StoreLpsPasswordsResponse:
		message.Payload = &pmv1.ServerMessage_StoreLpsPasswords{StoreLpsPasswords: response}
	case *pmv1.ValidateLuksTokenResponse:
		message.Payload = &pmv1.ServerMessage_ValidateLuksToken{ValidateLuksToken: response}
	case *pmv1.SyncState:
		message.Payload = &pmv1.ServerMessage_SyncState{SyncState: response}
	default:
		return errors.New("unsupported agent response")
	}
	return agent.Send(message)
}

// errForeignTerminalSession is the terminal path's cross-device claim. It is
// a sentinel rather than an inline error so frameNotAuthorized can recognise
// it without matching on message text.
var errForeignTerminalSession = errors.New("terminal session belongs to another device")

// frameNotAuthorized reports whether a per-frame application error is the
// device claiming a resource that is not its own. Only those end the
// connection.
//
// Everything else — malformed input, a stale transition, an already-applied
// replay — is dropped and the stream continues. The agent's outbox is
// durable: a frame control refuses is re-sent on every reconnect, so ending
// the connection turns one bad frame into a permanent reconnect loop and
// discards every other frame the device was about to report. Defaulting to
// "keep the stream" is what makes a new sink's rejection safe by
// construction; a new cross-actor sentinel must be added here, and
// TestFrameAuthorizationClassificationCoversEveryCrossActorSentinel fails
// until it is.
func frameNotAuthorized(err error) bool {
	switch {
	case errors.Is(err, errForeignTerminalSession),
		errors.Is(err, execution.ErrWrongDevice),
		errors.Is(err, execution.ErrWrongDelivery),
		errors.Is(err, execution.ErrWrongAction),
		errors.Is(err, delivery.ErrWrongDevice),
		errors.Is(err, delivery.ErrWrongManifest):
		return true
	}
	var connectErr *connect.Error
	if errors.As(err, &connectErr) {
		switch connectErr.Code() {
		case connect.CodeUnauthenticated, connect.CodePermissionDenied:
			return true
		}
	}
	return false
}

func (h *Handler) routeTerminal(deviceID, sessionID string, message *pmv1.AgentMessage) error {
	session := h.terminalSessions.Get(sessionID)
	if session == nil {
		return nil
	}
	if session.DeviceID != deviceID {
		return errForeignTerminalSession
	}
	h.terminalSessions.RouteAgentMessage(sessionID, message)
	return nil
}

func (h *Handler) recordHello(ctx context.Context, deviceID string, hello *pmv1.Hello) error {
	if _, err := h.store.GetDevice(ctx, deviceID); err != nil {
		return err
	}
	now := h.now().UTC().Truncate(time.Microsecond)
	_, err := h.store.WithAudit(ctx, agentOperation(deviceID, "Hello"),
		func(ctx context.Context, tx *store.Tx, recorder *store.AuditRecorder) error {
			current, err := tx.GetDevice(ctx, deviceID)
			if err != nil {
				return err
			}
			rows, err := tx.RecordDeviceHello(ctx, db.RecordDeviceHelloParams{
				Hostname: hello.Hostname, AgentVersion: hello.AgentVersion, LastSeenAt: &now, ID: deviceID,
			})
			if err != nil {
				return err
			}
			if rows != 1 {
				return store.ErrNotFound
			}
			recorder.Effect(store.AuditEffect{
				ResourceType: "device", ResourceID: deviceID, Action: "CONNECT", Outcome: store.EffectApplied,
				ChangedFields: []string{"agent_version", "hostname", "last_seen_at"},
			})
			if current.Hostname != hello.Hostname {
				executionIDs, err := tx.ListExecutionIDsForDevice(ctx, deviceID)
				if err != nil {
					return err
				}
				for _, executionID := range executionIDs {
					recorder.RefreshSearch("execution", executionID)
				}
			}
			return nil
		})
	return err
}

func (h *Handler) recordSecurityAlert(ctx context.Context, deviceID string, alert *pmv1.SecurityAlert) error {
	if alert == nil || alert.Type == pmv1.SecurityAlertType_SECURITY_ALERT_TYPE_UNSPECIFIED {
		return errors.New("invalid security alert")
	}
	op := agentOperation(deviceID, "SecurityAlert")
	// The alert type is the record's whole content. It rides the result
	// code because that column takes 64 characters of the shape an enum
	// name has; the effect's action column stops at 32 and the longest
	// alert name is 47, and a reference column takes a ULID or nothing.
	op.ResultCode = alert.Type.String()
	_, err := h.store.RecordOperation(ctx, op, store.AuditEffect{
		ResourceType: "device", ResourceID: deviceID, Action: "SECURITY_ALERT",
		Outcome: store.EffectApplied,
	})
	return err
}

func manifestResultState(result *pmv1.ManifestResult) (state, code string, err error) {
	if result == nil {
		return "", "", errors.New("manifest result is required")
	}
	switch result.Status {
	case pmv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS:
		return delivery.StateSucceeded, "SUCCESS", nil
	case pmv1.ExecutionStatus_EXECUTION_STATUS_FAILED:
		return delivery.StateFailed, "FAILED", nil
	case pmv1.ExecutionStatus_EXECUTION_STATUS_INDETERMINATE:
		return delivery.StatePartial, "INDETERMINATE", nil
	default:
		return "", "", errors.New("invalid manifest result status")
	}
}

func validID(value string) bool {
	_, err := ulid.ParseStrict(value)
	return err == nil
}

func agentOperation(deviceID, descriptor string) store.AuditOperation {
	return store.AuditOperation{
		Class: store.ClassMutation, ActorType: "agent", ActorID: deviceID, Origin: "agent_stream",
		RequestDescriptor:    "powermanage.v1.AgentService.Stream/" + descriptor,
		AuthorizationOutcome: store.AuthorizationAllowed, AuthorizationDetail: "device_mtls",
		Result: store.ResultSuccess, ResultCode: "OK",
	}
}

func normalizeStreamClose(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return nil
	}
	var connectErr *connect.Error
	if errors.As(err, &connectErr) && (connectErr.Code() == connect.CodeCanceled ||
		(connectErr.Code() == connect.CodeUnknown && strings.Contains(connectErr.Message(), "EOF"))) {
		return nil
	}
	return err
}
