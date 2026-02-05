// Package control handles notifications from gateways via PostgreSQL LISTEN/NOTIFY.
package control

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/store"
)

// MessageType identifies the type of message being sent.
type MessageType string

const (
	// Messages from gateway to control server
	MessageTypeHello        MessageType = "hello"
	MessageTypeHeartbeat    MessageType = "heartbeat"
	MessageTypeActionResult MessageType = "action_result"
)

// Message represents a message from the gateway.
type Message struct {
	Type      MessageType     `json:"type"`
	DeviceID  string          `json:"device_id"`
	MessageID string          `json:"message_id"`
	Payload   json.RawMessage `json:"payload"`
}

// Handler processes messages from gateways via PostgreSQL LISTEN/NOTIFY.
type Handler struct {
	store  *store.Store
	logger *slog.Logger
}

// NewHandler creates a new control handler.
func NewHandler(st *store.Store, logger *slog.Logger) *Handler {
	return &Handler{
		store:  st,
		logger: logger,
	}
}

// Run starts listening for messages on the control_inbox channel.
// This method blocks until the context is cancelled.
func (h *Handler) Run(ctx context.Context) error {
	h.logger.Info("starting control handler, listening on control_inbox")

	if err := h.store.Listen(ctx, "control_inbox", func(channel, payload string) {
		h.logger.Debug("received notification", "channel", channel, "payload_length", len(payload))
		var msg Message
		if err := json.Unmarshal([]byte(payload), &msg); err != nil {
			h.logger.Error("failed to unmarshal message", "error", err, "payload", payload)
			return
		}
		h.handleMessage(ctx, &msg)
	}); err != nil {
		return err
	}

	h.logger.Debug("listener started, waiting for notifications")

	// Block until context is cancelled
	<-ctx.Done()
	return ctx.Err()
}

func (h *Handler) handleMessage(ctx context.Context, msg *Message) {
	logger := h.logger.With("message_id", msg.MessageID, "device_id", msg.DeviceID, "type", msg.Type)

	switch msg.Type {
	case MessageTypeHello:
		h.handleHello(ctx, msg, logger)
	case MessageTypeHeartbeat:
		h.handleHeartbeat(ctx, msg, logger)
	case MessageTypeActionResult:
		h.handleActionResult(ctx, msg, logger)
	default:
		logger.Warn("unknown message type")
	}
}

// HelloPayload is the payload for hello messages.
type HelloPayload struct {
	Hostname     string `json:"hostname"`
	AgentVersion string `json:"agent_version"`
}

func (h *Handler) handleHello(ctx context.Context, msg *Message, logger *slog.Logger) {
	var payload HelloPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		logger.Error("failed to unmarshal hello payload", "error", err)
		return
	}

	logger.Debug("received hello", "hostname", payload.Hostname, "version", payload.AgentVersion)

	// Emit DeviceHeartbeat event (trigger updates projection and may notify UI)
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   msg.DeviceID,
		EventType:  "DeviceHeartbeat",
		Data: map[string]any{
			"agent_version": payload.AgentVersion,
			"hostname":      payload.Hostname,
		},
		ActorType: "device",
		ActorID:   msg.DeviceID,
	}); err != nil {
		logger.Error("failed to append heartbeat event", "error", err)
		return
	}

	// Dispatch pending actions - the ExecutionDispatched event triggers notification to gateway
	h.dispatchPendingActions(ctx, msg.DeviceID, logger)
}

// HeartbeatPayload is the payload for heartbeat messages.
type HeartbeatPayload struct {
	Uptime       int64  `json:"uptime"`
	AgentVersion string `json:"agent_version"`
}

func (h *Handler) handleHeartbeat(ctx context.Context, msg *Message, logger *slog.Logger) {
	var payload HeartbeatPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		logger.Error("failed to unmarshal heartbeat payload", "error", err)
		return
	}

	logger.Debug("received heartbeat", "uptime", payload.Uptime)

	// Emit DeviceHeartbeat event
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   msg.DeviceID,
		EventType:  "DeviceHeartbeat",
		Data: map[string]any{
			"agent_version": payload.AgentVersion,
			"uptime":        payload.Uptime,
		},
		ActorType: "device",
		ActorID:   msg.DeviceID,
	}); err != nil {
		logger.Error("failed to append heartbeat event", "error", err)
	}
}

// ActionResultPayload is the payload for action result messages.
type ActionResultPayload struct {
	ActionID   string `json:"action_id"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
	Output     string `json:"output,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}

func (h *Handler) handleActionResult(ctx context.Context, msg *Message, logger *slog.Logger) {
	var payload ActionResultPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		logger.Error("failed to unmarshal action result payload", "error", err)
		return
	}

	logger = logger.With("action_id", payload.ActionID, "status", payload.Status)
	logger.Debug("received action result")

	// Determine the event type based on status
	var eventType string
	switch payload.Status {
	case "success":
		eventType = "ExecutionCompleted"
	case "failed":
		eventType = "ExecutionFailed"
	case "timeout":
		eventType = "ExecutionTimedOut"
	default:
		eventType = "ExecutionFailed"
	}

	// Emit execution result event
	data := map[string]any{
		"device_id":   msg.DeviceID,
		"status":      payload.Status,
		"duration_ms": payload.DurationMs,
	}
	if payload.Error != "" {
		data["error"] = payload.Error
	}
	if payload.Output != "" {
		data["output"] = payload.Output
	}

	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "execution",
		StreamID:   payload.ActionID,
		EventType:  eventType,
		Data:       data,
		ActorType:  "device",
		ActorID:    msg.DeviceID,
	}); err != nil {
		logger.Error("failed to append execution result event", "error", err)
	}
}

func (h *Handler) dispatchPendingActions(ctx context.Context, deviceID string, logger *slog.Logger) {
	logger.Debug("checking for pending executions", "device_id", deviceID)

	executions, err := h.store.Queries().ListPendingExecutionsForDevice(ctx, deviceID)
	if err != nil {
		logger.Error("failed to list pending executions", "error", err)
		return
	}

	logger.Debug("found pending executions", "device_id", deviceID, "count", len(executions))

	for _, exec := range executions {
		// Emit ExecutionDispatched event - this updates the UI
		if err := h.store.AppendEvent(ctx, store.Event{
			StreamType: "execution",
			StreamID:   exec.ID,
			EventType:  "ExecutionDispatched",
			Data: map[string]any{
				"device_id": deviceID,
			},
			ActorType: "system",
			ActorID:   "dispatcher",
		}); err != nil {
			logger.Error("failed to append dispatch event", "error", err, "execution_id", exec.ID)
			continue
		}

		// Notify the agent directly with action details
		// The ExecutionCreated trigger only fires on new executions,
		// so we need to manually notify for re-dispatched ones
		agentChannel := fmt.Sprintf("agent_%s", deviceID)

		// Parse params from []byte to avoid base64 encoding when marshaling
		// exec.Params is JSONB from PostgreSQL, which sqlc returns as []byte
		var params any
		if len(exec.Params) > 0 {
			if err := json.Unmarshal(exec.Params, &params); err != nil {
				logger.Warn("failed to parse params for execution",
					"execution_id", exec.ID,
					"error", err,
					"raw", string(exec.Params),
				)
				// Fallback: use the raw JSON string
				params = string(exec.Params)
			}
		}

		payload := map[string]any{
			"type":            "action_dispatch",
			"execution_id":    exec.ID,
			"action_type":     exec.ActionType,
			"desired_state":   exec.DesiredState,
			"params":          params,
			"timeout_seconds": exec.TimeoutSeconds,
		}
		payloadBytes, _ := json.Marshal(payload)
		logger.Debug("sending action dispatch notification",
			"execution_id", exec.ID,
			"channel", agentChannel,
			"payload", string(payloadBytes),
		)
		if err := h.store.Notify(ctx, agentChannel, string(payloadBytes)); err != nil {
			logger.Error("failed to notify agent", "error", err, "execution_id", exec.ID)
		}

		logger.Debug("dispatched execution", "execution_id", exec.ID)
	}
}
