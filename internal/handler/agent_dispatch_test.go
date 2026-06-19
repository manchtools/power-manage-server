package handler

// handleAgentMessage dispatcher coverage for AgentHandler — closes
// the dispatch-table gap from manchtools/power-manage-server#150
// (the bidi-stream entrypoint Stream() still needs a client-stream
// fixture, but its dispatcher core is testable in isolation).
//
// Strategy: build an AgentHandler with the existing recording
// fakeEnqueuer (from agent_handlers_test.go) and a TerminalSessionRegistry,
// then drive handleAgentMessage with each AgentMessage_X payload
// variant. Side effects on the enqueuer / registry are the asserts.

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// =============================================================================
// Per-payload-variant dispatch
// =============================================================================

func TestHandleAgentMessage_Heartbeat_DispatchesToHandleHeartbeat(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)

	require.NoError(t, h.handleAgentMessage(context.Background(), "dev-1", &pm.AgentMessage{
		Payload: &pm.AgentMessage_Heartbeat{Heartbeat: &pm.Heartbeat{}},
	}))

	last := fake.lastCall(t)
	assert.Equal(t, taskqueue.TypeDeviceHeartbeat, last.taskType,
		"Heartbeat payload must dispatch to handleHeartbeat")
}

func TestHandleAgentMessage_OutputChunk_DispatchesToHandleOutputChunk(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)

	require.NoError(t, h.handleAgentMessage(context.Background(), "dev-1", &pm.AgentMessage{
		Payload: &pm.AgentMessage_OutputChunk{OutputChunk: &pm.OutputChunk{
			ExecutionId: "exec-1",
			Stream:      pm.OutputStreamType_OUTPUT_STREAM_TYPE_STDOUT,
			Data:        []byte("hi"),
		}},
	}))

	last := fake.lastCall(t)
	assert.Equal(t, taskqueue.TypeExecutionOutputChunk, last.taskType)
}

func TestHandleAgentMessage_QueryResult_DispatchesToHandleQueryResult(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)

	require.NoError(t, h.handleAgentMessage(context.Background(), "dev-1", &pm.AgentMessage{
		Payload: &pm.AgentMessage_QueryResult{QueryResult: &pm.OSQueryResult{
			QueryId: "q-1", Success: true,
		}},
	}))

	assert.Equal(t, taskqueue.TypeOSQueryResult, fake.lastCall(t).taskType)
}

func TestHandleAgentMessage_Inventory_DispatchesToHandleInventory(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)

	require.NoError(t, h.handleAgentMessage(context.Background(), "dev-1", &pm.AgentMessage{
		Payload: &pm.AgentMessage_Inventory{Inventory: &pm.DeviceInventory{}},
	}))

	assert.Equal(t, taskqueue.TypeInventoryUpdate, fake.lastCall(t).taskType)
}

func TestHandleAgentMessage_SecurityAlert_DispatchesToHandleSecurityAlert(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)

	require.NoError(t, h.handleAgentMessage(context.Background(), "dev-1", &pm.AgentMessage{
		Payload: &pm.AgentMessage_SecurityAlert{SecurityAlert: &pm.SecurityAlert{
			Type:    pm.SecurityAlertType_SECURITY_ALERT_TYPE_INVALID_CERTIFICATE,
			Message: "cert mismatch",
		}},
	}))

	assert.Equal(t, taskqueue.TypeSecurityAlert, fake.lastCall(t).taskType)
}

func TestHandleAgentMessage_RevokeLuksDeviceKeyResult_DispatchesToHandleRevokeLuksResult(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)

	require.NoError(t, h.handleAgentMessage(context.Background(), "dev-1", &pm.AgentMessage{
		Payload: &pm.AgentMessage_RevokeLuksDeviceKeyResult{
			RevokeLuksDeviceKeyResult: &pm.RevokeLuksDeviceKeyResult{ActionId: "act-1", Success: true},
		},
	}))

	assert.Equal(t, taskqueue.TypeRevokeLuksDeviceKeyResult, fake.lastCall(t).taskType)
}

func TestHandleAgentMessage_LogQueryResult_DispatchesToHandleLogQueryResult(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)

	require.NoError(t, h.handleAgentMessage(context.Background(), "dev-1", &pm.AgentMessage{
		Payload: &pm.AgentMessage_LogQueryResult{LogQueryResult: &pm.LogQueryResult{
			QueryId: "q-1", Success: true,
		}},
	}))

	assert.Equal(t, taskqueue.TypeLogQueryResult, fake.lastCall(t).taskType)
}

// =============================================================================
// Unknown payload — fail-loud
// =============================================================================

func TestHandleAgentMessage_NilPayload_ReturnsError(t *testing.T) {
	// A message with no payload set goes to the default branch and
	// returns "unknown message type". This is the right shape: the
	// bidi-stream handler logs + continues, which surfaces operator
	// visibility into agents sending malformed messages.
	h, _ := newAgentHandlerForTest(t)

	err := h.handleAgentMessage(context.Background(), "dev-1", &pm.AgentMessage{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown message type")
}

// =============================================================================
// Terminal-output cross-tenant guard
// =============================================================================

func TestHandleAgentMessage_TerminalOutput_NilRegistryIsNoOp(t *testing.T) {
	// Without terminalSessions wired (single-gateway dev mode), the
	// dispatcher must not panic on TerminalOutput — it just drops
	// the message silently. Pre-#150 this was the documented behaviour.
	h, _ := newAgentHandlerForTest(t)

	require.NoError(t, h.handleAgentMessage(context.Background(), "dev-1", &pm.AgentMessage{
		Payload: &pm.AgentMessage_TerminalOutput{TerminalOutput: &pm.TerminalOutput{
			SessionId: "sess-1",
		}},
	}))
}

func TestHandleAgentMessage_TerminalOutput_DeviceMismatchDrops(t *testing.T) {
	// Critical security guard: if a compromised agent sends a
	// TerminalOutput message claiming to be for a session belonging
	// to a DIFFERENT device, the dispatcher must drop the message.
	// Routing it would let agent A inject TTY output into agent B's
	// terminal session.
	h, _ := newAgentHandlerForTest(t)
	registry := connection.NewTerminalSessionRegistry()
	registry.Register(&connection.TerminalSession{
		SessionID: "sess-1",
		DeviceID:  "dev-victim",
		StartedAt: time.Now(),
		OutputCh:  make(chan *pm.AgentMessage, 1),
	})
	h.terminalSessions = registry

	// Compromised agent dev-attacker sends output for dev-victim's session.
	require.NoError(t, h.handleAgentMessage(context.Background(), "dev-attacker", &pm.AgentMessage{
		Payload: &pm.AgentMessage_TerminalOutput{TerminalOutput: &pm.TerminalOutput{
			SessionId: "sess-1",
		}},
	}))

	// The session's OutputCh must remain empty — the output was dropped.
	sess := registry.Get("sess-1")
	require.NotNil(t, sess)
	select {
	case <-sess.OutputCh:
		t.Fatal("cross-tenant TerminalOutput leaked through to victim's session — security regression")
	default:
		// expected: no message routed
	}
}

func TestHandleAgentMessage_TerminalOutput_UnknownSessionIsLoggedAndDropped(t *testing.T) {
	// Session ID that doesn't exist in the registry → log Debug + drop.
	// Test asserts no panic + handler returns nil.
	h, _ := newAgentHandlerForTest(t)
	h.terminalSessions = connection.NewTerminalSessionRegistry()

	require.NoError(t, h.handleAgentMessage(context.Background(), "dev-1", &pm.AgentMessage{
		Payload: &pm.AgentMessage_TerminalOutput{TerminalOutput: &pm.TerminalOutput{
			SessionId: "sess-does-not-exist",
		}},
	}))
}

func TestHandleAgentMessage_TerminalOutput_HappyPathRoutesToSession(t *testing.T) {
	// Same device on both sides → route to the registered session.
	h, _ := newAgentHandlerForTest(t)
	registry := connection.NewTerminalSessionRegistry()
	registry.Register(&connection.TerminalSession{
		SessionID: "sess-1",
		DeviceID:  "dev-1",
		StartedAt: time.Now(),
		OutputCh:  make(chan *pm.AgentMessage, 1),
	})
	h.terminalSessions = registry

	msg := &pm.AgentMessage{
		Payload: &pm.AgentMessage_TerminalOutput{TerminalOutput: &pm.TerminalOutput{
			SessionId: "sess-1",
		}},
	}
	require.NoError(t, h.handleAgentMessage(context.Background(), "dev-1", msg))

	sess := registry.Get("sess-1")
	require.NotNil(t, sess)
	select {
	case routed := <-sess.OutputCh:
		assert.Same(t, msg, routed, "the message routed must be the SAME pointer the agent sent")
	default:
		t.Fatal("happy-path TerminalOutput failed to route to the session — bidi flow broken")
	}
}

// =============================================================================
// Terminal-state-change cross-tenant guard (mirror of TerminalOutput path)
// =============================================================================

func TestHandleAgentMessage_TerminalStateChange_DeviceMismatchDrops(t *testing.T) {
	h, _ := newAgentHandlerForTest(t)
	registry := connection.NewTerminalSessionRegistry()
	registry.Register(&connection.TerminalSession{
		SessionID: "sess-1",
		DeviceID:  "dev-victim",
		StartedAt: time.Now(),
		OutputCh:  make(chan *pm.AgentMessage, 1),
	})
	h.terminalSessions = registry

	require.NoError(t, h.handleAgentMessage(context.Background(), "dev-attacker", &pm.AgentMessage{
		Payload: &pm.AgentMessage_TerminalStateChange{TerminalStateChange: &pm.TerminalStateChange{
			SessionId: "sess-1",
			State:     pm.TerminalSessionState_TERMINAL_SESSION_STATE_EXITED,
		}},
	}))

	sess := registry.Get("sess-1")
	require.NotNil(t, sess)
	select {
	case <-sess.OutputCh:
		t.Fatal("cross-tenant TerminalStateChange leaked through")
	default:
	}
}

// Belt-and-suspenders import guard.
var _ = slog.Default
