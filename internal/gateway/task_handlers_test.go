package gateway

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/verify"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// TestParseActionParams_Package tests package parameter parsing.
func TestParseActionParams_Package(t *testing.T) {
	action := &pm.Action{}
	params := `{"name":"vim"}`
	require.NoError(t, actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_PACKAGE), []byte(params)))

	require.NotNil(t, action.GetPackage())
	assert.Equal(t, "vim", action.GetPackage().Name)
}

func TestParseActionParams_Shell(t *testing.T) {
	action := &pm.Action{}
	params := `{"script":"echo hello","runAsRoot":true}`
	require.NoError(t, actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_SHELL), []byte(params)))

	require.NotNil(t, action.GetShell())
	assert.Equal(t, "echo hello", action.GetShell().Script)
	assert.True(t, action.GetShell().RunAsRoot)
}

func TestParseActionParams_ScriptRun(t *testing.T) {
	action := &pm.Action{}
	params := `{"script":"#!/bin/bash\nexit 0"}`
	require.NoError(t, actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_SCRIPT_RUN), []byte(params)))

	require.NotNil(t, action.GetShell())
	assert.Contains(t, action.GetShell().Script, "exit 0")
}

func TestParseActionParams_Systemd(t *testing.T) {
	action := &pm.Action{}
	params := `{"unitName":"nginx.service","enable":true}`
	require.NoError(t, actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_SERVICE), []byte(params)))

	require.NotNil(t, action.GetService())
	assert.Equal(t, "nginx.service", action.GetService().UnitName)
	assert.True(t, action.GetService().Enable)
}

func TestParseActionParams_File(t *testing.T) {
	action := &pm.Action{}
	params := `{"path":"/etc/test.conf","content":"key=value"}`
	require.NoError(t, actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_FILE), []byte(params)))

	require.NotNil(t, action.GetFile())
	assert.Equal(t, "/etc/test.conf", action.GetFile().Path)
}

func TestParseActionParams_Directory(t *testing.T) {
	action := &pm.Action{}
	params := `{"path":"/opt/myapp"}`
	require.NoError(t, actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_DIRECTORY), []byte(params)))

	require.NotNil(t, action.GetDirectory())
	assert.Equal(t, "/opt/myapp", action.GetDirectory().Path)
}

func TestParseActionParams_Update(t *testing.T) {
	action := &pm.Action{}
	params := `{}`
	require.NoError(t, actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_UPDATE), []byte(params)))

	require.NotNil(t, action.GetUpdate())
}

func TestParseActionParams_Repository(t *testing.T) {
	action := &pm.Action{}
	params := `{"name":"myrepo"}`
	require.NoError(t, actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_REPOSITORY), []byte(params)))

	require.NotNil(t, action.GetRepository())
	assert.Equal(t, "myrepo", action.GetRepository().Name)
}

func TestParseActionParams_Flatpak(t *testing.T) {
	action := &pm.Action{}
	params := `{"appId":"org.gnome.Calculator"}`
	require.NoError(t, actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_FLATPAK), []byte(params)))

	require.NotNil(t, action.GetFlatpak())
	assert.Equal(t, "org.gnome.Calculator", action.GetFlatpak().AppId)
}

func TestParseActionParams_User(t *testing.T) {
	action := &pm.Action{}
	params := `{"username":"testuser"}`
	require.NoError(t, actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_USER), []byte(params)))

	require.NotNil(t, action.GetUser())
	assert.Equal(t, "testuser", action.GetUser().Username)
}

func TestParseActionParams_Group(t *testing.T) {
	action := &pm.Action{}
	params := `{"name":"developers"}`
	require.NoError(t, actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_GROUP), []byte(params)))

	require.NotNil(t, action.GetGroup())
	assert.Equal(t, "developers", action.GetGroup().Name)
}

func TestParseActionParams_InvalidJSON(t *testing.T) {
	action := &pm.Action{}
	// Malformed params now FAIL CLOSED (#368): an error so the dispatch
	// handler retries/dead-letters instead of sending empty params.
	require.Error(t, actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_PACKAGE), []byte("not json")))
	assert.Nil(t, action.Params)
}

func TestParseActionParams_UnknownType(t *testing.T) {
	action := &pm.Action{}
	// An unhandled action type now errors rather than silently no-op'ing (#368).
	require.Error(t, actionparams.PopulateAction(action, 9999, []byte(`{"name":"test"}`)))
	assert.Nil(t, action.Params)
}

func TestParseActionParams_EmptyParams(t *testing.T) {
	action := &pm.Action{}
	require.NoError(t, actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_SHELL), []byte("{}")))

	// Should parse without error, Shell should be set (with empty fields)
	require.NotNil(t, action.GetShell())
}

func TestParseActionParams_AppImage(t *testing.T) {
	action := &pm.Action{}
	params := `{"url":"https://example.com/app.AppImage"}`
	require.NoError(t, actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_APP_IMAGE), []byte(params)))

	require.NotNil(t, action.GetApp())
}

func TestParseActionParams_Deb(t *testing.T) {
	action := &pm.Action{}
	params := `{"url":"https://example.com/app.deb"}`
	require.NoError(t, actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_DEB), []byte(params)))

	require.NotNil(t, action.GetApp())
}

func TestParseActionParams_Rpm(t *testing.T) {
	action := &pm.Action{}
	params := `{"url":"https://example.com/app.rpm"}`
	require.NoError(t, actionparams.PopulateAction(action, int32(pm.ActionType_ACTION_TYPE_RPM), []byte(params)))

	require.NotNil(t, action.GetApp())
}

// TestActionDispatchPayloadRoundtrip verifies that the payload JSON
// correctly round-trips through marshal/unmarshal. Post-rewrite the payload
// carries only the signed envelope bytes + signature (and the correlation
// ExecutionID) — type/desired_state/timeout/params all live INSIDE the
// signed envelope bytes, so they are not separate payload fields.
func TestActionDispatchPayloadRoundtrip(t *testing.T) {
	original := taskqueue.ActionDispatchPayload{
		ExecutionID:   "exec-123",
		EnvelopeBytes: []byte{0x0a, 0x05, 'h', 'e', 'l', 'l', 'o'},
		Signature:     []byte("sig"),
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded taskqueue.ActionDispatchPayload
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.ExecutionID, decoded.ExecutionID)
	assert.Equal(t, original.EnvelopeBytes, decoded.EnvelopeBytes)
	assert.Equal(t, original.Signature, decoded.Signature)
}

// TestOSQueryDispatchPayloadRoundtrip verifies osquery payload round-trips.
func TestOSQueryDispatchPayloadRoundtrip(t *testing.T) {
	original := taskqueue.OSQueryDispatchPayload{
		QueryID: "q-123",
		Table:   "processes",
		Columns: []string{"pid", "name"},
		Limit:   100,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded taskqueue.OSQueryDispatchPayload
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.QueryID, decoded.QueryID)
	assert.Equal(t, original.Table, decoded.Table)
	assert.Equal(t, original.Columns, decoded.Columns)
	assert.Equal(t, original.Limit, decoded.Limit)
}

// TestLogQueryDispatchPayloadRoundtrip verifies log query payload round-trips.
func TestLogQueryDispatchPayloadRoundtrip(t *testing.T) {
	original := taskqueue.LogQueryDispatchPayload{
		QueryID:  "lq-456",
		Lines:    100,
		Unit:     "nginx.service",
		Since:    "2026-01-01",
		Priority: "err",
		Grep:     "error",
		Kernel:   true,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded taskqueue.LogQueryDispatchPayload
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.QueryID, decoded.QueryID)
	assert.Equal(t, original.Lines, decoded.Lines)
	assert.Equal(t, original.Unit, decoded.Unit)
	assert.Equal(t, original.Kernel, decoded.Kernel)
}

type recordingMessageSender struct {
	deviceID string
	messages []*pm.ServerMessage
	err      error
}

func (r *recordingMessageSender) Send(deviceID string, msg *pm.ServerMessage) error {
	if r.err != nil {
		return r.err
	}
	r.deviceID = deviceID
	r.messages = append(r.messages, msg)
	return nil
}

// TestDeviceTaskHandler_ForwardsEnvelopeVerbatim pins the post-rewrite gateway
// contract: the gateway no longer reconstructs a typed Action or re-serialises
// params. It forwards the signed envelope bytes + signature into
// ActionDispatch.{envelope,signature} BYTE-FOR-BYTE. That verbatim forwarding
// is the whole point — the agent verifies the signature over THESE bytes and
// unmarshals THESE bytes, so a gateway re-marshal could never diverge from
// what was signed.
func TestDeviceTaskHandler_ForwardsEnvelopeVerbatim(t *testing.T) {
	// A representative signed envelope's bytes (the gateway treats them as
	// opaque — it does not unmarshal them — so deterministic-marshalling a
	// real envelope here is sufficient).
	env := &pm.SignedActionEnvelope{
		ActionId:       &pm.ActionId{Value: "exec-001"},
		ActionType:     pm.ActionType_ACTION_TYPE_PACKAGE,
		DesiredState:   pm.DesiredState_DESIRED_STATE_PRESENT,
		TimeoutSeconds: 600,
		TargetDeviceId: "device-1",
		Params:         &pm.SignedActionEnvelope_Package{Package: &pm.PackageParams{Name: "htop"}},
	}
	envBytes, err := verify.MarshalEnvelope(env)
	require.NoError(t, err)

	payload := taskqueue.ActionDispatchPayload{
		ExecutionID:   "exec-001",
		EnvelopeBytes: envBytes,
		Signature:     []byte("ca-sig-bytes"),
	}
	data, err := json.Marshal(payload)
	require.NoError(t, err)

	sender := &recordingMessageSender{}
	h := &deviceTaskHandler{
		deviceID: "device-1",
		manager:  sender,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	err = h.handleActionDispatch(context.Background(), asynq.NewTask(taskqueue.TypeActionDispatch, data))
	require.NoError(t, err)

	require.Len(t, sender.messages, 1)
	assert.Equal(t, "device-1", sender.deviceID)
	dispatch := sender.messages[0].GetAction()
	require.NotNil(t, dispatch)
	assert.Equal(t, envBytes, dispatch.GetEnvelope(), "envelope bytes must be forwarded verbatim")
	assert.Equal(t, []byte("ca-sig-bytes"), dispatch.GetSignature(), "signature must be forwarded verbatim")
}

// TestDeviceTaskHandler_RejectsEmptyEnvelope pins the fail-closed guard: a
// dispatch task with no envelope (a producer wiring bug) must error rather
// than hand the agent a message it would reject anyway.
func TestDeviceTaskHandler_RejectsEmptyEnvelope(t *testing.T) {
	payload := taskqueue.ActionDispatchPayload{
		ExecutionID: "exec-002",
		Signature:   []byte("sig"),
		// EnvelopeBytes intentionally empty.
	}
	data, err := json.Marshal(payload)
	require.NoError(t, err)

	sender := &recordingMessageSender{}
	h := &deviceTaskHandler{deviceID: "device-1", manager: sender, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	err = h.handleActionDispatch(context.Background(), asynq.NewTask(taskqueue.TypeActionDispatch, data))
	require.Error(t, err)
	assert.Empty(t, sender.messages, "nothing must be sent to the agent for an empty envelope")
}

// TestDeviceTaskHandler_RejectsEmptySignature pins the symmetric guard for a
// missing signature.
func TestDeviceTaskHandler_RejectsEmptySignature(t *testing.T) {
	payload := taskqueue.ActionDispatchPayload{
		ExecutionID:   "exec-003",
		EnvelopeBytes: []byte{0x0a, 0x01, 'x'},
		// Signature intentionally empty.
	}
	data, err := json.Marshal(payload)
	require.NoError(t, err)

	sender := &recordingMessageSender{}
	h := &deviceTaskHandler{deviceID: "device-1", manager: sender, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	err = h.handleActionDispatch(context.Background(), asynq.NewTask(taskqueue.TypeActionDispatch, data))
	require.Error(t, err)
	assert.Empty(t, sender.messages, "nothing must be sent to the agent for an empty signature")
}

// TestGatewayMux_RejectsUnsignedTask exercises the taskqueue HMAC envelope
// layer (UNCHANGED by this rewrite) end-to-end through the real device mux:
// only a correctly-wrapped task reaches handleActionDispatch; an unsigned, a
// wrong-key, and a byte-tampered task are all rejected by VerifyMiddleware
// BEFORE the handler runs. This is the second, independent signing layer (the
// CA action signature is the other) — the test pins that the mux still gates
// on it and that the gate fails closed.
func TestGatewayMux_RejectsUnsignedTask(t *testing.T) {
	const keyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	const wrongKeyHex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	taskSigner, err := taskqueue.NewSigner(keyHex)
	require.NoError(t, err)
	require.NotNil(t, taskSigner)
	wrongSigner, err := taskqueue.NewSigner(wrongKeyHex)
	require.NoError(t, err)

	// A valid signed envelope so a correctly-wrapped task reaches and passes
	// the inner handler.
	env := &pm.SignedActionEnvelope{
		ActionId:       &pm.ActionId{Value: "exec-hmac"},
		ActionType:     pm.ActionType_ACTION_TYPE_SHELL,
		TargetDeviceId: "device-hmac",
		Params:         &pm.SignedActionEnvelope_Shell{Shell: &pm.ShellParams{Script: "echo ok"}},
	}
	envBytes, err := verify.MarshalEnvelope(env)
	require.NoError(t, err)
	innerPayload, err := json.Marshal(taskqueue.ActionDispatchPayload{
		ExecutionID:   "exec-hmac",
		EnvelopeBytes: envBytes,
		Signature:     []byte("ca-sig"),
	})
	require.NoError(t, err)

	newMux := func(sender messageSender) *asynq.ServeMux {
		f := NewTaskHandlerFactory(nil, taskSigner, slog.New(slog.NewTextHandler(io.Discard, nil)))
		// NewMux wires the same VerifyMiddleware + handler registration as
		// production; we only swap the message sender so we can observe
		// whether the inner handler ran.
		mux := asynq.NewServeMux()
		mux.Use(taskSigner.VerifyMiddleware())
		h := &deviceTaskHandler{deviceID: "device-hmac", manager: sender, logger: f.logger}
		mux.HandleFunc(taskqueue.TypeActionDispatch, h.handleActionDispatch)
		return mux
	}

	// queue context so VerifyMiddleware's queueOf has a name.
	ctxWithQueue := func() context.Context {
		return context.Background()
	}

	t.Run("correctly wrapped task reaches the handler", func(t *testing.T) {
		sender := &recordingMessageSender{}
		mux := newMux(sender)
		wrapped := taskSigner.Wrap(innerPayload)
		err := mux.ProcessTask(ctxWithQueue(), asynq.NewTask(taskqueue.TypeActionDispatch, wrapped))
		require.NoError(t, err)
		require.Len(t, sender.messages, 1, "a correctly HMAC-wrapped task must reach handleActionDispatch")
	})

	t.Run("unsigned task is rejected before the handler", func(t *testing.T) {
		sender := &recordingMessageSender{}
		mux := newMux(sender)
		// Raw inner payload, NOT wrapped — too short / no HMAC prefix.
		err := mux.ProcessTask(ctxWithQueue(), asynq.NewTask(taskqueue.TypeActionDispatch, innerPayload))
		require.Error(t, err)
		assert.Empty(t, sender.messages, "unsigned task must NOT reach the handler")
	})

	t.Run("wrong-key task is rejected before the handler", func(t *testing.T) {
		sender := &recordingMessageSender{}
		mux := newMux(sender)
		wrapped := wrongSigner.Wrap(innerPayload) // HMAC under the wrong key
		err := mux.ProcessTask(ctxWithQueue(), asynq.NewTask(taskqueue.TypeActionDispatch, wrapped))
		require.Error(t, err)
		assert.Empty(t, sender.messages, "wrong-key task must NOT reach the handler")
	})

	t.Run("byte-tampered task is rejected before the handler", func(t *testing.T) {
		sender := &recordingMessageSender{}
		mux := newMux(sender)
		wrapped := taskSigner.Wrap(innerPayload)
		// Flip a byte in the payload region (after the 32-byte HMAC prefix).
		tampered := append([]byte(nil), wrapped...)
		tampered[len(tampered)-1] ^= 0xff
		err := mux.ProcessTask(ctxWithQueue(), asynq.NewTask(taskqueue.TypeActionDispatch, tampered))
		require.Error(t, err)
		assert.Empty(t, sender.messages, "byte-tampered task must NOT reach the handler")
	})
}
