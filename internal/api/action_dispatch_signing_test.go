package api_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/verify"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// newDispatchTestCA mints a fresh self-signed CA and returns a real
// ca.ActionSigner over its private key plus a verify.ActionVerifier over the
// matching certificate. The dispatch charter tests use the REAL signer +
// verifier so they prove the enqueued envelope is what an agent would accept,
// and that the full-envelope binding rejects field swaps.
func newDispatchTestCA(t *testing.T) (ca.ActionSigner, *verify.ActionVerifier) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Dispatch Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(caKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	c, err := ca.NewFromPEM(certPEM, keyPEM, 24*time.Hour)
	require.NoError(t, err)
	verifier, err := verify.NewActionVerifier(certPEM)
	require.NoError(t, err)
	return ca.NewActionSigner(c), verifier
}

// lastDispatchPayload extracts the most recent ActionDispatch payload the
// recording enqueuer captured. Fails if none / wrong type.
func lastDispatchPayload(t *testing.T, q *api.NoOpEnqueuer) taskqueue.ActionDispatchPayload {
	t.Helper()
	require.NotEmpty(t, q.DeviceCalls, "expected at least one EnqueueToDevice call")
	last := q.DeviceCalls[len(q.DeviceCalls)-1]
	assert.Equal(t, taskqueue.TypeActionDispatch, last.TaskType)
	payload, ok := last.Payload.(taskqueue.ActionDispatchPayload)
	require.True(t, ok, "enqueued payload must be an ActionDispatchPayload, got %T", last.Payload)
	return payload
}

// TestDispatchAction_SignsExecutedEnvelope drives the REAL DispatchAction with
// a REAL CA signer + recording enqueuer and asserts:
//   - the enqueued EnvelopeBytes verify under the matching verifier+signature;
//   - the envelope decodes to the request's executed semantics (desired_state,
//     timeout, params, target device, execution id);
//   - mutating ANY bound field and re-marshalling breaks verification — the
//     full-envelope binding is real (a compromised relay can't rewrite the
//     action under a still-valid signature).
func TestDispatchAction_SignsExecutedEnvelope(t *testing.T) {
	st := testutil.SetupPostgres(t)
	signer, verifier := newDispatchTestCA(t)
	h := api.NewActionHandler(st, slog.Default(), signer)
	queue := &api.NoOpEnqueuer{}
	h.SetTaskQueueClient(queue)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "dispatch-host")

	resp, err := h.DispatchAction(ctx, connect.NewRequest(&pm.DispatchActionRequest{
		DeviceId: deviceID,
		ActionSource: &pm.DispatchActionRequest_InlineAction{
			InlineAction: &pm.Action{
				// Inline Id satisfies request validation (Action.id is
				// validate:"required,ulid"); the handler IGNORES it and mints
				// its own execution id, which is what binds the envelope.
				Id:             &pm.ActionId{Value: testutil.NewID()},
				Type:           pm.ActionType_ACTION_TYPE_SHELL,
				DesiredState:   pm.DesiredState_DESIRED_STATE_ABSENT,
				TimeoutSeconds: 222,
				Params: &pm.Action_Shell{
					Shell: &pm.ShellParams{Script: "echo dispatched", RunAsRoot: true},
				},
			},
		},
	}))
	require.NoError(t, err)
	executionID := resp.Msg.Execution.Id

	payload := lastDispatchPayload(t, queue)
	require.Equal(t, executionID, payload.ExecutionID)
	require.NotEmpty(t, payload.EnvelopeBytes)
	require.NotEmpty(t, payload.Signature)

	// The enqueued envelope verifies under the agent-side verifier over the
	// EXACT transported bytes.
	require.NoError(t, verifier.Verify(payload.EnvelopeBytes, payload.Signature),
		"enqueued envelope must verify under the matching CA verifier")

	// The transported bytes decode to the request's executed semantics.
	var env pm.SignedActionEnvelope
	require.NoError(t, proto.Unmarshal(payload.EnvelopeBytes, &env))
	assert.Equal(t, executionID, env.GetActionId().GetValue())
	assert.Equal(t, deviceID, env.GetTargetDeviceId())
	assert.Equal(t, pm.ActionType_ACTION_TYPE_SHELL, env.GetActionType())
	assert.Equal(t, pm.DesiredState_DESIRED_STATE_ABSENT, env.GetDesiredState())
	assert.Equal(t, int32(222), env.GetTimeoutSeconds())
	require.NotNil(t, env.GetShell())
	assert.Equal(t, "echo dispatched", env.GetShell().Script)
	assert.True(t, env.GetShell().RunAsRoot)

	// Binding proof: flip desired_state and re-marshal — the original
	// signature must reject the tampered bytes.
	env.DesiredState = pm.DesiredState_DESIRED_STATE_PRESENT
	tampered, err := verify.MarshalEnvelope(&env)
	require.NoError(t, err)
	require.Error(t, verifier.Verify(tampered, payload.Signature),
		"mutating desired_state must break verification")
}

// TestDispatchAction_BindsTargetDevice pins that the target device is bound:
// taking a signature legitimately issued for one device and presenting the
// envelope retargeted at another device fails verification — no cross-device
// replay of a captured envelope.
func TestDispatchAction_BindsTargetDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	signer, verifier := newDispatchTestCA(t)
	h := api.NewActionHandler(st, slog.Default(), signer)
	queue := &api.NoOpEnqueuer{}
	h.SetTaskQueueClient(queue)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "device-A")
	_ = testutil.CreateTestDevice(t, st, "device-B")

	_, err := h.DispatchAction(ctx, connect.NewRequest(&pm.DispatchActionRequest{
		DeviceId: deviceID,
		ActionSource: &pm.DispatchActionRequest_InlineAction{
			InlineAction: &pm.Action{
				Id:           &pm.ActionId{Value: testutil.NewID()},
				Type:         pm.ActionType_ACTION_TYPE_SHELL,
				DesiredState: pm.DesiredState_DESIRED_STATE_PRESENT,
				Params:       &pm.Action_Shell{Shell: &pm.ShellParams{Script: "id"}},
			},
		},
	}))
	require.NoError(t, err)

	payload := lastDispatchPayload(t, queue)
	require.NoError(t, verifier.Verify(payload.EnvelopeBytes, payload.Signature))

	var env pm.SignedActionEnvelope
	require.NoError(t, proto.Unmarshal(payload.EnvelopeBytes, &env))
	require.Equal(t, deviceID, env.GetTargetDeviceId())

	env.TargetDeviceId = "device-B"
	retargeted, err := verify.MarshalEnvelope(&env)
	require.NoError(t, err)
	require.Error(t, verifier.Verify(retargeted, payload.Signature),
		"retargeting the device must break verification — no cross-device replay")
}

// TestDispatchInstantAction_SignsEnvelope drives the REAL DispatchInstantAction
// (REBOOT/SYNC) with a REAL signer and asserts the envelope binds the instant
// action type + device, and that lifting the signature onto a DIFFERENT type
// is rejected.
func TestDispatchInstantAction_SignsEnvelope(t *testing.T) {
	st := testutil.SetupPostgres(t)
	signer, verifier := newDispatchTestCA(t)
	h := api.NewActionHandler(st, slog.Default(), signer)
	queue := &api.NoOpEnqueuer{}
	h.SetTaskQueueClient(queue)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "instant-host")

	resp, err := h.DispatchInstantAction(ctx, connect.NewRequest(&pm.DispatchInstantActionRequest{
		DeviceId:      deviceID,
		InstantAction: pm.ActionType_ACTION_TYPE_REBOOT,
	}))
	require.NoError(t, err)
	executionID := resp.Msg.Execution.Id

	payload := lastDispatchPayload(t, queue)
	require.Equal(t, executionID, payload.ExecutionID)
	require.NoError(t, verifier.Verify(payload.EnvelopeBytes, payload.Signature),
		"instant-action envelope must verify under the matching CA verifier")

	var env pm.SignedActionEnvelope
	require.NoError(t, proto.Unmarshal(payload.EnvelopeBytes, &env))
	assert.Equal(t, executionID, env.GetActionId().GetValue())
	assert.Equal(t, deviceID, env.GetTargetDeviceId())
	assert.Equal(t, pm.ActionType_ACTION_TYPE_REBOOT, env.GetActionType())
	// REBOOT carries no params — the oneof must be unset.
	assert.Nil(t, env.GetParams(), "instant actions carry no params")

	// Binding proof: lift the REBOOT signature onto SYNC by mutating the type
	// and re-marshalling. Verification must fail — a compromised relay cannot
	// turn a signed REBOOT into a SYNC (or vice versa).
	env.ActionType = pm.ActionType_ACTION_TYPE_SYNC
	lifted, err := verify.MarshalEnvelope(&env)
	require.NoError(t, err)
	require.Error(t, verifier.Verify(lifted, payload.Signature),
		"lifting the signature onto a different instant type must break verification")
}
