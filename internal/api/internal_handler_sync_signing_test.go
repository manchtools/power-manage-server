package api_test

import (
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/verify"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// CHARTER — sync-path device-bound signing (WS1 SERVER).
//
// Contract under test (ProxySyncActions, served by the gateway's
// SyncActions RPC):
//
//   - Every pm.Action delivered to a syncing device — standalone AND
//     grouped members — MUST carry a signed_envelope + signature pair so
//     the offline agent can verify it before executing. The PUSH/dispatch
//     rewrite stopped create-time signing, so an unsigned sync delivery is
//     a regression the agent rejects.
//   - The envelope is DEVICE-BOUND: its TargetDeviceId is the syncing
//     device. A signature legitimately issued for device A must NOT verify
//     against an envelope retargeted at device B — no cross-device replay
//     of a captured envelope.
//   - The signature covers the EXACT bytes transported (Action.signed_envelope):
//     mutating any bound field and re-marshalling must break verification.
//   - The envelope's executed semantics (desired_state, params, type,
//     timeout, the action id) match the synced action.

// All three charters build the handler with a REAL ca.ActionSigner over a
// fresh test CA (newDispatchTestCA, shared with the dispatch charter) and a
// verify.ActionVerifier over the SAME CA cert — so the test verifies exactly
// what an agent holding that CA cert would verify, end to end.

// TestSyncActions_SignsDeviceBoundEnvelope drives the REAL ProxySyncActions
// with a REAL ca.ActionSigner over a test CA and asserts every returned
// Action (standalone) carries a device-bound, verifiable envelope, that its
// decoded semantics match the synced action, and that tampering rejects.
func TestSyncActions_SignsDeviceBoundEnvelope(t *testing.T) {
	st := testutil.SetupPostgres(t)
	signer, verifier := newDispatchTestCA(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), signer)
	h.SetDeviceGatewayResolver(allLiveResolver{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "sync-sign-host")
	actionID := testutil.CreateTestActionWithDesiredState(t, st, adminID, "Synced Shell",
		int(pm.ActionType_ACTION_TYPE_SHELL), int(pm.DesiredState_DESIRED_STATE_ABSENT))
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID,
		int(pm.AssignmentMode_ASSIGNMENT_MODE_REQUIRED))

	resp, err := h.ProxySyncActions(gwCtx(gwTestCN), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.StandaloneActions, 1)
	a := resp.Msg.StandaloneActions[0]

	// Every delivered action must carry the signed envelope + signature.
	require.NotEmpty(t, a.SignedEnvelope, "synced action must carry signed_envelope")
	require.NotEmpty(t, a.Signature, "synced action must carry a signature")

	// The signature verifies under the SAME-CA verifier over the EXACT
	// transported bytes — this is what the offline agent does.
	require.NoError(t, verifier.Verify(a.SignedEnvelope, a.Signature),
		"synced envelope must verify under the matching CA verifier")

	// The transported bytes decode to device-bound, matching semantics.
	var env pm.SignedActionEnvelope
	require.NoError(t, proto.Unmarshal(a.SignedEnvelope, &env))
	assert.Equal(t, deviceID, env.GetTargetDeviceId(),
		"envelope must be bound to the syncing device")
	assert.Equal(t, actionID, env.GetActionId().GetValue(),
		"synced actions carry their own id as the execution id (agent mints the execution offline)")
	assert.Equal(t, pm.ActionType_ACTION_TYPE_SHELL, env.GetActionType())
	assert.Equal(t, pm.DesiredState_DESIRED_STATE_ABSENT, env.GetDesiredState())

	// Binding proof: flip desired_state and re-marshal — the original
	// signature must reject the tampered bytes.
	env.DesiredState = pm.DesiredState_DESIRED_STATE_PRESENT
	tampered, err := verify.MarshalEnvelope(&env)
	require.NoError(t, err)
	require.Error(t, verifier.Verify(tampered, a.Signature),
		"mutating desired_state must break verification")
}

// TestSyncActions_BindsTargetDevice pins that the device binding is real:
// the envelope synced to device A carries A's id, and retargeting it at a
// different device breaks verification under A's signature — a captured
// envelope cannot be replayed against another device.
func TestSyncActions_BindsTargetDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	signer, verifier := newDispatchTestCA(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), signer)
	h.SetDeviceGatewayResolver(allLiveResolver{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceA := testutil.CreateTestDevice(t, st, "sync-bind-A")
	deviceB := testutil.CreateTestDevice(t, st, "sync-bind-B")
	actionID := testutil.CreateTestAction(t, st, adminID, "Bound Shell", int(pm.ActionType_ACTION_TYPE_SHELL))
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceA,
		int(pm.AssignmentMode_ASSIGNMENT_MODE_REQUIRED))

	resp, err := h.ProxySyncActions(gwCtx(gwTestCN), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: deviceA,
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.StandaloneActions, 1)
	a := resp.Msg.StandaloneActions[0]
	require.NoError(t, verifier.Verify(a.SignedEnvelope, a.Signature))

	var env pm.SignedActionEnvelope
	require.NoError(t, proto.Unmarshal(a.SignedEnvelope, &env))
	require.Equal(t, deviceA, env.GetTargetDeviceId(),
		"envelope synced to device A must be bound to device A")

	// Retarget at device B and re-marshal — A's signature must reject it.
	env.TargetDeviceId = deviceB
	retargeted, err := verify.MarshalEnvelope(&env)
	require.NoError(t, err)
	require.Error(t, verifier.Verify(retargeted, a.Signature),
		"retargeting the envelope at device B must break verification — no cross-device replay")
}

// TestSyncActions_UninstallFoldsIntoSignedEnvelope pins that the container's
// UNINSTALL → ABSENT override rides INSIDE the signed bytes, not just the
// advisory wire field. The agent executes the verified envelope, so an
// override applied only to the advisory pm.Action.DesiredState would be a
// no-op: the agent would re-install something the operator marked for
// removal. Assert the DECODED envelope (the thing the agent executes) is
// ABSENT, and that the advisory field agrees.
func TestSyncActions_UninstallFoldsIntoSignedEnvelope(t *testing.T) {
	st := testutil.SetupPostgres(t)
	signer, verifier := newDispatchTestCA(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), signer)
	h.SetDeviceGatewayResolver(allLiveResolver{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "sync-uninstall-sign-host")
	// Create the action with PRESENT as its stored desired_state so the
	// override is observable: the signed envelope must NOT echo PRESENT.
	actionID := testutil.CreateTestActionWithDesiredState(t, st, adminID, "Doomed Shell",
		int(pm.ActionType_ACTION_TYPE_SHELL), int(pm.DesiredState_DESIRED_STATE_PRESENT))
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID,
		int(pm.AssignmentMode_ASSIGNMENT_MODE_UNINSTALL))

	resp, err := h.ProxySyncActions(gwCtx(gwTestCN), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.StandaloneActions, 1)
	a := resp.Msg.StandaloneActions[0]

	assert.Equal(t, pm.DesiredState_DESIRED_STATE_ABSENT, a.DesiredState,
		"advisory wire field must reflect the UNINSTALL override")
	require.NoError(t, verifier.Verify(a.SignedEnvelope, a.Signature))

	var env pm.SignedActionEnvelope
	require.NoError(t, proto.Unmarshal(a.SignedEnvelope, &env))
	assert.Equal(t, pm.DesiredState_DESIRED_STATE_ABSENT, env.GetDesiredState(),
		"UNINSTALL override must ride in the SIGNED envelope the agent executes, not just the advisory field")
}

// TestSyncActions_SignsGroupedMembers pins that grouped members (action-set
// members ride on grouped_actions, not standalone_actions) are signed
// device-bound too — every Action delivered by the sync path, not just the
// standalone ones, must verify.
func TestSyncActions_SignsGroupedMembers(t *testing.T) {
	st := testutil.SetupPostgres(t)
	signer, verifier := newDispatchTestCA(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), signer)
	h.SetDeviceGatewayResolver(allLiveResolver{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "sync-group-sign-host")
	a1 := testutil.CreateTestAction(t, st, adminID, "Group Member 1", int(pm.ActionType_ACTION_TYPE_SHELL))
	a2 := testutil.CreateTestAction(t, st, adminID, "Group Member 2", int(pm.ActionType_ACTION_TYPE_SHELL))
	setID := testutil.CreateTestActionSet(t, st, adminID, "Signed Set")
	testutil.AddActionToTestSet(t, st, adminID, setID, a1, 0)
	testutil.AddActionToTestSet(t, st, adminID, setID, a2, 1)
	testutil.CreateTestAssignment(t, st, adminID, "action_set", setID, "device", deviceID,
		int(pm.AssignmentMode_ASSIGNMENT_MODE_REQUIRED))

	resp, err := h.ProxySyncActions(gwCtx(gwTestCN), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.GroupedActions, 1)
	g := resp.Msg.GroupedActions[0]
	require.Len(t, g.Actions, 2)

	for _, member := range g.Actions {
		require.NotEmpty(t, member.SignedEnvelope, "grouped member must carry signed_envelope")
		require.NotEmpty(t, member.Signature, "grouped member must carry a signature")
		require.NoError(t, verifier.Verify(member.SignedEnvelope, member.Signature),
			"grouped member envelope must verify under the matching CA verifier")

		var env pm.SignedActionEnvelope
		require.NoError(t, proto.Unmarshal(member.SignedEnvelope, &env))
		assert.Equal(t, deviceID, env.GetTargetDeviceId(),
			"grouped member envelope must be bound to the syncing device")
		assert.Equal(t, member.Id.Value, env.GetActionId().GetValue(),
			"grouped member envelope binds the member's own id")
	}
}
