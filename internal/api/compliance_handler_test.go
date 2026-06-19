package api_test

// Test coverage for ComplianceHandler.GetDeviceCompliance
// (manchtools/power-manage-server#155 / audit F034 — public RPC
// surface, the highest-priority file in the gap list). Exercises
// the result + summary load + the JSON detection_output decoding +
// the empty-results path.

import (
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func newComplianceHandler(t *testing.T) (*api.ComplianceHandler, *store.Store) {
	t.Helper()
	st := testutil.SetupPostgres(t)
	return api.NewComplianceHandler(st, slog.Default()), st
}

// TestGetDeviceCompliance_RejectsDeviceNotAssignedToCaller pins the #357 fix:
// GetDeviceCompliance returned a device's compliance (including detection
// script stdout/stderr) for ANY device_id, with no ownership/scope check —
// unlike its sibling GetDevice. A stock User holds GetDeviceCompliance:assigned
// (default role), so this was a cross-user disclosure IDOR. The handler must
// resolve the assignment filter (mirroring GetDevice) and refuse a device not
// assigned to the caller.
func TestGetDeviceCompliance_RejectsDeviceNotAssignedToCaller(t *testing.T) {
	h, st := newComplianceHandler(t)
	deviceID := testutil.CreateTestDevice(t, st, "compliance-idor")
	attacker := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	// UserContext holds GetDeviceCompliance:assigned but not the unrestricted
	// permission, so the assignment filter resolves to the caller's id.
	ctx := testutil.UserContext(attacker)

	_, err := h.GetDeviceCompliance(ctx,
		connect.NewRequest(&pm.GetDeviceComplianceRequest{DeviceId: deviceID}))
	require.Error(t, err, "a user must not read compliance for a device not assigned to them")
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestGetDeviceCompliance_NoResults_EmptyChecks(t *testing.T) {
	h, st := newComplianceHandler(t)
	deviceID := testutil.CreateTestDevice(t, st, "compliance-empty")

	resp, err := h.GetDeviceCompliance(testutil.AdminContext(testutil.NewID()),
		connect.NewRequest(&pm.GetDeviceComplianceRequest{DeviceId: deviceID}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.Checks, "device with no compliance results returns empty Checks")
}

func TestGetDeviceCompliance_DeviceWithResults_DecodesDetectionOutput(t *testing.T) {
	h, st := newComplianceHandler(t)
	ctx := testutil.AdminContext(testutil.NewID())

	deviceID := testutil.CreateTestDevice(t, st, "compliance-with-results")
	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, actorID, "ssh-config-check", 200) // ACTION_TYPE_SHELL

	// Seed a ComplianceResultUpdated event so the projector lands a
	// row in compliance_results_projection. Stream type is
	// "compliance"; payload carries device_id + action_id (composite
	// PK) + the detection_output sub-tree the handler unmarshals.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance", StreamID: deviceID + "_" + actionID,
		EventType: "ComplianceResultUpdated",
		Data: map[string]any{
			"device_id":   deviceID,
			"action_id":   actionID,
			"action_name": "ssh-config-check",
			"compliant":   false,
			"detection_output": map[string]any{
				"stdout":    "permit_root_login: yes",
				"stderr":    "",
				"exit_code": 1,
			},
		},
		ActorType: "system", ActorID: "compliance-engine",
	}))

	resp, err := h.GetDeviceCompliance(ctx,
		connect.NewRequest(&pm.GetDeviceComplianceRequest{DeviceId: deviceID}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Checks, 1)

	check := resp.Msg.Checks[0]
	assert.Equal(t, actionID, check.ActionId)
	assert.Equal(t, "ssh-config-check", check.ActionName)
	assert.False(t, check.Compliant)
	require.NotNil(t, check.DetectionOutput, "detection_output JSON must decode into the typed CommandOutput")
	assert.Equal(t, "permit_root_login: yes", check.DetectionOutput.Stdout)
	assert.Equal(t, int32(1), check.DetectionOutput.ExitCode)
}

func TestGetDeviceCompliance_MissingDetectionOutput_NilCommandOutput(t *testing.T) {
	// Replay-safe path: the projector accepts a ComplianceResultUpdated
	// without a detection_output key; the handler's json.Unmarshal
	// short-circuits because the column is empty/null. The check
	// surfaces with DetectionOutput == nil instead of a populated
	// zero-value struct that would falsely look like "ran with empty
	// output".
	h, st := newComplianceHandler(t)
	ctx := testutil.AdminContext(testutil.NewID())

	deviceID := testutil.CreateTestDevice(t, st, "compliance-no-output")
	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, actorID, "no-output-check", 200)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance", StreamID: deviceID + "_" + actionID,
		EventType: "ComplianceResultUpdated",
		Data: map[string]any{
			"device_id":   deviceID,
			"action_id":   actionID,
			"action_name": "no-output-check",
			"compliant":   true,
			// no detection_output
		},
		ActorType: "system", ActorID: "compliance-engine",
	}))

	resp, err := h.GetDeviceCompliance(ctx,
		connect.NewRequest(&pm.GetDeviceComplianceRequest{DeviceId: deviceID}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Checks, 1)
	assert.Nil(t, resp.Msg.Checks[0].DetectionOutput,
		"a missing detection_output column must surface as nil — populating an empty CommandOutput would lie")
}
