package taskqueue_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// TestDeviceHelloPayload_WireContract pins the exact JSON the agent and control
// exchange across the Asynq boundary for device hello. The hand-maintained
// payload is a "twin" of the proto Hello message; a renamed/added/dropped json
// tag silently breaks device connect. Pinning the wire shape turns that into a
// loud test failure — and in particular pins that `arch` (proto Hello field 5)
// is deliberately NOT on the wire (the N008 choice documented on the struct):
// adding it would fail this test, forcing a conscious contract update rather
// than silent twin drift.
func TestDeviceHelloPayload_WireContract(t *testing.T) {
	in := taskqueue.DeviceHelloPayload{
		DeviceID:     "01HXAMPLE",
		Hostname:     "host-1",
		AgentVersion: "2026.6.0",
	}

	got, err := json.Marshal(in)
	require.NoError(t, err)
	assert.JSONEq(t, `{"device_id":"01HXAMPLE","hostname":"host-1","agent_version":"2026.6.0"}`, string(got),
		"device-hello wire shape changed — agent↔control contract; update both sides deliberately")

	var back taskqueue.DeviceHelloPayload
	require.NoError(t, json.Unmarshal(got, &back))
	assert.Equal(t, in, back, "device-hello payload must round-trip unchanged")
}

// TestSecurityAlertType_NameContract pins the persisted semantics of
// SecurityAlertPayload.AlertType. The agent sends alert.Type.String() — the
// enum NAME — and control stores that string, so a proto enum RENAME silently
// rewrites what every NEW alert means while old rows keep the old name. This
// pins each name and is self-discovering over the generated enum map, so a new
// enum value can't be added without a maintainer consciously pinning its wire
// name (audit serialization #1 — round-trip tests pinned to the enum maps).
func TestSecurityAlertType_NameContract(t *testing.T) {
	want := map[pm.SecurityAlertType]string{
		pm.SecurityAlertType_SECURITY_ALERT_TYPE_UNSPECIFIED:                 "SECURITY_ALERT_TYPE_UNSPECIFIED",
		pm.SecurityAlertType_SECURITY_ALERT_TYPE_SERVER_REASSIGNMENT_ATTEMPT: "SECURITY_ALERT_TYPE_SERVER_REASSIGNMENT_ATTEMPT",
		pm.SecurityAlertType_SECURITY_ALERT_TYPE_CREDENTIAL_TAMPERING:        "SECURITY_ALERT_TYPE_CREDENTIAL_TAMPERING",
		pm.SecurityAlertType_SECURITY_ALERT_TYPE_INVALID_CERTIFICATE:         "SECURITY_ALERT_TYPE_INVALID_CERTIFICATE",
	}
	for v, name := range want {
		assert.Equalf(t, name, v.String(),
			"SecurityAlertType wire name changed for value %d — a rename rewrites persisted alert semantics; migrate deliberately", int32(v))
	}
	// Self-discovering: every generated enum value must be pinned above, so a
	// new SecurityAlertType can't ship unnoticed by the persisted-name contract.
	require.NotEmpty(t, pm.SecurityAlertType_name)
	for num, name := range pm.SecurityAlertType_name {
		_, pinned := want[pm.SecurityAlertType(num)]
		assert.Truef(t, pinned, "generated SecurityAlertType %d (%q) is not pinned — add it to the AlertType name contract", num, name)
	}
}
