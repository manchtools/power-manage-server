package payloads_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
)

// All roundtrip tests assert json.Marshal -> json.Unmarshal preserves
// the struct byte-identically. A field-tag typo on either side fails
// the test loudly: the marshal writes one key, the unmarshal looks for
// another, the assert.Equal catches the missing fields. This guards
// the wire contract that the projector decoder + handler emit site
// share — exactly the regression class PR F was created to prevent.

func ptr[T any](v T) *T { return &v }

func TestRoundtrip_UserCreatedWithRoles(t *testing.T) {
	in := payloads.UserCreatedWithRoles{
		Email:             ptr("a@b.com"),
		PasswordHash:      ptr("hash"),
		Role:              ptr("admin"),
		DisplayName:       ptr("Alice"),
		GivenName:         ptr("Alice"),
		FamilyName:        ptr("Example"),
		PreferredUsername: ptr("alice"),
		Picture:           ptr("https://example.com/a.png"),
		Locale:            ptr("en-US"),
		LinuxUsername:     ptr("alice"),
		LinuxUID:          ptr(int32(1001)),
		RoleIDs:           []string{"role-1", "role-2"},
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserCreatedWithRoles
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out, "must roundtrip cleanly through the events table JSONB")
}

func TestRoundtrip_UserProfileUpdated(t *testing.T) {
	in := payloads.UserProfileUpdated{
		DisplayName:       ptr("Alice"),
		GivenName:         ptr("Alice"),
		FamilyName:        ptr("Example"),
		PreferredUsername: ptr("alice"),
		Picture:           ptr("https://example.com/a.png"),
		Locale:            ptr("en-US"),
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserProfileUpdated
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_UserEmailChanged(t *testing.T) {
	in := payloads.UserEmailChanged{Email: ptr("new@example.com")}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserEmailChanged
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_UserPasswordChanged(t *testing.T) {
	in := payloads.UserPasswordChanged{PasswordHash: ptr("argon2id$...")}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserPasswordChanged
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_UserRoleChanged(t *testing.T) {
	in := payloads.UserRoleChanged{Role: ptr("admin")}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserRoleChanged
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_UserSshKeyAdded(t *testing.T) {
	in := payloads.UserSshKeyAdded{
		KeyID:     ptr("01H..."),
		PublicKey: ptr("ssh-ed25519 AAAA..."),
		Comment:   ptr("alice@laptop"),
		AddedAt:   ptr("2026-05-08T12:00:00Z"),
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserSshKeyAdded
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_UserSshKeyRemoved(t *testing.T) {
	in := payloads.UserSshKeyRemoved{KeyID: ptr("01H...")}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserSshKeyRemoved
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_UserSshSettingsUpdated(t *testing.T) {
	in := payloads.UserSshSettingsUpdated{
		SshAccessEnabled: ptr(true),
		SshAllowPubkey:   ptr(true),
		SshAllowPassword: ptr(false),
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserSshSettingsUpdated
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_UserLinuxUsernameChanged(t *testing.T) {
	in := payloads.UserLinuxUsernameChanged{LinuxUsername: ptr("alice")}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserLinuxUsernameChanged
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_UserSystemActionLinked(t *testing.T) {
	in := payloads.UserSystemActionLinked{
		Field:    ptr("system_user_action_id"),
		ActionID: ptr("01H..."),
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserSystemActionLinked
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_UserProvisioningSettingsUpdated(t *testing.T) {
	in := payloads.UserProvisioningSettingsUpdated{
		UserProvisioningEnabled: ptr(true),
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserProvisioningSettingsUpdated
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_DeviceRegistered(t *testing.T) {
	in := payloads.DeviceRegistered{
		Hostname:            ptr("host-01"),
		AgentVersion:        ptr("2026.06.0"),
		CertFingerprint:     ptr("aabbcc"),
		CertNotAfter:        ptr("2027-05-08T12:00:00Z"),
		RegistrationTokenID: ptr("token-1"),
		Labels:              json.RawMessage(`{"env":"prod"}`),
		AssignedUserID:      ptr("user-1"),
		CertPEM:             ptr("-----BEGIN CERTIFICATE-----..."),
		CACertPEM:           ptr("-----BEGIN CERTIFICATE-----..."),
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.DeviceRegistered
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_DeviceSeen(t *testing.T) {
	in := payloads.DeviceSeen{
		AgentVersion: ptr("2026.06.0"),
		Hostname:     ptr("host-01"),
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.DeviceSeen
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_DeviceHeartbeat(t *testing.T) {
	in := payloads.DeviceHeartbeat{AgentVersion: ptr("2026.06.0")}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.DeviceHeartbeat
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_DeviceCertRenewed(t *testing.T) {
	in := payloads.DeviceCertRenewed{
		CertFingerprint: ptr("aabbcc"),
		CertNotAfter:    ptr("2027-05-08T12:00:00Z"),
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.DeviceCertRenewed
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_DeviceLabelsUpdated(t *testing.T) {
	in := payloads.DeviceLabelsUpdated{Labels: json.RawMessage(`{"env":"prod"}`)}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.DeviceLabelsUpdated
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_DeviceLabelSet(t *testing.T) {
	in := payloads.DeviceLabelSet{Key: ptr("env"), Value: ptr("prod")}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.DeviceLabelSet
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_DeviceLabelRemoved(t *testing.T) {
	in := payloads.DeviceLabelRemoved{Key: ptr("env")}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.DeviceLabelRemoved
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_DeviceUserAssignment(t *testing.T) {
	in := payloads.DeviceUserAssignment{UserID: ptr("user-1")}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.DeviceUserAssignment
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_DeviceGroupAssignment(t *testing.T) {
	in := payloads.DeviceGroupAssignment{GroupID: ptr("group-1")}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.DeviceGroupAssignment
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_DeviceSyncIntervalSet(t *testing.T) {
	in := payloads.DeviceSyncIntervalSet{SyncIntervalMinutes: ptr(int32(15))}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.DeviceSyncIntervalSet
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_ActionCreated(t *testing.T) {
	in := payloads.ActionCreated{
		Name:           "install-nginx",
		Description:    ptr("install nginx package"),
		ActionType:     ptr(int32(1)),
		DesiredState:   ptr(int32(1)),
		Params:         json.RawMessage(`{"package":"nginx"}`),
		TimeoutSeconds: ptr(int32(300)),
		IsSystem:       ptr(false),
		Schedule:       json.RawMessage(`{"cron":"0 0 * * *"}`),
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.ActionCreated
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_ActionRenamed(t *testing.T) {
	in := payloads.ActionRenamed{Name: "install-nginx-v2"}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.ActionRenamed
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_ActionDescriptionUpdated(t *testing.T) {
	in := payloads.ActionDescriptionUpdated{Description: ptr("new description")}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.ActionDescriptionUpdated
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_ActionParamsUpdated(t *testing.T) {
	in := payloads.ActionParamsUpdated{
		Params:         json.RawMessage(`{"package":"nginx","version":"1.24"}`),
		TimeoutSeconds: ptr(int32(600)),
		DesiredState:   ptr(int32(0)),
		Schedule:       json.RawMessage(`{"cron":"0 6 * * *"}`),
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.ActionParamsUpdated
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_AssignmentCreated(t *testing.T) {
	in := payloads.AssignmentCreated{
		SourceType: "action",
		SourceID:   "act-1",
		TargetType: "device",
		TargetID:   "dev-1",
		SortOrder:  ptr(int32(0)),
		Mode:       ptr(int32(1)),
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.AssignmentCreated
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_AssignmentModeChanged(t *testing.T) {
	in := payloads.AssignmentModeChanged{Mode: ptr(int32(2))}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.AssignmentModeChanged
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_AssignmentSortOrderChanged(t *testing.T) {
	in := payloads.AssignmentSortOrderChanged{SortOrder: ptr(int32(7))}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.AssignmentSortOrderChanged
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_ExecutionCreated(t *testing.T) {
	in := payloads.ExecutionCreated{
		DeviceID:       "dev-1",
		ActionID:       ptr("act-1"),
		DefinitionID:   ptr("def-1"),
		ActionType:     ptr(int32(1)),
		DesiredState:   ptr(int32(1)),
		Params:         json.RawMessage(`{"package":"nginx"}`),
		TimeoutSeconds: ptr(int32(300)),
		ExecutedAt:     ptr("2026-05-08T12:00:00Z"),
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.ExecutionCreated
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_ExecutionScheduled(t *testing.T) {
	in := payloads.ExecutionScheduled{
		DeviceID:       "dev-1",
		ActionID:       ptr("act-1"),
		ActionType:     ptr(int32(1)),
		DesiredState:   ptr(int32(1)),
		Params:         json.RawMessage(`{"package":"nginx"}`),
		TimeoutSeconds: ptr(int32(300)),
		ScheduledFor:   "2026-05-09T12:00:00Z",
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.ExecutionScheduled
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_ExecutionTerminal(t *testing.T) {
	in := payloads.ExecutionTerminal{
		CompletedAt:     ptr("2026-05-08T12:00:00Z"),
		Error:           ptr("non-zero exit"),
		Output:          json.RawMessage(`{"stdout":"ok","stderr":"","exit_code":0}`),
		DurationMs:      ptr(int64(1500)),
		Changed:         ptr(true),
		Compliant:       ptr(false),
		DetectionOutput: json.RawMessage(`{"stdout":"compliant","stderr":"","exit_code":0}`),
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.ExecutionTerminal
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_ExecutionTimedOut(t *testing.T) {
	in := payloads.ExecutionTimedOut{
		CompletedAt: ptr("2026-05-08T12:00:00Z"),
		Error:       ptr("timeout"),
		Output:      json.RawMessage(`{"stdout":"","stderr":"killed","exit_code":-1}`),
		DurationMs:  ptr(int64(300000)),
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.ExecutionTimedOut
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_ExecutionReason(t *testing.T) {
	in := payloads.ExecutionReason{Reason: ptr("device offline during scheduled window")}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.ExecutionReason
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_LpsPasswordRotated(t *testing.T) {
	rotated := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	in := payloads.LpsPasswordRotated{
		DeviceID:       "dev-1",
		ActionID:       "act-1",
		Username:       "alice",
		Password:       "ENCRYPTED-CIPHERTEXT",
		RotatedAt:      rotated,
		RotationReason: "scheduled",
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.LpsPasswordRotated
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.True(t, in.RotatedAt.Equal(out.RotatedAt), "RotatedAt must round-trip the same instant")
	// Compare structurally with a normalised time (json round trip
	// drops monotonic clock readings so == fails even when the
	// instant matches).
	in.RotatedAt = out.RotatedAt
	assert.Equal(t, in, out)
}

func TestRoundtrip_LuksKeyRotated(t *testing.T) {
	rotated := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	in := payloads.LuksKeyRotated{
		DeviceID:       "dev-1",
		ActionID:       "act-1",
		DevicePath:     "/dev/sda1",
		Passphrase:     "ENCRYPTED-CIPHERTEXT",
		RotatedAt:      rotated,
		RotationReason: "scheduled",
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.LuksKeyRotated
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.True(t, in.RotatedAt.Equal(out.RotatedAt))
	in.RotatedAt = out.RotatedAt
	assert.Equal(t, in, out)
}

// TestRoundtrip_CommandOutput covers the nested JSONB sub-shape used
// by the terminal-execution payloads. The wire format must exactly
// match the legacy commandOutputToMap output so historical events
// continue to decode through the same key set.
func TestRoundtrip_CommandOutput(t *testing.T) {
	in := payloads.CommandOutput{
		Stdout:   "hello\n",
		Stderr:   "warn: foo\n",
		ExitCode: 0,
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.CommandOutput
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
	// Wire-shape sanity: keys must be EXACTLY the legacy ones so an
	// extra key would break historical decoders (CR catch on PR #192).
	var asMap map[string]any
	require.NoError(t, json.Unmarshal(raw, &asMap))
	assert.Contains(t, asMap, "stdout")
	assert.Contains(t, asMap, "stderr")
	assert.Contains(t, asMap, "exit_code")
	assert.Len(t, asMap, 3, "wire shape must keep the exact legacy key set")
}

// TestRawCommandOutput_NilOmitted locks the contract used by
// ExecutionTerminal / ExecutionTimedOut: a nil *CommandOutput
// produces nil json.RawMessage so the surrounding payload's
// omitempty tag drops the field from the wire entirely.
func TestRawCommandOutput_NilOmitted(t *testing.T) {
	assert.Nil(t, payloads.RawCommandOutput(nil),
		"nil input must return nil so omitempty fires on the parent payload")

	// End-to-end omitempty contract: marshalling the parent payload
	// with nil Output must NOT include the `output` key in the wire
	// JSON. Without this assertion the helper could regress (e.g.
	// to []byte("null")) and we'd only catch it via downstream
	// projector failures (CR catch on PR #192).
	completedAt := time.Date(2026, 5, 9, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	host := payloads.ExecutionTerminal{
		CompletedAt: &completedAt,
		Output:      payloads.RawCommandOutput(nil),
	}
	wire, err := json.Marshal(host)
	require.NoError(t, err)
	var asMap map[string]any
	require.NoError(t, json.Unmarshal(wire, &asMap))
	assert.NotContains(t, asMap, "output", "omitempty contract must omit output when nil")
	assert.NotContains(t, asMap, "detection_output", "omitempty must also drop detection_output when nil")
}

// TestRawCommandOutput_ProducesObject locks that the helper writes
// a JSON object (not a quoted string), and exact legacy wire keys.
// A regression where the helper started emitting a quoted JSON
// string would silently break every consumer of historical
// ExecutionCompleted/ExecutionFailed events.
func TestRawCommandOutput_ProducesObject(t *testing.T) {
	in := &payloads.CommandOutput{
		Stdout:   "out\n",
		Stderr:   "err\n",
		ExitCode: 1,
	}
	raw := payloads.RawCommandOutput(in)
	require.NotNil(t, raw)
	require.Greater(t, len(raw), 0)
	// First byte must be '{', NOT '"' — distinguishes a JSON object
	// from a quoted JSON string.
	assert.Equal(t, byte('{'), raw[0],
		"output must be a JSON object, not a quoted string")

	// Wire keys must be EXACTLY the legacy set — extra keys would
	// break historical decoders (CR catch on PR #192).
	var asMap map[string]any
	require.NoError(t, json.Unmarshal(raw, &asMap))
	assert.Contains(t, asMap, "stdout")
	assert.Contains(t, asMap, "stderr")
	assert.Contains(t, asMap, "exit_code")
	assert.Len(t, asMap, 3, "wire shape must keep the exact legacy key set")

	// Round-trip back through ExecutionTerminal so the test mirrors
	// how the field actually rides on the wire.
	completedAt := time.Date(2026, 5, 9, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	host := payloads.ExecutionTerminal{
		CompletedAt: &completedAt,
		Output:      raw,
	}
	wire, err := json.Marshal(host)
	require.NoError(t, err)
	var decoded payloads.ExecutionTerminal
	require.NoError(t, json.Unmarshal(wire, &decoded))
	assert.JSONEq(t, string(raw), string(decoded.Output))
}

// TestLpsPasswordRotated_LogValueMasksPassword locks the security
// guarantee: routing the payload through slog must NEVER emit the
// raw Password value, even if a future call site does
// `slog.Warn("...", "payload", payload)` directly.
func TestLpsPasswordRotated_LogValueMasksPassword(t *testing.T) {
	const secret = "super-secret-cipher-bytes"
	p := payloads.LpsPasswordRotated{
		DeviceID:       "dev-1",
		ActionID:       "act-1",
		Username:       "alice",
		Password:       secret,
		RotatedAt:      time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC),
		RotationReason: "scheduled",
	}
	// Render the slog.Value into a string and grep for the secret.
	v := p.LogValue()
	rendered := v.String()
	assert.NotContains(t, rendered, secret,
		"LpsPasswordRotated.LogValue() must NOT contain the raw Password value")
	assert.Contains(t, rendered, "[REDACTED]",
		"LpsPasswordRotated.LogValue() must emit the explicit redaction marker")
	// The non-secret context fields must still be present so logs
	// remain actionable.
	assert.Contains(t, rendered, "alice")
	assert.Contains(t, rendered, "scheduled")
}

// TestLuksKeyRotated_LogValueMasksPassphrase — sibling to the LPS
// test for LuksKeyRotated. Same security contract.
func TestLuksKeyRotated_LogValueMasksPassphrase(t *testing.T) {
	const secret = "wXr-luks-passphrase-blob"
	p := payloads.LuksKeyRotated{
		DeviceID:       "dev-1",
		ActionID:       "act-1",
		DevicePath:     "/dev/sda1",
		Passphrase:     secret,
		RotatedAt:      time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC),
		RotationReason: "initial",
	}
	v := p.LogValue()
	rendered := v.String()
	assert.NotContains(t, rendered, secret,
		"LuksKeyRotated.LogValue() must NOT contain the raw Passphrase value")
	assert.Contains(t, rendered, "[REDACTED]",
		"LuksKeyRotated.LogValue() must emit the explicit redaction marker")
	assert.Contains(t, rendered, "/dev/sda1")
}

func TestRoundtrip_LuksDeviceKeyRevocationRequested(t *testing.T) {
	in := payloads.LuksDeviceKeyRevocationRequested{
		DeviceID:    "dev-1",
		ActionID:    "act-1",
		RequestedAt: time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.LuksDeviceKeyRevocationRequested
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_LuksDeviceKeyRevocationFailed(t *testing.T) {
	in := payloads.LuksDeviceKeyRevocationFailed{
		DeviceID: "dev-1",
		ActionID: "act-1",
		Error:    "dispatch enqueue failed: deadline exceeded",
		FailedAt: time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.LuksDeviceKeyRevocationFailed
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_LuksDeviceKeyRevocationDispatched(t *testing.T) {
	in := payloads.LuksDeviceKeyRevocationDispatched{
		DeviceID:     "dev-1",
		ActionID:     "act-1",
		DispatchedAt: time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.LuksDeviceKeyRevocationDispatched
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_RoleCreated(t *testing.T) {
	in := payloads.RoleCreated{
		Name:        "ops",
		Description: "operations team",
		Permissions: []string{"devices:read", "actions:dispatch"},
		IsSystem:    false,
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.RoleCreated
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_RoleUpdated(t *testing.T) {
	in := payloads.RoleUpdated{
		Name:        "ops",
		Description: "operations team (updated)",
		Permissions: []string{"devices:read"},
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.RoleUpdated
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_UserRoleAssigned(t *testing.T) {
	in := payloads.UserRoleAssigned{
		UserID: "user-1",
		RoleID: "role-1",
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserRoleAssigned
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_UserRoleAssigned_WithScope(t *testing.T) {
	// server #7 S2: scoped grants carry both ScopeKind + ScopeID
	// on the wire. The pointers must round-trip identically.
	kind := "device_group"
	id := "01H..."
	in := payloads.UserRoleAssigned{
		UserID:    "user-1",
		RoleID:    "role-1",
		ScopeKind: &kind,
		ScopeID:   &id,
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserRoleAssigned
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
	// Pin that nil pointers round-trip as nil (not zero-value
	// pointer-to-empty-string) so the omitempty contract works.
	assert.Equal(t, "device_group", *out.ScopeKind)
	assert.Equal(t, "01H...", *out.ScopeID)
}

func TestRoundtrip_UserRoleAssigned_LegacyEventWithoutScopeFields(t *testing.T) {
	// Backward-compatibility guard: an event emitted before #7 has
	// no scope_kind / scope_id keys in its JSON. Decoding it must
	// produce nil pointers — NOT empty strings — so the projector
	// classifies it as an unscoped grant.
	raw := []byte(`{"user_id":"u1","role_id":"r1"}`)
	var out payloads.UserRoleAssigned
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, "u1", out.UserID)
	assert.Equal(t, "r1", out.RoleID)
	assert.Nil(t, out.ScopeKind, "legacy events must decode to nil ScopeKind, not a pointer to empty string")
	assert.Nil(t, out.ScopeID)
}

func TestRoundtrip_UserRoleAssigned_NoScope_OmitsKeysOnWire(t *testing.T) {
	// omitempty contract: an unscoped grant must NOT write the
	// scope keys to the wire, so a legacy decoder that doesn't
	// know about scope still sees the historical shape.
	in := payloads.UserRoleAssigned{UserID: "u1", RoleID: "r1"}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var asMap map[string]any
	require.NoError(t, json.Unmarshal(raw, &asMap))
	assert.NotContains(t, asMap, "scope_kind", "unscoped grant must omit scope_kind from the wire JSON")
	assert.NotContains(t, asMap, "scope_id", "unscoped grant must omit scope_id from the wire JSON")
}

func TestRoundtrip_UserRoleRevoked(t *testing.T) {
	in := payloads.UserRoleRevoked{
		UserID: "user-1",
		RoleID: "role-1",
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserRoleRevoked
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_UserRoleRevoked_WithScope(t *testing.T) {
	// server #7 S5 4-tuple revoke grammar.
	kind := "user_group"
	id := "01HXY..."
	in := payloads.UserRoleRevoked{
		UserID:    "user-1",
		RoleID:    "role-1",
		ScopeKind: &kind,
		ScopeID:   &id,
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserRoleRevoked
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_UserGroupCreated(t *testing.T) {
	in := payloads.UserGroupCreated{
		Name:         "ops",
		Description:  "operations",
		IsDynamic:    true,
		DynamicQuery: "(user.email contains \"@example.com\")",
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserGroupCreated
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_UserGroupUpdated(t *testing.T) {
	in := payloads.UserGroupUpdated{Name: "ops", Description: "ops team"}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserGroupUpdated
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_UserGroupMaintenanceWindowSet(t *testing.T) {
	in := payloads.UserGroupMaintenanceWindowSet{
		MaintenanceWindow: map[string]any{
			"schedule": []any{
				map[string]any{"days": []any{"mon", "tue"}, "allow": "always"},
			},
		},
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserGroupMaintenanceWindowSet
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_UserGroupMemberAddedRemoved(t *testing.T) {
	added := payloads.UserGroupMemberAdded{GroupID: "g-1", UserID: "u-1"}
	rawA, err := json.Marshal(added)
	require.NoError(t, err)
	var outA payloads.UserGroupMemberAdded
	require.NoError(t, json.Unmarshal(rawA, &outA))
	assert.Equal(t, added, outA)

	removed := payloads.UserGroupMemberRemoved{GroupID: "g-1", UserID: "u-1"}
	rawR, err := json.Marshal(removed)
	require.NoError(t, err)
	var outR payloads.UserGroupMemberRemoved
	require.NoError(t, json.Unmarshal(rawR, &outR))
	assert.Equal(t, removed, outR)
}

func TestRoundtrip_UserGroupRoleAssignedRevoked(t *testing.T) {
	a := payloads.UserGroupRoleAssigned{GroupID: "g-1", RoleID: "r-1"}
	rawA, err := json.Marshal(a)
	require.NoError(t, err)
	var outA payloads.UserGroupRoleAssigned
	require.NoError(t, json.Unmarshal(rawA, &outA))
	assert.Equal(t, a, outA)

	r := payloads.UserGroupRoleRevoked{GroupID: "g-1", RoleID: "r-1"}
	rawR, err := json.Marshal(r)
	require.NoError(t, err)
	var outR payloads.UserGroupRoleRevoked
	require.NoError(t, json.Unmarshal(rawR, &outR))
	assert.Equal(t, r, outR)
}

func TestRoundtrip_UserGroupRoleAssigned_WithScope(t *testing.T) {
	kind := "device_group"
	id := "01HXY..."
	in := payloads.UserGroupRoleAssigned{
		GroupID:   "g-1",
		RoleID:    "r-1",
		ScopeKind: &kind,
		ScopeID:   &id,
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserGroupRoleAssigned
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_UserGroupRoleAssigned_NoScope_OmitsKeys(t *testing.T) {
	in := payloads.UserGroupRoleAssigned{GroupID: "g-1", RoleID: "r-1"}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var asMap map[string]any
	require.NoError(t, json.Unmarshal(raw, &asMap))
	assert.NotContains(t, asMap, "scope_kind")
	assert.NotContains(t, asMap, "scope_id")
}

func TestRoundtrip_UserGroupRoleAssigned_LegacyEventDecodesAsUnscoped(t *testing.T) {
	raw := []byte(`{"group_id":"g1","role_id":"r1"}`)
	var out payloads.UserGroupRoleAssigned
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, "g1", out.GroupID)
	assert.Equal(t, "r1", out.RoleID)
	assert.Nil(t, out.ScopeKind)
	assert.Nil(t, out.ScopeID)
}

func TestRoundtrip_UserGroupRoleRevoked_WithScope(t *testing.T) {
	kind := "user_group"
	id := "01HXY..."
	in := payloads.UserGroupRoleRevoked{
		GroupID:   "g-1",
		RoleID:    "r-1",
		ScopeKind: &kind,
		ScopeID:   &id,
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserGroupRoleRevoked
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_UserGroupQueryUpdated(t *testing.T) {
	in := payloads.UserGroupQueryUpdated{IsDynamic: false, DynamicQuery: ""}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.UserGroupQueryUpdated
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_DeviceGroupCreated(t *testing.T) {
	in := payloads.DeviceGroupCreated{
		Name:         "prod",
		Description:  "production fleet",
		IsDynamic:    true,
		DynamicQuery: "(device.labels.env equals \"prod\")",
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.DeviceGroupCreated
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_DeviceGroupRenamedDescUpdated(t *testing.T) {
	r := payloads.DeviceGroupRenamed{Name: "prod-2"}
	rawR, err := json.Marshal(r)
	require.NoError(t, err)
	var outR payloads.DeviceGroupRenamed
	require.NoError(t, json.Unmarshal(rawR, &outR))
	assert.Equal(t, r, outR)

	d := payloads.DeviceGroupDescriptionUpdated{Description: "new desc"}
	rawD, err := json.Marshal(d)
	require.NoError(t, err)
	var outD payloads.DeviceGroupDescriptionUpdated
	require.NoError(t, json.Unmarshal(rawD, &outD))
	assert.Equal(t, d, outD)
}

func TestRoundtrip_DeviceGroupMemberAddedRemoved(t *testing.T) {
	a := payloads.DeviceGroupMemberAdded{DeviceID: "dev-1"}
	rawA, err := json.Marshal(a)
	require.NoError(t, err)
	var outA payloads.DeviceGroupMemberAdded
	require.NoError(t, json.Unmarshal(rawA, &outA))
	assert.Equal(t, a, outA)

	r := payloads.DeviceGroupMemberRemoved{DeviceID: "dev-1"}
	rawR, err := json.Marshal(r)
	require.NoError(t, err)
	var outR payloads.DeviceGroupMemberRemoved
	require.NoError(t, json.Unmarshal(rawR, &outR))
	assert.Equal(t, r, outR)
}

func TestRoundtrip_DeviceGroupQueryUpdated(t *testing.T) {
	in := payloads.DeviceGroupQueryUpdated{IsDynamic: true, DynamicQuery: "(true)"}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.DeviceGroupQueryUpdated
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_DeviceGroupSyncIntervalSet(t *testing.T) {
	in := payloads.DeviceGroupSyncIntervalSet{SyncIntervalMinutes: 60}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.DeviceGroupSyncIntervalSet
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

func TestRoundtrip_DeviceGroupMaintenanceWindowSet(t *testing.T) {
	in := payloads.DeviceGroupMaintenanceWindowSet{
		MaintenanceWindow: map[string]any{},
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out payloads.DeviceGroupMaintenanceWindowSet
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}
