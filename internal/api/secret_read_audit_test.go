package api_test

// Spec 24 (server#494): audit events for secret reads. GetDeviceLpsPasswords
// and GetDeviceLuksKeys return decrypted credential material; every
// successful read must append exactly one LpsPasswordsViewed /
// LuksKeysViewed event (identifiers only — never the secret), and every
// handler-tier rejection (absent device, decrypt failure) must append a
// *ViewDenied event without changing the caller-visible response.
// Interceptor-tier rejections never reach the handler and stay journal-only
// — structurally guaranteed because the appends live inside the handler.

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// seedLpsRotation appends one LpsPasswordRotated event with REAL ciphertext
// (the projector materialises the row the handler will read and decrypt).
func seedLpsRotation(t *testing.T, st *store.Store, enc *crypto.Encryptor, deviceID, actionID, username, plaintext string, rotatedAt time.Time) {
	t.Helper()
	ciphertext, err := enc.EncryptWithContext(plaintext, crypto.SecretAAD(deviceID, actionID, "lps"))
	require.NoError(t, err)
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "lps_password",
		StreamID:   deviceID + ":" + actionID + ":" + username,
		EventType:  "LpsPasswordRotated",
		Data: map[string]any{
			"device_id": deviceID, "action_id": actionID, "username": username,
			"password": ciphertext, "rotated_at": rotatedAt.Format(time.RFC3339Nano),
			"rotation_reason": "scheduled",
		},
		ActorType: "device",
		ActorID:   deviceID,
	}))
}

// seedLuksRotation appends one LuksKeyRotated event with real ciphertext.
func seedLuksRotation(t *testing.T, st *store.Store, enc *crypto.Encryptor, deviceID, actionID, devicePath, plaintext string, rotatedAt time.Time) {
	t.Helper()
	ciphertext, err := enc.EncryptWithContext(plaintext, crypto.SecretAAD(deviceID, actionID, "luks"))
	require.NoError(t, err)
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "luks_key",
		StreamID:   deviceID + ":" + actionID + ":" + devicePath,
		EventType:  "LuksKeyRotated",
		Data: map[string]any{
			"device_id": deviceID, "action_id": actionID, "device_path": devicePath,
			"passphrase": ciphertext, "rotated_at": rotatedAt.Format(time.RFC3339Nano),
			"rotation_reason": "scheduled",
		},
		ActorType: "device",
		ActorID:   deviceID,
	}))
}

// auditEventsOfType returns (count, dataJSON of the last one, actorID) for a
// device-stream event type, straight from the events table — the audit
// ground truth, not a projection.
func auditEventsOfType(t *testing.T, st *store.Store, deviceID, eventType string) (int, string, string) {
	t.Helper()
	rows, err := st.TestingPool().Query(context.Background(),
		`SELECT data::text, actor_id FROM events
		 WHERE stream_type = 'device' AND stream_id = $1 AND event_type = $2
		 ORDER BY sequence_num`, deviceID, eventType)
	require.NoError(t, err)
	defer rows.Close()
	count, data, actor := 0, "", ""
	for rows.Next() {
		count++
		require.NoError(t, rows.Scan(&data, &actor))
	}
	require.NoError(t, rows.Err())
	return count, data, actor
}

func TestGetDeviceLpsPasswords_Success_AppendsOneViewedEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewDeviceHandler(st, enc, slog.Default(), api.NoOpSigner{})

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "lps-view-host")
	actionID := testutil.CreateTestAction(t, st, userID, "LPS Action", int(pm.ActionType_ACTION_TYPE_LPS))

	// Two rotations of the same account → one history row + one current row,
	// so the event must list BOTH identifiers.
	base := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	seedLpsRotation(t, st, enc, deviceID, actionID, "root", "old-Secret-1", base)
	seedLpsRotation(t, st, enc, deviceID, actionID, "root", "new-Secret-2", base.Add(24*time.Hour))

	resp, err := h.GetDeviceLpsPasswords(testutil.UserContext(userID), connect.NewRequest(
		&pm.GetDeviceLpsPasswordsRequest{DeviceId: deviceID}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Current, 1)
	require.Len(t, resp.Msg.History, 1)

	count, data, actor := auditEventsOfType(t, st, deviceID, "LpsPasswordsViewed")
	assert.Equal(t, 1, count, "exactly ONE viewed event per successful call (spec 24 AC 5)")
	assert.Equal(t, userID, actor, "the viewing operator is the actor")
	assert.Contains(t, data, "root", "the returned username is an identifier in the payload")
	assert.Contains(t, data, deviceID)

	// Never the secret — neither plaintext nor ciphertext, under any key.
	assert.NotContains(t, data, "old-Secret-1")
	assert.NotContains(t, data, "new-Secret-2")
	assert.NotContains(t, data, "enc:", "ciphertext must not ride along in the audit payload")
	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(data), &payload))
	assert.NotContains(t, payload, "password")

	// AC 4: surfaced by ListAuditEvents (and clean there too).
	auditH := api.NewAuditHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	auditResp, err := auditH.ListAuditEvents(testutil.AdminContext(adminID), connect.NewRequest(
		&pm.ListAuditEventsRequest{StreamType: "device"}))
	require.NoError(t, err)
	var saw bool
	for _, e := range auditResp.Msg.Events {
		if e.EventType == "LpsPasswordsViewed" {
			saw = true
			assert.NotContains(t, e.Data, "old-Secret-1")
			assert.NotContains(t, e.Data, "new-Secret-2")
		}
	}
	assert.True(t, saw, "LpsPasswordsViewed must surface via ListAuditEvents")
}

func TestGetDeviceLuksKeys_Success_AppendsOneViewedEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewDeviceHandler(st, enc, slog.Default(), api.NoOpSigner{})

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "luks-view-host")
	actionID := testutil.CreateTestAction(t, st, userID, "LUKS Action", int(pm.ActionType_ACTION_TYPE_ENCRYPTION))

	seedLuksRotation(t, st, enc, deviceID, actionID, "/dev/sda2", "luks-Pass-1", time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC))

	resp, err := h.GetDeviceLuksKeys(testutil.UserContext(userID), connect.NewRequest(
		&pm.GetDeviceLuksKeysRequest{DeviceId: deviceID}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Current, 1)

	count, data, actor := auditEventsOfType(t, st, deviceID, "LuksKeysViewed")
	assert.Equal(t, 1, count, "exactly ONE viewed event per successful call (spec 24 AC 5)")
	assert.Equal(t, userID, actor)
	assert.Contains(t, data, "/dev/sda2", "the device path is the key identifier")
	assert.NotContains(t, data, "luks-Pass-1")
	assert.NotContains(t, data, "enc:")
	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(data), &payload))
	assert.NotContains(t, payload, "passphrase")
}

func TestGetDeviceLpsPasswords_AbsentDevice_NotFoundAndDeniedEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	ghostID := testutil.NewID()

	_, err := h.GetDeviceLpsPasswords(testutil.UserContext(userID), connect.NewRequest(
		&pm.GetDeviceLpsPasswordsRequest{DeviceId: ghostID}))
	require.Error(t, err, "an absent device must be NotFound, not an empty success")
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "device not found", "uniform NotFound — no existence oracle")

	denied, data, actor := auditEventsOfType(t, st, ghostID, "LpsPasswordsViewDenied")
	assert.Equal(t, 1, denied, "exactly one denied event (spec 24 AC 3)")
	assert.Equal(t, userID, actor)
	assert.Contains(t, data, "device not found")
	viewed, _, _ := auditEventsOfType(t, st, ghostID, "LpsPasswordsViewed")
	assert.Zero(t, viewed, "no view event on a denied read")
}

func TestGetDeviceLuksKeys_AbsentDevice_NotFoundAndDeniedEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	ghostID := testutil.NewID()

	_, err := h.GetDeviceLuksKeys(testutil.UserContext(userID), connect.NewRequest(
		&pm.GetDeviceLuksKeysRequest{DeviceId: ghostID}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	denied, data, actor := auditEventsOfType(t, st, ghostID, "LuksKeysViewDenied")
	assert.Equal(t, 1, denied)
	assert.Equal(t, userID, actor)
	assert.Contains(t, data, "device not found")
	viewed, _, _ := auditEventsOfType(t, st, ghostID, "LuksKeysViewed")
	assert.Zero(t, viewed)
}

func TestGetDeviceLpsPasswords_DecryptFailure_DeniedEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "lps-decfail-host")
	actionID := testutil.CreateTestAction(t, st, userID, "LPS Action", int(pm.ActionType_ACTION_TYPE_LPS))

	// Undecryptable fixture ciphertext (not produced by this encryptor).
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "lps_password",
		StreamID:   deviceID + ":" + actionID + ":root",
		EventType:  "LpsPasswordRotated",
		Data: map[string]any{
			"device_id": deviceID, "action_id": actionID, "username": "root",
			"password": "enc:v1:fixture-undecryptable", "rotated_at": "2026-07-01T10:00:00Z",
			"rotation_reason": "scheduled",
		},
		ActorType: "device",
		ActorID:   deviceID,
	}))

	_, err := h.GetDeviceLpsPasswords(testutil.UserContext(userID), connect.NewRequest(
		&pm.GetDeviceLpsPasswordsRequest{DeviceId: deviceID}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))

	denied, data, actor := auditEventsOfType(t, st, deviceID, "LpsPasswordsViewDenied")
	assert.Equal(t, 1, denied, "decrypt failure appends a denied event (spec 24 AC 3)")
	assert.Equal(t, userID, actor)
	assert.Contains(t, strings.ToLower(data), "decrypt")
	assert.NotContains(t, data, "fixture-undecryptable", "not even broken ciphertext may enter the audit payload")
	viewed, _, _ := auditEventsOfType(t, st, deviceID, "LpsPasswordsViewed")
	assert.Zero(t, viewed, "no view event when nothing was returned")
}

func TestGetDeviceLuksKeys_DecryptFailure_DeniedEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "luks-decfail-host")
	actionID := testutil.CreateTestAction(t, st, userID, "LUKS Action", int(pm.ActionType_ACTION_TYPE_ENCRYPTION))

	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "luks_key",
		StreamID:   deviceID + ":" + actionID + ":/dev/sda2",
		EventType:  "LuksKeyRotated",
		Data: map[string]any{
			"device_id": deviceID, "action_id": actionID, "device_path": "/dev/sda2",
			"passphrase": "enc:v1:fixture-undecryptable", "rotated_at": "2026-07-01T10:00:00Z",
			"rotation_reason": "scheduled",
		},
		ActorType: "device",
		ActorID:   deviceID,
	}))

	_, err := h.GetDeviceLuksKeys(testutil.UserContext(userID), connect.NewRequest(
		&pm.GetDeviceLuksKeysRequest{DeviceId: deviceID}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))

	denied, data, actor := auditEventsOfType(t, st, deviceID, "LuksKeysViewDenied")
	assert.Equal(t, 1, denied)
	assert.Equal(t, userID, actor)
	assert.Contains(t, strings.ToLower(data), "decrypt")
	assert.NotContains(t, data, "fixture-undecryptable", "not even broken ciphertext may enter the audit payload")
	viewed, _, _ := auditEventsOfType(t, st, deviceID, "LuksKeysViewed")
	assert.Zero(t, viewed)
}

// TestSecretReadHandlers_EmptyDeviceStillViewedEvent pins the boundary with
// the EXISTING empty-state behavior: a real device with no rotations is a
// successful (empty) read — it must audit as a VIEW with zero identifiers,
// not as a denial, and must not regress to NotFound.
func TestSecretReadHandlers_EmptyDeviceStillViewedEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "empty-secret-host")

	resp, err := h.GetDeviceLpsPasswords(testutil.UserContext(userID), connect.NewRequest(
		&pm.GetDeviceLpsPasswordsRequest{DeviceId: deviceID}))
	require.NoError(t, err, "an existing device with no rotations stays a successful empty read")
	assert.Empty(t, resp.Msg.Current)

	viewed, _, _ := auditEventsOfType(t, st, deviceID, "LpsPasswordsViewed")
	assert.Equal(t, 1, viewed, "an empty successful read is still a read — audited as a view")
	denied, _, _ := auditEventsOfType(t, st, deviceID, "LpsPasswordsViewDenied")
	assert.Zero(t, denied)
}
