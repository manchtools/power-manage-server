package api_test

import (
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/verify"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// WS4 — every root stream-RPC dispatch is CA-signed at the control server.
//
// Contract restated per surface: DispatchOSQuery / QueryDeviceLogs /
// RefreshDeviceInventory / RevokeLuksDeviceKey must enqueue a payload whose
// Signature verifies — under that surface's OWN domain — over the canonical
// bytes of payload.ToProto() (the exact bytes the gateway relays and the agent
// re-derives). Each test also proves the binding (mutating a field breaks
// verification) and the domain disjointness (the wrong domain rejects), and
// that a nil signer fails the dispatch closed rather than shipping an unsigned
// task. "Wrong" data is sourced from intent (a swapped table/unit/action_id, a
// sibling domain), never from the rule under test.

// lastDeviceCall returns the most recent EnqueueToDevice call of the expected
// task type.
func lastDeviceCall(t *testing.T, q *api.NoOpEnqueuer, taskType string) api.NoOpEnqueuerCall {
	t.Helper()
	require.NotEmpty(t, q.DeviceCalls, "expected at least one EnqueueToDevice call")
	last := q.DeviceCalls[len(q.DeviceCalls)-1]
	require.Equal(t, taskType, last.TaskType)
	return last
}

// payloadAs type-asserts an enqueued payload, failing the test (rather than
// panicking) on a type mismatch.
func payloadAs[T any](t *testing.T, call api.NoOpEnqueuerCall) T {
	t.Helper()
	p, ok := call.Payload.(T)
	require.Truef(t, ok, "payload type %T, want %T", call.Payload, *new(T))
	return p
}

func TestDispatchOSQuery_SignsCanonicalUnderDomain(t *testing.T) {
	st := testutil.SetupPostgres(t)
	signer, verifier := newDispatchTestCA(t)
	h := api.NewOSQueryHandler(st, slog.Default(), signer)
	queue := &api.NoOpEnqueuer{}
	h.SetTaskQueueClient(queue)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "osq-host")

	_, err := h.DispatchOSQuery(ctx, connect.NewRequest(&pm.DispatchOSQueryRequest{
		DeviceId: deviceID,
		Table:    "processes",
		Limit:    25,
	}))
	require.NoError(t, err)

	call := lastDeviceCall(t, queue, taskqueue.TypeOSQueryDispatch)
	payload := payloadAs[taskqueue.OSQueryDispatchPayload](t, call)
	require.NotEmpty(t, payload.Signature, "osquery dispatch must be signed")
	require.Equal(t, deviceID, payload.TargetDeviceID,
		"dispatch must bind the target device inside the signed bytes (PMSEC-001) — an empty target signs a message the agent will reject")

	canonical, err := verify.OSQueryCanonical(payload.ToProto())
	require.NoError(t, err)
	require.NoError(t, verifier.VerifyDomain(verify.OSQuerySignatureDomain, canonical, payload.Signature),
		"enqueued osquery must verify under the osquery domain")

	// Cross-device replay (PMSEC-001): retargeting the signed message to another
	// device must break verification — a compromised gateway cannot replay this
	// device's signed query onto a different served device.
	retargeted := payload.ToProto()
	retargeted.TargetDeviceId = testutil.CreateTestDevice(t, st, "osq-other-host")
	retargetedCanon, err := verify.OSQueryCanonical(retargeted)
	require.NoError(t, err)
	require.Error(t, verifier.VerifyDomain(verify.OSQuerySignatureDomain, retargetedCanon, payload.Signature),
		"retargeting target_device_id must break verification")

	// Domain disjointness: the same bytes/signature must NOT verify under a
	// sibling domain (no cross-surface replay).
	require.Error(t, verifier.VerifyDomain(verify.LogQuerySignatureDomain, canonical, payload.Signature),
		"osquery signature must not verify under the logquery domain")

	// Binding: swap the table and re-derive canonical — verification fails.
	swapped := payload.ToProto()
	swapped.Table = "shadow"
	swappedCanon, err := verify.OSQueryCanonical(swapped)
	require.NoError(t, err)
	require.Error(t, verifier.VerifyDomain(verify.OSQuerySignatureDomain, swappedCanon, payload.Signature),
		"swapping the table must break verification")
}

func TestDispatchOSQuery_SignsRawSQL(t *testing.T) {
	st := testutil.SetupPostgres(t)
	signer, verifier := newDispatchTestCA(t)
	h := api.NewOSQueryHandler(st, slog.Default(), signer)
	queue := &api.NoOpEnqueuer{}
	h.SetTaskQueueClient(queue)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "osq-raw-host")

	// Raw SQL is signed like any other query (decision: sign it uniformly).
	_, err := h.DispatchOSQuery(ctx, connect.NewRequest(&pm.DispatchOSQueryRequest{
		DeviceId: deviceID,
		RawSql:   "SELECT * FROM processes WHERE name = 'sshd'",
	}))
	require.NoError(t, err)

	call := lastDeviceCall(t, queue, taskqueue.TypeOSQueryDispatch)
	payload := payloadAs[taskqueue.OSQueryDispatchPayload](t, call)
	require.Equal(t, "SELECT * FROM processes WHERE name = 'sshd'", payload.RawSQL)
	require.NotEmpty(t, payload.Signature, "raw-SQL osquery dispatch must be signed")

	canonical, err := verify.OSQueryCanonical(payload.ToProto())
	require.NoError(t, err)
	require.NoError(t, verifier.VerifyDomain(verify.OSQuerySignatureDomain, canonical, payload.Signature))

	// The signature binds raw_sql: mutating it breaks verification.
	swapped := payload.ToProto()
	swapped.RawSql = "SELECT * FROM shadow"
	swappedCanon, err := verify.OSQueryCanonical(swapped)
	require.NoError(t, err)
	require.Error(t, verifier.VerifyDomain(verify.OSQuerySignatureDomain, swappedCanon, payload.Signature),
		"swapping raw_sql after signing must break verification")
}

func TestDispatchOSQuery_NilSignerFailsClosed(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewOSQueryHandler(st, slog.Default(), nil) // nil signer = wiring bug
	queue := &api.NoOpEnqueuer{}
	h.SetTaskQueueClient(queue)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "osq-nilsign-host")

	_, err := h.DispatchOSQuery(ctx, connect.NewRequest(&pm.DispatchOSQueryRequest{
		DeviceId: deviceID, Table: "processes",
	}))
	require.Error(t, err, "a nil signer must fail the dispatch closed")
	assert.Empty(t, queue.DeviceCalls, "no task may be enqueued when signing is impossible")
}

func TestQueryDeviceLogs_SignsCanonicalUnderDomain(t *testing.T) {
	st := testutil.SetupPostgres(t)
	signer, verifier := newDispatchTestCA(t)
	h := api.NewLogsHandler(st, slog.Default(), signer)
	queue := &api.NoOpEnqueuer{}
	h.SetTaskQueueClient(queue)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "logs-host")

	_, err := h.QueryDeviceLogs(ctx, connect.NewRequest(&pm.QueryDeviceLogsRequest{
		DeviceId: deviceID,
		Unit:     "nginx.service",
		Lines:    100,
	}))
	require.NoError(t, err)

	call := lastDeviceCall(t, queue, taskqueue.TypeLogQueryDispatch)
	payload := payloadAs[taskqueue.LogQueryDispatchPayload](t, call)
	require.NotEmpty(t, payload.Signature, "log query dispatch must be signed")
	require.Equal(t, deviceID, payload.TargetDeviceID,
		"log query dispatch must bind the target device inside the signed bytes (PMSEC-001)")

	canonical, err := verify.LogQueryCanonical(payload.ToProto())
	require.NoError(t, err)
	require.NoError(t, verifier.VerifyDomain(verify.LogQuerySignatureDomain, canonical, payload.Signature))
	require.Error(t, verifier.VerifyDomain(verify.OSQuerySignatureDomain, canonical, payload.Signature),
		"log query signature must not verify under the osquery domain")

	// Binding: swap the unit — verification fails (no unit retargeting).
	swapped := payload.ToProto()
	swapped.Unit = "ssh.service"
	swappedCanon, err := verify.LogQueryCanonical(swapped)
	require.NoError(t, err)
	require.Error(t, verifier.VerifyDomain(verify.LogQuerySignatureDomain, swappedCanon, payload.Signature),
		"swapping the unit must break verification")
}

func TestRefreshDeviceInventory_SignsCanonicalUnderDomain(t *testing.T) {
	st := testutil.SetupPostgres(t)
	signer, verifier := newDispatchTestCA(t)
	h := api.NewOSQueryHandler(st, slog.Default(), signer)
	queue := &api.NoOpEnqueuer{}
	h.SetTaskQueueClient(queue)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "inv-host")

	_, err := h.RefreshDeviceInventory(ctx, connect.NewRequest(&pm.RefreshDeviceInventoryRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)

	call := lastDeviceCall(t, queue, taskqueue.TypeInventoryRequest)
	payload := payloadAs[taskqueue.InventoryRequestPayload](t, call)
	require.NotEmpty(t, payload.QueryID, "inventory request must carry a query_id to be bindable")
	require.NotEmpty(t, payload.Signature, "inventory request must be signed")
	require.Equal(t, deviceID, payload.TargetDeviceID,
		"inventory request must bind the target device inside the signed bytes (PMSEC-001)")

	canonical, err := verify.RequestInventoryCanonical(payload.ToProto())
	require.NoError(t, err)
	require.NoError(t, verifier.VerifyDomain(verify.InventorySignatureDomain, canonical, payload.Signature))
	require.Error(t, verifier.VerifyDomain(verify.OSQuerySignatureDomain, canonical, payload.Signature),
		"inventory signature must not verify under the osquery domain")

	// Binding: a different query_id must not verify under this signature.
	other := &pm.RequestInventory{QueryId: testutil.NewID()}
	otherCanon, err := verify.RequestInventoryCanonical(other)
	require.NoError(t, err)
	require.Error(t, verifier.VerifyDomain(verify.InventorySignatureDomain, otherCanon, payload.Signature),
		"a different query_id must break verification")
}

func TestRevokeLuksDeviceKey_SignsCanonicalUnderDomain(t *testing.T) {
	st := testutil.SetupPostgres(t)
	signer, verifier := newDispatchTestCA(t)
	h := api.NewDeviceHandler(st, testutil.NewEncryptor(t), slog.Default(), signer)
	queue := &api.NoOpEnqueuer{}
	h.SetTaskQueueClient(queue)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "luks-host")
	actionID := testutil.NewID()

	_, err := h.RevokeLuksDeviceKey(ctx, connect.NewRequest(&pm.RevokeLuksDeviceKeyRequest{
		DeviceId: deviceID,
		ActionId: actionID,
	}))
	require.NoError(t, err)

	call := lastDeviceCall(t, queue, taskqueue.TypeRevokeLuksDeviceKey)
	payload := payloadAs[taskqueue.RevokeLuksDeviceKeyPayload](t, call)
	require.Equal(t, actionID, payload.ActionID)
	require.NotEmpty(t, payload.Signature, "LUKS revoke dispatch must be signed")
	require.Equal(t, deviceID, payload.TargetDeviceID,
		"LUKS revoke must bind the target device inside the signed bytes (PMSEC-001) — the most destructive cross-device replay to close")

	canonical, err := verify.RevokeLuksDeviceKeyCanonical(payload.ToProto())
	require.NoError(t, err)
	require.NoError(t, verifier.VerifyDomain(verify.LuksRevokeSignatureDomain, canonical, payload.Signature))
	require.Error(t, verifier.VerifyDomain(verify.InventorySignatureDomain, canonical, payload.Signature),
		"LUKS revoke signature must not verify under the inventory domain")

	// Binding: a different action_id must not verify (no cross-action replay
	// of a captured revocation signature).
	other := &pm.RevokeLuksDeviceKey{ActionId: testutil.NewID()}
	otherCanon, err := verify.RevokeLuksDeviceKeyCanonical(other)
	require.NoError(t, err)
	require.Error(t, verifier.VerifyDomain(verify.LuksRevokeSignatureDomain, otherCanon, payload.Signature),
		"a different action_id must break verification")
}

// TestStreamDispatch_GatewayRelayRoundTrip proves the sign→relay→verify chain:
// the signature the control server computes over payload.ToProto() still
// verifies when re-derived from the wire message the gateway builds (ToProto
// with the carried signature attached) — i.e. the shared ToProto guarantees the
// agent's re-derived canonical matches the signed bytes, no field-mapping drift.
func TestStreamDispatch_GatewayRelayRoundTrip(t *testing.T) {
	st := testutil.SetupPostgres(t)
	signer, verifier := newDispatchTestCA(t)
	h := api.NewOSQueryHandler(st, slog.Default(), signer)
	queue := &api.NoOpEnqueuer{}
	h.SetTaskQueueClient(queue)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "relay-host")

	_, err := h.DispatchOSQuery(ctx, connect.NewRequest(&pm.DispatchOSQueryRequest{
		DeviceId: deviceID, Table: "users",
	}))
	require.NoError(t, err)
	payload := payloadAs[taskqueue.OSQueryDispatchPayload](t, lastDeviceCall(t, queue, taskqueue.TypeOSQueryDispatch))

	// Gateway relay: build the wire message and attach the carried signature
	// (mirrors handleOSQueryDispatch — gateway never originates).
	wire := payload.ToProto()
	wire.Signature = payload.Signature

	// Agent side: re-derive canonical from the received message, verify.
	agentCanon, err := verify.OSQueryCanonical(wire)
	require.NoError(t, err)
	require.NoError(t, verifier.VerifyDomain(verify.OSQuerySignatureDomain, agentCanon, wire.Signature),
		"the agent's re-derived canonical must verify against the control-signed signature")
}
