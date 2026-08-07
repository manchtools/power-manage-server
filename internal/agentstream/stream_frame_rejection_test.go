package agentstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/protobuf/encoding/protojson"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/delivery"
	"github.com/manchtools/power-manage/server/internal/execution"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testdb"
)

// CHARTER — one rejected frame must not cost the connection.
//
// The agent's outbox is durable: a frame control refuses is re-sent on every
// reconnect. Ending the stream on an application-level rejection therefore
// turns one bad frame into a permanent reconnect loop, and every other frame
// the agent was about to report is lost with it. Only a claim the device is
// not entitled to make ends the connection.

type fakeSecrets struct{}

func (fakeSecrets) ValidateLuksToken(context.Context, string, *pmv1.ValidateLuksTokenRequest) (*pmv1.ValidateLuksTokenResponse, error) {
	return &pmv1.ValidateLuksTokenResponse{}, nil
}

func (fakeSecrets) GetLuksKey(context.Context, string, *pmv1.GetLuksKeyRequest) (*pmv1.GetLuksKeyResponse, error) {
	return &pmv1.GetLuksKeyResponse{}, nil
}

func (fakeSecrets) StoreLuksKey(context.Context, string, *pmv1.StoreLuksKeyRequest) (*pmv1.StoreLuksKeyResponse, error) {
	return &pmv1.StoreLuksKeyResponse{}, nil
}

func (fakeSecrets) StoreLpsPasswords(context.Context, string, *pmv1.StoreLpsPasswordsRequest) (*pmv1.StoreLpsPasswordsResponse, error) {
	return &pmv1.StoreLpsPasswordsResponse{}, nil
}

type fakeSync struct{}

func (fakeSync) Sync(context.Context, string) (*pmv1.SyncState, error) {
	return &pmv1.SyncState{SyncIntervalMinutes: 30}, nil
}

type fakeWaker struct{}

func (fakeWaker) WakeDevice(context.Context, string) error { return nil }

// seededExecution is one device with one acknowledged delivery holding one
// pending occurrence — the state an agent is in when it reports a result.
type seededExecution struct {
	deviceID   string
	deliveryID string
	occurrence string
	actionID   string
}

func seedExecution(t *testing.T, raw *testdb.DB, at time.Time) seededExecution {
	t.Helper()
	ctx := context.Background()
	seeded := seededExecution{
		deviceID: ulid.Make().String(), deliveryID: ulid.Make().String(),
		occurrence: ulid.Make().String(), actionID: ulid.Make().String(),
	}
	_, err := raw.Exec(ctx, `
		INSERT INTO devices (id, hostname, agent_version, agent_sealing_public_key, registered_at)
		VALUES ($1, $2, 'v1', $3, $4)`,
		seeded.deviceID, "host-"+seeded.deviceID, bytes.Repeat([]byte{1}, 32), at)
	require.NoError(t, err)
	manifest, err := protojson.Marshal(&pmv1.Manifest{
		ManifestId: ulid.Make().String(),
		Occurrences: []*pmv1.ManifestOccurrence{{
			OccurrenceId: seeded.occurrence,
			Action: &pmv1.Action{
				Id: &pmv1.ActionId{Value: seeded.actionID}, Type: pmv1.ActionType_ACTION_TYPE_ENCRYPTION,
			},
		}},
	})
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `
		INSERT INTO deliveries (
			delivery_id, device_id, manifest_id, manifest, state, pushed_at, acked_receipt_at
		) VALUES ($1, $2, $3, $4, $5, $6, $6)`,
		seeded.deliveryID, seeded.deviceID, ulid.Make().String(), manifest, delivery.StateAckedReceipt, at)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `
		INSERT INTO executions (
			id, delivery_id, device_id, action_type, desired_state, params,
			timeout_seconds, status, created_at, created_by_type, created_by_id
		) VALUES ($1, $2, $3, 1, 0, '{}', 300, 'pending', $4, 'user', $5)`,
		seeded.occurrence, seeded.deliveryID, seeded.deviceID, at, ulid.Make().String())
	require.NoError(t, err)
	return seeded
}

// streamFixture is one live AgentService stream over h2c, terminated by the
// real handler with the real execution sink behind it. The fake sink used by
// the routing tests never errors, so it cannot show what an error costs.
type streamFixture struct {
	store   *store.Store
	client  powermanagev1connect.AgentServiceClient
	own     seededExecution
	foreign seededExecution
}

func newStreamFixture(t *testing.T) *streamFixture {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "power-manage.db")
	st, err := store.New(ctx, path)
	require.NoError(t, err)
	t.Cleanup(st.Close)
	raw, err := testdb.Open(ctx, path)
	require.NoError(t, err)
	t.Cleanup(raw.Close)

	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	f := &streamFixture{store: st, own: seedExecution(t, raw, now), foreign: seedExecution(t, raw, now)}

	handler := New(Config{
		Store: st, Manager: connection.NewManager(),
		Deliveries:    &fakeDeliveryState{},
		Executions:    execution.New(execution.Config{Store: st, Now: func() time.Time { return now }}),
		DeviceResults: &fakeDeviceResults{},
		Secrets:       fakeSecrets{}, Sync: fakeSync{}, Waker: fakeWaker{},
		TerminalSessions: connection.NewTerminalSessionRegistry(),
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:              func() time.Time { return now },
	})
	t.Cleanup(handler.Close)

	procedure, connectHandler := powermanagev1connect.NewAgentServiceHandler(handler)
	mux := http.NewServeMux()
	// Stands in for MTLSMiddleware: the transport is already authenticated by
	// the time a frame reaches Stream, so the identity is bound here directly.
	mux.Handle(procedure, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connectHandler.ServeHTTP(w, r.WithContext(WithDeviceID(r.Context(), f.own.deviceID)))
	}))
	server := httptest.NewServer(h2c.NewHandler(mux, &http2.Server{}))
	t.Cleanup(server.Close)

	httpClient := &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	f.client = powermanagev1connect.NewAgentServiceClient(httpClient, server.URL, connect.WithGRPC())
	return f
}

// open completes the handshake and returns a stream ready for result frames.
func (f *streamFixture) open(t *testing.T, ctx context.Context) *connect.BidiStreamForClient[pmv1.AgentMessage, pmv1.ServerMessage] {
	t.Helper()
	stream := f.client.Stream(ctx)
	t.Cleanup(func() { _ = stream.CloseRequest() })
	require.NoError(t, stream.Send(&pmv1.AgentMessage{
		Id: ulid.Make().String(),
		Payload: &pmv1.AgentMessage_Hello{Hello: &pmv1.Hello{
			DeviceId: &pmv1.DeviceId{Value: f.own.deviceID}, AgentVersion: "v1", Hostname: "device",
		}},
	}))
	welcome, err := stream.Receive()
	require.NoError(t, err)
	require.NotNil(t, welcome.GetWelcome())
	return stream
}

// luksResult is the frame the agent's LUKS success path actually produces.
func luksResult(seeded seededExecution, metadata map[string]string) *pmv1.AgentMessage {
	return &pmv1.AgentMessage{
		Id: ulid.Make().String(),
		Payload: &pmv1.AgentMessage_ActionResult{ActionResult: &pmv1.ActionResult{
			ActionId: &pmv1.ActionId{Value: seeded.actionID}, Status: pmv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
			DeliveryId: seeded.deliveryID, OccurrenceId: seeded.occurrence, Changed: true,
			Output:   &pmv1.CommandOutput{Stdout: "LUKS: ownership taken, managed passphrase set\n"},
			Metadata: metadata,
		}},
	}
}

func syncRequest() *pmv1.AgentMessage {
	return &pmv1.AgentMessage{
		Id: ulid.Make().String(), Payload: &pmv1.AgentMessage_SyncRequest{SyncRequest: &pmv1.SyncRequest{}},
	}
}

// A rejected LUKS result is the concrete case: the agent stamps
// luks.device_path onto every setup success and the server refuses any
// non-empty metadata. Before the fix this one frame closed the stream, so the
// result was either lost outright or replayed on every reconnect forever.
func TestStreamSurvivesRejectedActionResult(t *testing.T) {
	f := newStreamFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stream := f.open(t, ctx)

	require.NoError(t, stream.Send(luksResult(f.own, map[string]string{"luks.device_path": "/dev/sda2"})))

	// The connection must still be usable: a request frame sent after the
	// refused one still gets its answer.
	require.NoError(t, stream.Send(syncRequest()))
	response, err := stream.Receive()
	require.NoError(t, err, "a rejected application frame must not end the stream")
	require.NotNil(t, response.GetSyncState())

	// The rejection is real — the result did not land.
	row, err := f.store.GetExecution(ctx, f.own.occurrence)
	require.NoError(t, err)
	assert.Equal(t, "pending", row.Status, "a frame the server refused must not be recorded as applied")
}

// The counterpart: a frame claiming another device's execution is an
// authorization failure, and that still ends the connection.
func TestStreamTerminatesOnCrossDeviceClaim(t *testing.T) {
	f := newStreamFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stream := f.open(t, ctx)

	// No follow-up frame here: the connection is expected to be gone, so a
	// second Send would race the teardown. Receive is the deterministic
	// observation point — it carries the code the handler returned.
	require.NoError(t, stream.Send(luksResult(f.foreign, nil)))

	_, err := stream.Receive()
	require.Error(t, err, "a cross-device claim must end the connection")
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	row, err := f.store.GetExecution(context.Background(), f.foreign.occurrence)
	require.NoError(t, err)
	assert.Equal(t, "pending", row.Status, "another device's execution must be untouched")
}

// And the frame the server does accept still commits, so the two branches
// above distinguish rejection from acceptance, not from a broken sink.
func TestStreamAppliesCleanActionResult(t *testing.T) {
	f := newStreamFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stream := f.open(t, ctx)

	require.NoError(t, stream.Send(luksResult(f.own, nil)))
	require.NoError(t, stream.Send(syncRequest()))
	response, err := stream.Receive()
	require.NoError(t, err)
	require.NotNil(t, response.GetSyncState())

	row, err := f.store.GetExecution(ctx, f.own.occurrence)
	require.NoError(t, err)
	assert.Equal(t, "success", row.Status)
}
