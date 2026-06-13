package api_test

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/gateway/registry"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// newID returns a fresh ULID string for test action ids.
func newULID() string { return ulid.Make().String() }

// wiredHandler builds a real InternalHandler with a fake device→gateway
// registry attached as the resolver, and binds deviceID to gatewayID in it.
func wiredHandler(t *testing.T, st *store.Store, deviceID, gatewayID string) (*api.InternalHandler, *registry.Registry) {
	t.Helper()
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})
	reg := registry.New(registry.NewFakeBackend(nil), nil)
	require.NoError(t, reg.AttachDevice(context.Background(), deviceID, gatewayID, registry.DefaultDeviceTTL))
	h.SetDeviceGatewayResolver(reg)
	return h, reg
}

// countEvents returns how many events of the given type exist.
func countEvents(t *testing.T, st *store.Store, eventType string) int {
	t.Helper()
	evs, err := st.Queries().LoadEventsByType(context.Background(), db.LoadEventsByTypeParams{
		EventType: eventType,
		Limit:     1000,
		Offset:    0,
	})
	require.NoError(t, err)
	return len(evs)
}

// TestInternalHandlers_GatewayBindingIsSelfDiscovering pins that EVERY
// InternalService handler whose request carries a device_id rejects a
// gateway_id that does not match the device→gateway binding (server SA-C2 / #403).
// The case table is checked for completeness against the live InternalService
// proto descriptor, so a newly-added credential-bearing RPC that forgets the
// binding fails here rather than silently shipping an unbindable handler.
func TestInternalHandlers_GatewayBindingIsSelfDiscovering(t *testing.T) {
	st := testutil.SetupPostgres(t)
	device := testutil.CreateTestDevice(t, st, "binding-host")
	const liveGateway = "gw-A"
	const wrongGateway = "gw-B"
	h, _ := wiredHandler(t, st, device, liveGateway)
	ctx := context.Background()
	actionID := newULID()

	// Each entry drives the REAL handler with a gateway_id that does NOT match
	// the binding (device is live on gw-A, request claims gw-B).
	cases := []struct {
		name string
		call func() error
	}{
		{"VerifyDevice", func() error {
			_, e := h.VerifyDevice(ctx, connect.NewRequest(&pm.VerifyDeviceRequest{DeviceId: device, GatewayId: wrongGateway}))
			return e
		}},
		{"ProxySyncActions", func() error {
			_, e := h.ProxySyncActions(ctx, connect.NewRequest(&pm.InternalSyncActionsRequest{DeviceId: device, GatewayId: wrongGateway}))
			return e
		}},
		{"ProxyValidateLuksToken", func() error {
			_, e := h.ProxyValidateLuksToken(ctx, connect.NewRequest(&pm.InternalValidateLuksTokenRequest{DeviceId: device, Token: "some-token", GatewayId: wrongGateway}))
			return e
		}},
		{"ProxyGetLuksKey", func() error {
			_, e := h.ProxyGetLuksKey(ctx, connect.NewRequest(&pm.InternalGetLuksKeyRequest{DeviceId: device, ActionId: actionID, GatewayId: wrongGateway}))
			return e
		}},
		{"ProxyStoreLuksKey", func() error {
			_, e := h.ProxyStoreLuksKey(ctx, connect.NewRequest(&pm.InternalStoreLuksKeyRequest{
				DeviceId: device, ActionId: actionID, DevicePath: "/dev/sda1", Passphrase: "secret", RotationReason: pm.RotationReason_ROTATION_REASON_INITIAL, GatewayId: wrongGateway,
			}))
			return e
		}},
		{"ProxyStoreLpsPasswords", func() error {
			_, e := h.ProxyStoreLpsPasswords(ctx, connect.NewRequest(&pm.InternalStoreLpsPasswordsRequest{
				DeviceId: device, ActionId: actionID,
				Rotations: []*pm.LpsPasswordRotation{{Username: "alice", Password: "pw", RotatedAt: "2026-06-13T00:00:00Z", Reason: pm.RotationReason_ROTATION_REASON_INITIAL}},
				GatewayId: wrongGateway,
			}))
			return e
		}},
	}

	for _, c := range cases {
		err := c.call()
		require.Errorf(t, err, "%s must reject a cross-gateway device_id", c.name)
		assert.Equalf(t, connect.CodePermissionDenied, connect.CodeOf(err),
			"%s must reject a gateway binding mismatch with PermissionDenied", c.name)
	}

	// Completeness: the table must cover EXACTLY the InternalService requests
	// that carry a device_id (discovered from the proto descriptor), so a new
	// device-origin RPC can't escape the binding by omission.
	want := internalRequestsWithDeviceID(t)
	assert.Equalf(t, want, len(cases),
		"every InternalService request carrying device_id needs a binding case here (proto descriptor has %d, table has %d)", want, len(cases))
}

// internalRequestsWithDeviceID counts InternalService methods whose request
// message carries a device_id field — the self-discovering completeness anchor.
func internalRequestsWithDeviceID(t *testing.T) int {
	t.Helper()
	svc := pm.File_pm_v1_internal_proto.Services().ByName("InternalService")
	require.NotNil(t, svc, "InternalService descriptor must resolve")
	n := 0
	methods := svc.Methods()
	for i := 0; i < methods.Len(); i++ {
		if methods.Get(i).Input().Fields().ByName("device_id") != nil {
			n++
		}
	}
	require.NotZero(t, n, "matches-zero guard: no InternalService request carries device_id")
	return n
}

// TestProxyGetLuksKey_GatewayBinding covers the LUKS-secret read path across all
// four binding states, proving the secret is never returned to the wrong gateway.
func TestProxyGetLuksKey_GatewayBinding(t *testing.T) {
	st := testutil.SetupPostgres(t)
	device := testutil.CreateTestDevice(t, st, "luks-host")
	const liveGateway = "gw-A"
	h, _ := wiredHandler(t, st, device, liveGateway)
	ctx := context.Background()
	actionID := newULID()

	// Seed a key through the correctly-bound store path.
	_, err := h.ProxyStoreLuksKey(ctx, connect.NewRequest(&pm.InternalStoreLuksKeyRequest{
		DeviceId: device, ActionId: actionID, DevicePath: "/dev/sda1", Passphrase: "topsecret",
		RotationReason: pm.RotationReason_ROTATION_REASON_INITIAL, GatewayId: liveGateway,
	}))
	require.NoError(t, err)

	t.Run("correct gateway returns the passphrase", func(t *testing.T) {
		resp, err := h.ProxyGetLuksKey(ctx, connect.NewRequest(&pm.InternalGetLuksKeyRequest{
			DeviceId: device, ActionId: actionID, GatewayId: liveGateway,
		}))
		require.NoError(t, err)
		assert.Equal(t, "topsecret", resp.Msg.Passphrase)
	})

	t.Run("wrong gateway is rejected and leaks no passphrase", func(t *testing.T) {
		resp, err := h.ProxyGetLuksKey(ctx, connect.NewRequest(&pm.InternalGetLuksKeyRequest{
			DeviceId: device, ActionId: actionID, GatewayId: "gw-B",
		}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
		assert.Nil(t, resp, "no response (and no passphrase) on a binding mismatch")
	})

	t.Run("absent gateway_id is rejected (InvalidArgument)", func(t *testing.T) {
		_, err := h.ProxyGetLuksKey(ctx, connect.NewRequest(&pm.InternalGetLuksKeyRequest{
			DeviceId: device, ActionId: actionID, GatewayId: "",
		}))
		require.Error(t, err)
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	})

	t.Run("device live on no gateway fails closed (FailedPrecondition)", func(t *testing.T) {
		other := testutil.CreateTestDevice(t, st, "unattached-host")
		_, err := h.ProxyGetLuksKey(ctx, connect.NewRequest(&pm.InternalGetLuksKeyRequest{
			DeviceId: other, ActionId: actionID, GatewayId: liveGateway,
		}))
		require.Error(t, err)
		assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err),
			"a device not live on any gateway must fail closed, never allow")
	})
}

// TestProxyStoreLuksKey_NoEventOnGatewayMismatch proves the device-attributed
// LuksKeyRotated event is NEVER appended on a binding mismatch — the forge path.
func TestProxyStoreLuksKey_NoEventOnGatewayMismatch(t *testing.T) {
	st := testutil.SetupPostgres(t)
	device := testutil.CreateTestDevice(t, st, "luks-forge-host")
	h, _ := wiredHandler(t, st, device, "gw-A")
	ctx := context.Background()

	before := countEvents(t, st, "LuksKeyRotated")
	_, err := h.ProxyStoreLuksKey(ctx, connect.NewRequest(&pm.InternalStoreLuksKeyRequest{
		DeviceId: device, ActionId: newULID(), DevicePath: "/dev/sda1", Passphrase: "secret",
		RotationReason: pm.RotationReason_ROTATION_REASON_INITIAL, GatewayId: "gw-B",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	assert.Equal(t, before, countEvents(t, st, "LuksKeyRotated"),
		"a forged-gateway store must NOT append a device-attributed LuksKeyRotated event")
}

// TestInternalHandler_NilResolverBypass pins the documented single-gateway
// exception: with no resolver wired, the binding is not enforced (gateway_id is
// ignored) so non-HA deployments keep working.
func TestInternalHandler_NilResolverBypass(t *testing.T) {
	st := testutil.SetupPostgres(t)
	device := testutil.CreateTestDevice(t, st, "single-gw-host")
	// No SetDeviceGatewayResolver — resolver stays nil.
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	resp, err := h.VerifyDevice(context.Background(), connect.NewRequest(&pm.VerifyDeviceRequest{
		DeviceId: device, GatewayId: "anything-or-empty",
	}))
	require.NoError(t, err, "with no resolver wired, the binding check is bypassed (single-gateway)")
	assert.NotNil(t, resp)
}
