package api_test

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
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
				Rotations: []*pm.LpsPasswordRotation{{Username: "alice", SealedPassword: make([]byte, 61), RotatedAt: "2026-06-13T00:00:00Z", Reason: pm.RotationReason_ROTATION_REASON_INITIAL}},
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

	// VerifyDevice is the connection BOOTSTRAP and is intentionally exempt from the
	// binding (enforcing it there deadlocks the device's own connect — see
	// VerifyDevice in internal_handler.go). Prove the exemption is LIVE: with the
	// device live on gw-A, a VerifyDevice claiming gw-B still SUCCEEDS.
	_, verr := h.VerifyDevice(ctx, connect.NewRequest(&pm.VerifyDeviceRequest{DeviceId: device, GatewayId: wrongGateway}))
	require.NoError(t, verr, "VerifyDevice is the pre-attach bootstrap and must NOT enforce the gateway binding")

	// Completeness: EVERY InternalService request carrying a device_id must either
	// have a binding case above OR be a justified exemption — so a new device-origin
	// RPC can't escape the binding by omission, and an exemption can't go stale.
	deviceRPCs := internalRequestsWithDeviceID(t)
	covered := map[string]bool{}
	for _, c := range cases {
		covered[c.name] = true
	}
	for name := range deviceRPCs {
		if bindingExemptInternalRPCs[name] {
			continue
		}
		assert.Truef(t, covered[name],
			"InternalService.%s carries device_id but enforces no binding case here — add a case above or a justified entry to bindingExemptInternalRPCs", name)
	}
	for name := range bindingExemptInternalRPCs {
		assert.Truef(t, deviceRPCs[name],
			"bindingExemptInternalRPCs[%q] is stale — that RPC no longer carries device_id", name)
	}
}

// bindingExemptInternalRPCs are device-origin InternalService methods that
// deliberately do NOT enforce verifyDeviceGatewayBinding. VerifyDevice is the
// connection BOOTSTRAP: the gateway calls it to admit a device's mTLS stream
// BEFORE AttachDevice publishes the device→gateway binding, so enforcing the
// binding there is a chicken-and-egg that rejects every agent (the server#404
// regression). It reads only existence, returns no secret/action, and appends no
// event, so the SA-C2 confinement does not apply; the device's identity is
// already proven by its mTLS client cert.
var bindingExemptInternalRPCs = map[string]bool{
	"VerifyDevice": true,
}

// internalRequestsWithDeviceID returns the set of InternalService method names
// whose request message carries a device_id field — the self-discovering
// completeness anchor for the binding guard.
func internalRequestsWithDeviceID(t *testing.T) map[string]bool {
	t.Helper()
	svc := pm.File_pm_v1_internal_proto.Services().ByName("InternalService")
	require.NotNil(t, svc, "InternalService descriptor must resolve")
	out := map[string]bool{}
	methods := svc.Methods()
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		if m.Input().Fields().ByName("device_id") != nil {
			out[string(m.Name())] = true
		}
	}
	require.NotZero(t, len(out), "matches-zero guard: no InternalService request carries device_id")
	return out
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

// TestProxyGetLuksKey_DeviceScopingAcrossDevices pins WS2 #9 (explicitly
// requested by the work plan): a LUKS key stored for device A must NEVER be
// returned to device B, even when B presents a perfectly valid gateway binding
// of its own. This guards the WHERE device_id scoping in the GetLuksKey query
// independently of the gateway-origin binding — a regression that scoped only by
// action_id would leak A's passphrase to B.
func TestProxyGetLuksKey_DeviceScopingAcrossDevices(t *testing.T) {
	st := testutil.SetupPostgres(t)
	deviceA := testutil.CreateTestDevice(t, st, "luks-scope-a")
	deviceB := testutil.CreateTestDevice(t, st, "luks-scope-b")
	const gwA, gwB = "gw-A", "gw-B"
	h, reg := wiredHandler(t, st, deviceA, gwA)
	require.NoError(t, reg.AttachDevice(context.Background(), deviceB, gwB, registry.DefaultDeviceTTL))
	ctx := context.Background()
	actionID := newULID()

	// Seed a secret for device A via its correctly-bound gateway.
	_, err := h.ProxyStoreLuksKey(ctx, connect.NewRequest(&pm.InternalStoreLuksKeyRequest{
		DeviceId: deviceA, ActionId: actionID, DevicePath: "/dev/sda1", Passphrase: "A-secret",
		RotationReason: pm.RotationReason_ROTATION_REASON_INITIAL, GatewayId: gwA,
	}))
	require.NoError(t, err)

	// Device B — correctly bound to ITS OWN gateway — asks for the SAME action
	// id. It must not receive device A's passphrase: either a not-found error, or
	// (defensively) a response that is anything but A's secret.
	resp, err := h.ProxyGetLuksKey(ctx, connect.NewRequest(&pm.InternalGetLuksKeyRequest{
		DeviceId: deviceB, ActionId: actionID, GatewayId: gwB,
	}))
	if err != nil {
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err),
			"device B has no key for this action id and must be told not-found, not handed another device's key")
	} else {
		assert.NotEqual(t, "A-secret", resp.Msg.Passphrase,
			"device B must NEVER receive device A's LUKS passphrase")
	}
}

// TestProxyValidateLuksToken_ConsumesByHash pins the validate-side at-rest-hash
// contract (WS10): a minted plaintext token validates once (the server hashes it
// before lookup), is single-use (replay → not-found), and a tampered token never
// matches. Create-side hashing is covered elsewhere; this covers the proxy
// validate path, which was previously only tested for missing fields.
func TestProxyValidateLuksToken_ConsumesByHash(t *testing.T) {
	st := testutil.SetupPostgres(t)
	dh := api.NewDeviceHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "luks-validate-host")
	actionID := testutil.CreateTestAction(t, st, userID, "Encrypt Disk", int(pm.ActionType_ACTION_TYPE_ENCRYPTION))
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)
	const gw = "gw-A"
	ih, _ := wiredHandler(t, st, deviceID, gw)
	ctx := context.Background()

	mint := func() string {
		resp, err := dh.CreateLuksToken(testutil.UserContext(userID), connect.NewRequest(&pm.CreateLuksTokenRequest{
			DeviceId: deviceID, ActionId: actionID,
		}))
		require.NoError(t, err)
		require.NotEmpty(t, resp.Msg.Token)
		return resp.Msg.Token
	}

	// Happy: the plaintext validates (server hashes before lookup) and returns
	// the bound action.
	plaintext := mint()
	resp, err := ih.ProxyValidateLuksToken(ctx, connect.NewRequest(&pm.InternalValidateLuksTokenRequest{
		DeviceId: deviceID, Token: plaintext, GatewayId: gw,
	}))
	require.NoError(t, err)
	assert.Equal(t, actionID, resp.Msg.ActionId)

	// Replay: a consumed one-time token is rejected.
	_, err = ih.ProxyValidateLuksToken(ctx, connect.NewRequest(&pm.InternalValidateLuksTokenRequest{
		DeviceId: deviceID, Token: plaintext, GatewayId: gw,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "a consumed token must not be replayable")

	// Tampered: a different token never matches the stored hash (mint a fresh
	// valid one first so the rejection is hash-mismatch, not an empty store).
	tampered := mint() + "tampered"
	_, err = ih.ProxyValidateLuksToken(ctx, connect.NewRequest(&pm.InternalValidateLuksTokenRequest{
		DeviceId: deviceID, Token: tampered, GatewayId: gw,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "a tampered token must not match the at-rest hash")
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
