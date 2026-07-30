package api_test

import (
	"context"
	"log/slog"
	"reflect"
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

// AgentOps carries the operations that used to live on InternalService. Two
// properties came with them and are pinned here, because both were previously
// supplied by the RPC boundary that spec 41 deleted:
//
//   - validation runs BEFORE any store work (the boundary sweep used to prove
//     this for every InternalService RPC by reflection; an in-process call has
//     no boundary to sweep, so it is asserted directly)
//   - deviceID comes from the authenticated stream, never from a request field,
//     which is what stops one device reading another's secrets

func newAgentOps(t *testing.T) (*api.AgentOps, *store.Store, *crypto.Encryptor) {
	t.Helper()
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	signer, _ := newDispatchTestCA(t)
	return api.NewAgentOps(st, enc, signer, slog.Default()), st, enc
}

// A malformed request must be rejected before the store is touched. The
// credential-bearing paths are exactly where a missing validate lets a
// malformed identifier reach a query.
func TestAgentOps_ValidatesBeforeStoreWork(t *testing.T) {
	ops, _, _ := newAgentOps(t)
	ctx := context.Background()
	const deviceID = "01J0000000000000000000DEVA"

	t.Run("GetLuksKey rejects a non-ULID action id", func(t *testing.T) {
		_, err := ops.GetLuksKey(ctx, deviceID, &pm.GetLuksKeyRequest{ActionId: "not-a-ulid"})
		require.Error(t, err)
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err),
			"a malformed action id must fail validation, not reach the store as a lookup miss")
	})

	t.Run("ValidateLuksToken rejects an empty request", func(t *testing.T) {
		_, err := ops.ValidateLuksToken(ctx, deviceID, &pm.ValidateLuksTokenRequest{})
		require.Error(t, err)
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	})
}

// The cross-device property. A LUKS key is bound by AAD to device+action, so
// asking with a different device id must not yield the other device's
// passphrase — it must fail to find, and would fail to decrypt even if it did.
func TestAgentOps_GetLuksKeyIsScopedToTheStreamDevice(t *testing.T) {
	ops, st, enc := newAgentOps(t)
	ctx := context.Background()

	owner := testutil.CreateTestDevice(t, st, "owner-host")
	other := testutil.CreateTestDevice(t, st, "other-host")
	actionID := testutil.NewID()

	seedLuksRotation(t, st, enc, owner, actionID, "/dev/sda2", "correct-horse-battery", time.Now())

	got, err := ops.GetLuksKey(ctx, owner, &pm.GetLuksKeyRequest{ActionId: actionID})
	require.NoError(t, err, "the owning device must be able to read its own key")
	assert.Equal(t, "correct-horse-battery", got.Passphrase)

	_, err = ops.GetLuksKey(ctx, other, &pm.GetLuksKeyRequest{ActionId: actionID})
	require.Error(t, err, "a different device must not read this key")
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err),
		"a foreign device gets NotFound, never the passphrase and never PermissionDenied")
}

// VerifyDevice is the stream bootstrap: existence only, no secret, no event.
func TestAgentOps_VerifyDevice(t *testing.T) {
	ops, st, _ := newAgentOps(t)
	ctx := context.Background()

	deviceID := testutil.CreateTestDevice(t, st, "verify-host")
	require.NoError(t, ops.VerifyDevice(ctx, deviceID))

	err := ops.VerifyDevice(ctx, "01J0000000000000000000NOPE")
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	require.Error(t, ops.VerifyDevice(ctx, ""), "an empty device id is a caller bug, not a lookup")
}

// Self-discovering guard: every exported AgentOps method that takes a proto
// request must also take a deviceID string ahead of it. A method added later
// that reads the device from its request field would reintroduce exactly the
// cross-tenant hole the signature shape exists to prevent.
func TestAgentOps_EveryRequestTakingMethodTakesDeviceIDSeparately(t *testing.T) {
	typ := reflect.TypeOf(&api.AgentOps{})
	checked := 0
	for i := 0; i < typ.NumMethod(); i++ {
		m := typ.Method(i)
		// (receiver, ctx, ...)
		if m.Type.NumIn() < 3 {
			continue
		}
		var takesProtoReq bool
		for j := 2; j < m.Type.NumIn(); j++ {
			if in := m.Type.In(j); in.Kind() == reflect.Ptr &&
				in.Elem().PkgPath() == reflect.TypeOf(pm.GetLuksKeyRequest{}).PkgPath() {
				takesProtoReq = true
			}
		}
		if !takesProtoReq {
			continue
		}
		checked++
		assert.Equalf(t, reflect.String, m.Type.In(2).Kind(),
			"%s takes a proto request but its first argument after ctx is not the stream's device id; "+
				"reading the device from the request would let one device name another", m.Name)
	}
	require.Positive(t, checked,
		"no request-taking methods discovered — the reflection walk is broken and this would pass vacuously")
}
