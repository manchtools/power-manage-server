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

// countEventsByTypeForActor counts events of a type attributed to one device.
// LPS and LUKS rotations are appended to their own streams (lps_password /
// luks_key) with a fresh ULID each, NOT to the device stream — so counting the
// device stream returns zero forever and makes any before/after assertion pass
// vacuously. Attribution is via actor_id, which is the device.
func countEventsByTypeForActor(t *testing.T, st *store.Store, eventType, actorID string) int {
	t.Helper()
	var n int
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		`SELECT COUNT(*) FROM events WHERE event_type = $1 AND actor_id = $2`,
		eventType, actorID).Scan(&n))
	return n
}

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

// The seal is gone; the at-rest encryption is not. A stored LUKS passphrase
// must still be readable back through the same device|action AAD, and must NOT
// be readable under any other device or action — which is what makes the
// relocation of a ciphertext row a decryption failure rather than a leak.
func TestAgentOps_StoreLuksKey_AtRestAADSurvivesTheSealRemoval(t *testing.T) {
	ops, st, enc := newAgentOps(t)
	ctx := context.Background()

	deviceID := testutil.CreateTestDevice(t, st, "luks-store-host")
	actionID := testutil.NewID()
	const secret = "a-real-luks-passphrase"

	_, err := ops.StoreLuksKey(ctx, deviceID, &pm.StoreLuksKeyRequest{
		ActionId:       actionID,
		DevicePath:     "/dev/sda3",
		Passphrase:     secret,
		RotationReason: pm.RotationReason_ROTATION_REASON_SCHEDULED,
	})
	require.NoError(t, err)

	// Read it back through the ops path the agent uses.
	got, err := ops.GetLuksKey(ctx, deviceID, &pm.GetLuksKeyRequest{ActionId: actionID})
	require.NoError(t, err)
	assert.Equal(t, secret, got.Passphrase, "plaintext in, same plaintext out")

	// And prove the AAD is really binding: the stored ciphertext must not open
	// under a different action id.
	key, err := st.Repos().Luks.GetCurrentForAction(ctx, store.LuksKeyByActionKey{DeviceID: deviceID, ActionID: actionID})
	require.NoError(t, err)
	_, err = enc.DecryptWithContext(key.Passphrase, crypto.SecretAAD(deviceID, testutil.NewID(), "luks"))
	require.Error(t, err, "a ciphertext relocated to another action must fail to decrypt, not yield the passphrase")
	_, err = enc.DecryptWithContext(key.Passphrase, crypto.SecretAAD(testutil.NewID(), actionID, "luks"))
	require.Error(t, err, "a ciphertext relocated to another device must fail to decrypt")
}

// LPS rotation is irreversible — the agent has already changed the password
// locally. A batch must therefore be all-or-nothing at the staging boundary: a
// bad entry must not leave earlier entries persisted.
func TestAgentOps_StoreLpsPasswords_BadEntryPersistsNothing(t *testing.T) {
	ops, st, _ := newAgentOps(t)
	ctx := context.Background()

	deviceID := testutil.CreateTestDevice(t, st, "lps-batch-host")
	before := countEventsByTypeForActor(t, st, "LpsPasswordRotated", deviceID)

	// An empty batch is refused rather than treated as success — a silent no-op
	// would tell the agent its passwords were saved when nothing was stored.
	// The rejection comes from the contract's own `min=1` on rotations, via the
	// Validate call; an explicit length check here would be an unreachable
	// second guard, so there is deliberately none.
	_, err := ops.StoreLpsPasswords(ctx, deviceID, &pm.StoreLpsPasswordsRequest{ActionId: testutil.NewID()})
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	assert.Equal(t, before, countEventsByTypeForActor(t, st, "LpsPasswordRotated", deviceID),
		"a rejected batch must append nothing")
}

// The happy path: every rotation in the batch lands, encrypted under the lps
// AAD, and an unparseable timestamp does not lose the password.
func TestAgentOps_StoreLpsPasswords_PersistsWholeBatch(t *testing.T) {
	ops, st, _ := newAgentOps(t)
	ctx := context.Background()

	deviceID := testutil.CreateTestDevice(t, st, "lps-ok-host")
	actionID := testutil.NewID()

	_, err := ops.StoreLpsPasswords(ctx, deviceID, &pm.StoreLpsPasswordsRequest{
		ActionId: actionID,
		Rotations: []*pm.LpsPasswordRotation{
			{Username: "alice", Password: "pw-alice", RotatedAt: time.Now().Format(time.RFC3339Nano),
				Reason: pm.RotationReason_ROTATION_REASON_SCHEDULED},
			{Username: "bob", Password: "pw-bob", RotatedAt: "not-a-timestamp",
				Reason: pm.RotationReason_ROTATION_REASON_SCHEDULED},
		},
	})
	require.NoError(t, err, "an unparseable rotated_at must not lose an irreversible rotation")

	assert.Equal(t, 2, countEventsByTypeForActor(t, st, "LpsPasswordRotated", deviceID),
		"both rotations must be persisted")
}

// Orphaned property re-homed: SyncActions signs each delivered action bound to
// the SYNCING device. Signing moved to delivery time when create-time signing
// was dropped, so an unsigned or wrongly-bound envelope is silently useless —
// the offline agent rejects it and the device simply does nothing.
func TestAgentOps_SyncActions_SignsEnvelopesBoundToTheDevice(t *testing.T) {
	ops, st, _ := newAgentOps(t)
	ctx := context.Background()

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "sync-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "sync-me", int(pm.ActionType_ACTION_TYPE_SHELL))
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, 0)

	resp, err := ops.SyncActions(ctx, deviceID)
	require.NoError(t, err)

	all := append([]*pm.Action{}, resp.StandaloneActions...)
	for _, g := range resp.GroupedActions {
		all = append(all, g.Actions...)
	}
	require.NotEmpty(t, all, "the assigned action must reach the device, or this test proves nothing")

	for _, a := range all {
		assert.NotEmpty(t, a.SignedEnvelope, "action %s synced without a signed envelope", a.Id.GetValue())
		assert.NotEmpty(t, a.Signature, "action %s synced without a signature", a.Id.GetValue())
	}
}

// A nil signer must fail loudly rather than sync unsigned actions. Silently
// returning them would look to an operator like "no actions apply".
func TestAgentOps_SyncActions_NilSignerFailsClosed(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ops := api.NewAgentOps(st, testutil.NewEncryptor(t), nil, slog.Default())
	deviceID := testutil.CreateTestDevice(t, st, "unsigned-host")

	_, err := ops.SyncActions(context.Background(), deviceID)
	require.Error(t, err, "a missing signer is a wiring bug and must not degrade to unsigned sync")
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
}

// Spec 41 removed lps_public_key from the sync response. Nothing should try to
// distribute a sealing key that no longer exists in the contract.
func TestAgentOps_SyncActions_CarriesNoLpsPublicKey(t *testing.T) {
	typ := reflect.TypeOf(pm.SyncActionsResponse{})
	_, found := typ.FieldByName("LpsPublicKey")
	assert.False(t, found,
		"SyncActionsResponse still carries LpsPublicKey; the seal it fed was removed with the relay it defended against")
}
