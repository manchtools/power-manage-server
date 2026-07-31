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
	"github.com/manchtools/power-manage-sdk/verify"
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

// agentOpsVerifier is the CA verifier paired with the signer newAgentOps
// installs, so a test can check a signature rather than merely its length.
var agentOpsVerifier *verify.ActionVerifier

func newAgentOps(t *testing.T) (*api.AgentOps, *store.Store, *crypto.Encryptor) {
	t.Helper()
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	signer, verifier := newDispatchTestCA(t)
	agentOpsVerifier = verifier
	return api.NewAgentOps(st, enc, signer, slog.Default()), st, enc
}

// Every request-taking AgentOps method must reject a ZERO request before it
// touches the store — the in-process replacement for the InternalService
// boundary sweep that spec 41 deleted.
//
// Driven by reflection rather than a hand-picked list, because a hand-picked
// list is how this regressed: the first version named two methods and left
// StoreLuksKey — a credential-bearing path — unguarded, while reading as though
// the property were covered. A method added later is now covered automatically
// or fails here.
func TestAgentOps_EveryRequestMethodValidatesBeforeStoreWork(t *testing.T) {
	ops, _, _ := newAgentOps(t)
	ctx := context.Background()
	const deviceID = "01J0000000000000000000DEVA"

	typ := reflect.TypeOf(ops)
	protoPkg := reflect.TypeOf(pm.GetLuksKeyRequest{}).PkgPath()

	checked := 0
	for i := 0; i < typ.NumMethod(); i++ {
		m := typ.Method(i)
		if m.Type.NumIn() < 4 {
			continue // (recv, ctx, deviceID, req)
		}
		reqType := m.Type.In(3)
		if reqType.Kind() != reflect.Ptr || reqType.Elem().PkgPath() != protoPkg {
			continue
		}

		t.Run(m.Name, func(t *testing.T) {
			// NOT a zero request. Every method also has an explicit non-empty
			// check, so a zero request is rejected either way and cannot tell
			// whether Validate ran — the first version of this sweep passed with
			// Validate deleted, which is the failure it was written to prevent.
			//
			// Instead: fill every string field with a non-empty value that is
			// invalid for its format tag. The emptiness checks are satisfied, so
			// only the tag-driven validation can reject it.
			req := reflect.New(reqType.Elem())
			fillStringsWithInvalidIDs(req.Elem())
			out := m.Func.Call([]reflect.Value{
				reflect.ValueOf(ops), reflect.ValueOf(ctx), reflect.ValueOf(deviceID), req,
			})
			errVal := out[len(out)-1]
			require.False(t, errVal.IsNil(),
				"%s accepted a request whose ids are malformed — Validate does not run before the store work "+
					"(the explicit non-empty checks cannot catch this shape)", m.Name)
			err, _ := errVal.Interface().(error)
			assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err),
				"%s rejected the zero request, but not as a validation failure", m.Name)
		})
		checked++
	}

	require.Positive(t, checked,
		"no request-taking methods discovered — the reflection walk is broken and this would pass vacuously")
}

// fillStringsWithInvalidIDs sets every exported string field to a non-empty
// value that no `ulid` tag accepts, recursing into nested messages and slices so
// a batch request's elements are covered too.
func fillStringsWithInvalidIDs(v reflect.Value) {
	if v.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if !f.CanSet() {
			continue
		}
		switch f.Kind() {
		case reflect.String:
			f.SetString("not-a-ulid")
		case reflect.Ptr:
			if f.Type().Elem().Kind() == reflect.Struct {
				if f.IsNil() {
					f.Set(reflect.New(f.Type().Elem()))
				}
				fillStringsWithInvalidIDs(f.Elem())
			}
		case reflect.Slice:
			if f.Type().Elem().Kind() == reflect.Ptr && f.Type().Elem().Elem().Kind() == reflect.Struct {
				elem := reflect.New(f.Type().Elem().Elem())
				fillStringsWithInvalidIDs(elem.Elem())
				f.Set(reflect.Append(f, elem))
			}
		}
	}
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

	verifier := agentOpsVerifier
	require.NotNil(t, verifier, "the fixture must expose the CA verifier, or the signature check below is skipped")

	resp, err := ops.SyncActions(ctx, deviceID)
	require.NoError(t, err)

	all := append([]*pm.Action{}, resp.StandaloneActions...)
	for _, g := range resp.GroupedActions {
		all = append(all, g.Actions...)
	}
	require.NotEmpty(t, all, "the assigned action must reach the device, or this test proves nothing")

	for _, a := range all {
		require.NotEmpty(t, a.SignedEnvelope, "action %s synced without a signed envelope", a.Id.GetValue())
		require.NotEmpty(t, a.Signature, "action %s synced without a signature", a.Id.GetValue())

		// Non-empty bytes are not the property. An envelope signed for the wrong
		// device, or with a stale key, is non-empty and useless — the agent
		// verifies before executing, so it silently does nothing and the device
		// looks idle rather than broken. Verify the signature, and verify it is
		// bound to THIS device.
		require.NoError(t, verifier.Verify(a.SignedEnvelope, a.Signature),
			"action %s carries a signature that does not verify against the CA", a.Id.GetValue())
		assert.Contains(t, string(a.SignedEnvelope), deviceID,
			"the signed envelope for action %s is not bound to the syncing device", a.Id.GetValue())
	}

	// Device binding must be exclusive, not incidental: an envelope minted for
	// this device must not verify as one minted for another.
	other := testutil.CreateTestDevice(t, st, "other-sync-host")
	otherResp, err := ops.SyncActions(ctx, other)
	require.NoError(t, err)
	for _, a := range otherResp.StandaloneActions {
		assert.NotContains(t, string(a.SignedEnvelope), deviceID,
			"another device's envelope must not carry this device's id")
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

// A token this server ISSUES must be redeemable through the path that consumes
// it. Nothing tested that round trip: one test asserted the issued token is 64
// characters, another exercised redemption with a fixture token, and no test
// carried a real token from one to the other.
//
// The gap had teeth. `ValidateLuksTokenRequest.Token` was tagged
// `required,uuid` while the issuer mints 32 random bytes as 64 hex characters —
// a token that has never been a UUID. It went unnoticed because the redemption
// path did not run the validator; the moment it did, every legitimate operator
// redemption started failing with InvalidArgument, and only in production,
// because the fixtures were UUIDs.
//
// This drives BOTH production handlers, so the contract cannot drift on either
// side without failing here.
func TestAgentOps_ValidateLuksToken_AcceptsATokenThisServerIssued(t *testing.T) {
	ops, st, enc := newAgentOps(t)
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "luks-roundtrip-host")
	actionID := testutil.CreateTestAction(t, st, userID, "Encrypt Disk", int(pm.ActionType_ACTION_TYPE_ENCRYPTION))
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)

	// Issue through the production handler — never a hand-built token.
	devices := api.NewDeviceHandler(st, enc, slog.Default(), api.NoOpSigner{})
	issued, err := devices.CreateLuksToken(testutil.UserContext(userID), connect.NewRequest(&pm.CreateLuksTokenRequest{
		DeviceId: deviceID,
		ActionId: actionID,
	}))
	require.NoError(t, err)
	require.NotEmpty(t, issued.Msg.Token)

	// Redeem it through the production path the agent uses. DeviceId is set
	// because the SDK client sets it (sdk/client.go ValidateLuksToken) and the
	// request tags it required; the value the server TRUSTS is still the stream
	// argument, not this field.
	got, err := ops.ValidateLuksToken(ctx, deviceID, &pm.ValidateLuksTokenRequest{
		DeviceId: deviceID,
		Token:    issued.Msg.Token,
	})
	require.NoError(t, err,
		"the server refused a token it had just issued — the redemption contract does not match the issued format")
	assert.Equal(t, actionID, got.ActionId, "redemption must resolve to the action the token was minted for")

	// One-time: the second redemption must fail, or a leaked token is reusable.
	_, err = ops.ValidateLuksToken(ctx, deviceID, &pm.ValidateLuksTokenRequest{
		DeviceId: deviceID,
		Token:    issued.Msg.Token,
	})
	require.Error(t, err, "a one-time token must not be redeemable twice")
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

// A database that cannot answer is not a device that does not exist.
//
// Every agent-facing lookup mapped ANY repository error to NotFound. During an
// outage the fleet is told, uniformly and authoritatively, that it has been
// deleted — and NotFound is a terminal answer, so agents stop retrying work
// that would succeed the moment the database returns. The same collapse hid
// context cancellation and driver faults behind a message asserting the row is
// gone.
//
// The uniform-NotFound rule this looked like is about AUTHORIZATION: a row that
// exists but is not yours must be indistinguishable from one that does not
// exist, so there is no existence oracle. It says nothing about infrastructure
// failures, and the scoping that provides it is the deviceID in the query,
// which is unchanged.
//
// Driven through a CLOSED store so the repository returns a real driver error
// rather than a no-rows sentinel — the one distinction under test.
func TestAgentOps_RepositoryFailureIsInternalNotNotFound(t *testing.T) {
	ops, st, _ := newAgentOps(t)
	ctx := context.Background()

	deviceID := testutil.CreateTestDevice(t, st, "outage-host")
	st.Close() // every subsequent query fails with a driver error, not ErrNoRows

	t.Run("VerifyDevice", func(t *testing.T) {
		err := ops.VerifyDevice(ctx, deviceID)
		require.Error(t, err)
		assert.Equal(t, connect.CodeInternal, connect.CodeOf(err),
			"a failed lookup reported as NotFound tells a live device it was decommissioned")
	})

	t.Run("ValidateLuksToken", func(t *testing.T) {
		_, err := ops.ValidateLuksToken(ctx, deviceID, &pm.ValidateLuksTokenRequest{
			DeviceId: deviceID,
			Token:    testutil.NewID(),
		})
		require.Error(t, err)
		assert.Equal(t, connect.CodeInternal, connect.CodeOf(err),
			"an unreachable database must not report a valid token as expired")
	})

	t.Run("GetLuksKey", func(t *testing.T) {
		_, err := ops.GetLuksKey(ctx, deviceID, &pm.GetLuksKeyRequest{ActionId: testutil.NewID()})
		require.Error(t, err)
		assert.Equal(t, connect.CodeInternal, connect.CodeOf(err),
			"an unreachable database must not report an existing LUKS key as absent — the agent would treat the volume as unmanaged")
	})
}
