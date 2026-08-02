package store_test

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/manchtools/power-manage/server/internal/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	sdkcrypto "github.com/manchtools/power-manage-sdk/crypto"
	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/agentsecrets"
	pmcrypto "github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
)

type agentSecretFixture struct {
	t              *testing.T
	store          *store.Store
	raw            *testdb.DB
	service        *agentsecrets.Service
	atRest         *pmcrypto.Encryptor
	controlPrivate *ecdh.PrivateKey
	agentPrivate   *ecdh.PrivateKey
	now            time.Time
	deviceID       string
	luksActionID   string
	lpsActionID    string
}

func newAgentSecretFixture(t *testing.T) *agentSecretFixture {
	t.Helper()
	st, raw := setupSQLite(t)
	controlPrivate, err := sdkcrypto.GenerateX25519()
	require.NoError(t, err)
	agentPrivate, err := sdkcrypto.GenerateX25519()
	require.NoError(t, err)
	atRest, err := pmcrypto.NewEncryptor(strings.Repeat("01", 32))
	require.NoError(t, err)
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	fixture := &agentSecretFixture{
		t: t, store: st, raw: raw, atRest: atRest,
		controlPrivate: controlPrivate, agentPrivate: agentPrivate, now: now,
		deviceID: newID(), luksActionID: newID(), lpsActionID: newID(),
	}
	_, err = raw.Exec(context.Background(), `
		INSERT INTO devices (id, hostname, agent_version, agent_sealing_public_key, registered_at)
		VALUES ($1, 'sealed-device', 'v1', $2, $3)`,
		fixture.deviceID, agentPrivate.PublicKey().Bytes(), now)
	require.NoError(t, err)
	_, err = raw.Exec(context.Background(), `
		INSERT INTO actions (id, name, action_type, params, created_at, updated_at)
		VALUES ($1, 'disk encryption', $3, '{}', $4, $4),
		       ($2, 'local passwords', $5, '{}', $4, $4)`,
		fixture.luksActionID, fixture.lpsActionID,
		int32(pmv1.ActionType_ACTION_TYPE_ENCRYPTION), now,
		int32(pmv1.ActionType_ACTION_TYPE_LPS))
	require.NoError(t, err)
	fixture.service = agentsecrets.New(agentsecrets.Config{
		Store: st, AtRest: atRest, ControlSealingPrivateKey: controlPrivate,
		Now: func() time.Time { return now },
	})
	return fixture
}

func (f *agentSecretFixture) sealToControl(message, field, plaintext string, bindings ...string) *pmv1.SealedValue {
	f.t.Helper()
	aad, info, err := sdkcrypto.FieldSealContext(sdkcrypto.DirectionAgentToControl, message, field, bindings...)
	require.NoError(f.t, err)
	sealed, err := sdkcrypto.SealToPublicKey(f.controlPrivate.PublicKey(), []byte(plaintext), aad, info)
	require.NoError(f.t, err)
	return &pmv1.SealedValue{Version: 1, Ciphertext: sealed}
}

func TestAgentSecrets_LuksFieldsAreSealedInTransitAndEncryptedAtRest(t *testing.T) {
	f := newAgentSecretFixture(t)
	ctx := context.Background()
	passphrase := "correct horse battery staple"
	request := &pmv1.StoreLuksKeyRequest{
		ActionId: f.luksActionID, DevicePath: "/dev/vda3",
		Passphrase: f.sealToControl("powermanage.v1.StoreLuksKeyRequest", "passphrase", passphrase,
			f.deviceID, f.luksActionID),
		RotationReason: pmv1.RotationReason_ROTATION_REASON_INITIAL,
	}
	response, err := f.service.StoreLuksKey(ctx, f.deviceID, request)
	require.NoError(t, err)
	assert.True(t, response.Success)

	row, err := f.store.GetCurrentLuksKeyForAgent(ctx, f.deviceID, f.luksActionID)
	require.NoError(t, err)
	assert.NotEqual(t, passphrase, row.Passphrase)
	assert.True(t, strings.HasPrefix(row.Passphrase, "enc:v1:"))
	openedAtRest, err := f.atRest.DecryptWithContext(row.Passphrase,
		pmcrypto.SecretAAD(f.deviceID, f.luksActionID, "luks"))
	require.NoError(t, err)
	assert.Equal(t, passphrase, openedAtRest)

	got, err := f.service.GetLuksKey(ctx, f.deviceID, &pmv1.GetLuksKeyRequest{ActionId: f.luksActionID})
	require.NoError(t, err)
	aad, info, err := sdkcrypto.FieldSealContext(sdkcrypto.DirectionControlToAgent,
		"powermanage.v1.GetLuksKeyResponse", "passphrase", f.deviceID, f.luksActionID)
	require.NoError(t, err)
	openedForAgent, err := sdkcrypto.OpenWithPrivateKey(f.agentPrivate, got.Passphrase.Ciphertext, aad, info)
	require.NoError(t, err)
	assert.Equal(t, passphrase, string(openedForAgent))
	wrongAgent, err := sdkcrypto.GenerateX25519()
	require.NoError(t, err)
	_, err = sdkcrypto.OpenWithPrivateKey(wrongAgent, got.Passphrase.Ciphertext, aad, info)
	require.Error(t, err)

	otherAction := newID()
	_, err = f.raw.Exec(ctx, `
		INSERT INTO actions (id, name, action_type, params) VALUES ($1, 'other encryption', $2, '{}')`,
		otherAction, int32(pmv1.ActionType_ACTION_TYPE_ENCRYPTION))
	require.NoError(t, err)
	wrongContext := proto.Clone(request).(*pmv1.StoreLuksKeyRequest)
	wrongContext.ActionId = otherAction
	_, err = f.service.StoreLuksKey(ctx, f.deviceID, wrongContext)
	require.Error(t, err, "a field sealed for another action must not open")
	var wrongRows int
	require.NoError(t, f.raw.QueryRow(ctx, `SELECT count(*) FROM luks_keys WHERE action_id = $1`, otherAction).Scan(&wrongRows))
	assert.Zero(t, wrongRows)
}

func TestAgentSecrets_LpsBatchIsAtomicAndUsernameBound(t *testing.T) {
	f := newAgentSecretFixture(t)
	ctx := context.Background()
	rotation := func(username, password string) *pmv1.LpsPasswordRotation {
		return &pmv1.LpsPasswordRotation{
			Username: username,
			Password: f.sealToControl("powermanage.v1.LpsPasswordRotation", "password", password,
				f.deviceID, f.lpsActionID, username),
			RotatedAt: f.now.Format(time.RFC3339Nano),
			Reason:    pmv1.RotationReason_ROTATION_REASON_SCHEDULED,
		}
	}
	request := &pmv1.StoreLpsPasswordsRequest{
		ActionId: f.lpsActionID,
		Rotations: []*pmv1.LpsPasswordRotation{
			rotation("alice", "alice-secret"), rotation("bob", "bob-secret"),
		},
	}
	tampered := proto.Clone(request).(*pmv1.StoreLpsPasswordsRequest)
	badBob := proto.Clone(tampered.Rotations[1]).(*pmv1.LpsPasswordRotation)
	badBob.Password = &pmv1.SealedValue{Version: 1, Ciphertext: append([]byte(nil), badBob.Password.Ciphertext...)}
	badBob.Password.Ciphertext[len(badBob.Password.Ciphertext)-1] ^= 0xff
	tampered.Rotations[1] = badBob
	_, err := f.service.StoreLpsPasswords(ctx, f.deviceID, tampered)
	require.Error(t, err)
	var count int
	require.NoError(t, f.raw.QueryRow(ctx, `SELECT count(*) FROM lps_passwords`).Scan(&count))
	assert.Zero(t, count, "the batch must be prepared before any row is written")

	response, err := f.service.StoreLpsPasswords(ctx, f.deviceID, request)
	require.NoError(t, err)
	assert.True(t, response.Success)
	rows, err := f.raw.Query(ctx, `
		SELECT username, password FROM lps_passwords
		WHERE device_id = $1 AND action_id = $2 AND is_current = TRUE ORDER BY username`,
		f.deviceID, f.lpsActionID)
	require.NoError(t, err)
	defer rows.Close()
	want := map[string]string{"alice": "alice-secret", "bob": "bob-secret"}
	for rows.Next() {
		var username, ciphertext string
		require.NoError(t, rows.Scan(&username, &ciphertext))
		assert.True(t, strings.HasPrefix(ciphertext, "enc:v1:"))
		plaintext, err := f.atRest.DecryptWithContext(ciphertext,
			pmcrypto.SecretAAD(f.deviceID, f.lpsActionID, "lps"))
		require.NoError(t, err)
		assert.Equal(t, want[username], plaintext)
		delete(want, username)
	}
	require.NoError(t, rows.Err())
	assert.Empty(t, want)

	duplicate := &pmv1.StoreLpsPasswordsRequest{
		ActionId: f.lpsActionID,
		Rotations: []*pmv1.LpsPasswordRotation{
			rotation("alice", "one"), rotation("alice", "two"),
		},
	}
	_, err = f.service.StoreLpsPasswords(ctx, f.deviceID, duplicate)
	assert.ErrorIs(t, err, agentsecrets.ErrDuplicateUsername)
}

func TestAgentSecrets_LuksTokenIsDeviceBoundAndConsumedOnce(t *testing.T) {
	f := newAgentSecretFixture(t)
	ctx := context.Background()
	token := newID()
	hash := sha256.Sum256([]byte(token))
	_, err := f.raw.Exec(ctx, `
		INSERT INTO luks_tokens
			(id, device_id, action_id, token, min_length, complexity, created_at, expires_at)
		VALUES ($1, $2, $3, $4, 20, $5, $6, $7)`,
		newID(), f.deviceID, f.luksActionID, hex.EncodeToString(hash[:]),
		int32(pmv1.LpsPasswordComplexity_LPS_PASSWORD_COMPLEXITY_COMPLEX), f.now, f.now.Add(time.Hour))
	require.NoError(t, err)

	wrongDevice := newID()
	_, err = f.service.ValidateLuksToken(ctx, wrongDevice,
		&pmv1.ValidateLuksTokenRequest{Token: token})
	require.Error(t, err)
	var used bool
	require.NoError(t, f.raw.QueryRow(ctx, `SELECT used FROM luks_tokens WHERE token = $1`, hex.EncodeToString(hash[:])).Scan(&used))
	assert.False(t, used)

	response, err := f.service.ValidateLuksToken(ctx, f.deviceID,
		&pmv1.ValidateLuksTokenRequest{Token: token})
	require.NoError(t, err)
	assert.Equal(t, f.luksActionID, response.ActionId)
	assert.Equal(t, int32(20), response.MinLength)
	_, err = f.service.ValidateLuksToken(ctx, f.deviceID,
		&pmv1.ValidateLuksTokenRequest{Token: token})
	require.Error(t, err, "a consumed token must not validate twice")

	var auditContainsSecret bool
	require.NoError(t, f.raw.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM audit_operations ao
			LEFT JOIN audit_effects ae ON ae.operation_id = ao.operation_id
			WHERE concat_ws('|', ao.request_descriptor, ao.authorization_detail,
			                   ae.before_ref, ae.after_ref) LIKE '%' || $1 || '%'
		)`, token).Scan(&auditContainsSecret))
	assert.False(t, auditContainsSecret)
}
