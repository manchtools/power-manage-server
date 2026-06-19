package api_test

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"

	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestCreateLuksToken_PersistsHashNotPlaintext pins WS10 #3: the LUKS
// one-time token is stored hashed. Observable behavior: a consume by the
// raw plaintext token FAILS (no plaintext at rest), while a consume by
// the SHA-256 hash of the returned token SUCCEEDS (the stored value is
// the hash, and the plaintext is returned to the caller only once).
func TestCreateLuksToken_PersistsHashNotPlaintext(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "luks-hash-device")
	actionID := testutil.CreateTestAction(t, st, userID, "Encrypt Disk", int(pm.ActionType_ACTION_TYPE_ENCRYPTION))
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)
	ctx := testutil.UserContext(userID)

	create := func() string {
		resp, err := h.CreateLuksToken(ctx, connect.NewRequest(&pm.CreateLuksTokenRequest{
			DeviceId: deviceID, ActionId: actionID,
		}))
		require.NoError(t, err)
		return resp.Msg.Token
	}

	// Raw plaintext token must NOT consume — it is not what is stored.
	plaintext := create()
	_, err := st.Repos().Luks.ConsumeToken(ctx, store.ConsumeLuksTokenParams{Token: plaintext, DeviceID: deviceID})
	require.Error(t, err, "the plaintext token must not match the at-rest value (it is stored hashed)")

	// The SHA-256 hash of the returned token DOES consume — proving the
	// stored value is the hash.
	plaintext2 := create()
	_, err = st.Repos().Luks.ConsumeToken(ctx, store.ConsumeLuksTokenParams{Token: sha256Hex(plaintext2), DeviceID: deviceID})
	require.NoError(t, err, "the stored value must be the SHA-256 hash of the returned token")

	// And it is one-time: a replay of the same hash fails.
	_, err = st.Repos().Luks.ConsumeToken(ctx, store.ConsumeLuksTokenParams{Token: sha256Hex(plaintext2), DeviceID: deviceID})
	require.Error(t, err, "a consumed token must not be replayable")
}
