package api_test

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// setActionParams overwrites an action's stored params JSONB directly, so a
// test can plant params that are valid JSON (the column accepts them) but are
// not a decodable EncryptionParams message.
func setActionParams(t *testing.T, st *store.Store, ctx context.Context, actionID string, paramsJSON string) {
	t.Helper()
	_, err := st.TestingPool().Exec(ctx,
		"UPDATE actions_projection SET params = $1::jsonb WHERE id = $2", paramsJSON, actionID)
	require.NoError(t, err)
}

// WS16 #10: CreateLuksToken silently ignored a protojson.Unmarshal error on the
// encryption action's Params, falling back to the floor policy (min 16,
// complexity 0) on a security-gating token. Corrupt params must fail closed.
func TestCreateLuksToken_ParamsUnmarshalFailure_FailsClosed(t *testing.T) {
	t.Run("corrupt params → CodeInternal, no floor fallback", func(t *testing.T) {
		st := testutil.SetupPostgres(t)
		h := api.NewDeviceHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

		userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
		deviceID := testutil.CreateTestDevice(t, st, "luks-corrupt-device")
		actionID := testutil.CreateTestAction(t, st, userID, "Encrypt Disk", int(pm.ActionType_ACTION_TYPE_ENCRYPTION))
		testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)
		ctx := testutil.UserContext(userID)

		// Valid JSON, but not a decodable EncryptionParams message.
		setActionParams(t, st, ctx, actionID, `"this is not an encryption params object"`)

		_, err := h.CreateLuksToken(ctx, connect.NewRequest(&pm.CreateLuksTokenRequest{
			DeviceId: deviceID, ActionId: actionID,
		}))
		require.Error(t, err, "corrupt encryption params must not silently produce a floor-policy token")
		assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
	})

	t.Run("valid params → token carries the configured policy", func(t *testing.T) {
		st := testutil.SetupPostgres(t)
		h := api.NewDeviceHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

		userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
		deviceID := testutil.CreateTestDevice(t, st, "luks-valid-device")
		actionID := testutil.CreateTestAction(t, st, userID, "Encrypt Disk", int(pm.ActionType_ACTION_TYPE_ENCRYPTION))
		testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)
		ctx := testutil.UserContext(userID)

		setActionParams(t, st, ctx, actionID, `{"userPassphraseMinLength":24}`)

		resp, err := h.CreateLuksToken(ctx, connect.NewRequest(&pm.CreateLuksTokenRequest{
			DeviceId: deviceID, ActionId: actionID,
		}))
		require.NoError(t, err)

		tok, err := st.Repos().Luks.ConsumeToken(ctx, store.ConsumeLuksTokenParams{
			Token: sha256Hex(resp.Msg.Token), DeviceID: deviceID,
		})
		require.NoError(t, err)
		assert.Equal(t, int32(24), tok.MinLength, "configured min length must round-trip into the token, not the floor")
	})

	t.Run("empty params → floor policy preserved", func(t *testing.T) {
		st := testutil.SetupPostgres(t)
		h := api.NewDeviceHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})

		userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
		deviceID := testutil.CreateTestDevice(t, st, "luks-floor-device")
		actionID := testutil.CreateTestAction(t, st, userID, "Encrypt Disk", int(pm.ActionType_ACTION_TYPE_ENCRYPTION))
		testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)
		ctx := testutil.UserContext(userID)

		setActionParams(t, st, ctx, actionID, `{}`)

		resp, err := h.CreateLuksToken(ctx, connect.NewRequest(&pm.CreateLuksTokenRequest{
			DeviceId: deviceID, ActionId: actionID,
		}))
		require.NoError(t, err)

		tok, err := st.Repos().Luks.ConsumeToken(ctx, store.ConsumeLuksTokenParams{
			Token: sha256Hex(resp.Msg.Token), DeviceID: deviceID,
		})
		require.NoError(t, err)
		assert.Equal(t, int32(16), tok.MinLength, "empty params keeps the min-16 floor")
	})
}
