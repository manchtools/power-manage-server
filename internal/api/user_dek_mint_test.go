package api_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/testutil"
	"log/slog"
)

// TestCreateUser_MintsExactlyOneDEK pins spec 19 AC 1 on the API
// provisioning path: when a user is materialised through CreateUser,
// exactly one user_encryption_keys row exists for their ULID, holding
// a KEK-wrapped DEK in the single at-rest format.
func TestCreateUser_MintsExactlyOneDEK(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	adminID := testutil.CreateTestUser(t, st, "dekadm-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")
	h := api.NewUserHandler(st, slog.Default(), nil)

	resp, err := h.CreateUser(testutil.AuthContext(adminID, "a@t", auth.AdminPermissions()), connect.NewRequest(&pm.CreateUserRequest{
		Email:    "dek-" + testutil.NewID()[:8] + "@test.com",
		Password: "s3cret-password",
	}))
	require.NoError(t, err)
	userID := resp.Msg.User.Id

	key, err := st.Repos().UserEncryptionKey.Get(ctx, userID)
	require.NoError(t, err, "a freshly created user must have an encryption key (AC 1)")
	assert.Contains(t, key.WrappedDEK, "enc:v1:", "the DEK is stored KEK-wrapped in the single at-rest format; never plaintext")

	var n int
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM user_encryption_keys WHERE user_id = $1`, userID).Scan(&n))
	assert.Equal(t, 1, n, "exactly one key row per user")

	// The creation event itself is sealed: the email must not appear
	// in plaintext anywhere in the event row (AC 2 on the create path).
	var raw string
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		`SELECT data::text FROM events WHERE stream_type = 'user' AND stream_id = $1
		 AND event_type = 'UserCreatedWithRoles'`, userID).Scan(&raw))
	assert.NotContains(t, raw, "dek-", "creation event must not carry the email in plaintext")
	assert.Contains(t, raw, "pii:v1:", "creation event PII is sealed")
}
