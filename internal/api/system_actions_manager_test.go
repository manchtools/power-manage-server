package api

// SystemActionManager tests — closes manchtools/power-manage-server#151
// (audit F015). The store extraction landed in #154 (PR #213); this
// file fills in the manager-level coverage that the audit flagged
// as missing — SyncUserSystemActions's policy decisions, the
// idempotent re-run shape, and CleanupDeletedUserActions.
//
// We don't mock the store; the manager's policy reads from the
// projection so the cleanest test fixture is a real testcontainer
// Postgres + the existing testutil helpers + a NoOpSigner. Tests
// assert side effects via the projection state after each call.

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// newManagerForTest stands up a SystemActionManager backed by a real
// PG testcontainer + a NoOpSigner. Returns the manager + the store
// so tests can also seed events directly.
func newManagerForTest(t *testing.T) (*SystemActionManager, *store.Store) {
	t.Helper()
	st := testutil.SetupPostgres(t)
	return NewSystemActionManager(st, NoOpSigner{}, slog.Default()), st
}

// setLinuxUsername emits the UserLinuxUsernameChanged event so the
// projection's linux_username column is populated. Without this, the
// manager skips system-action sync (the "no linux username" gate).
func setLinuxUsername(t *testing.T, st *store.Store, userID, username string) {
	t.Helper()
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "user", StreamID: userID,
		EventType: "UserLinuxUsernameChanged",
		Data:      map[string]any{"linux_username": username},
		ActorType: "system", ActorID: "test",
	}))
}

// enableGlobalProvisioning flips the singleton server_settings row's
// user_provisioning_enabled to true via the typed event. Tests that
// want SyncUserSystemActions to take the create-action branch use
// this.
func enableGlobalProvisioning(t *testing.T, st *store.Store) {
	t.Helper()
	enabled := true
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "server_settings", StreamID: "singleton",
		EventType: "ServerSettingUpdated",
		Data:      map[string]any{"user_provisioning_enabled": enabled},
		ActorType: "system", ActorID: "test",
	}))
}

// =============================================================================
// SyncUserSystemActions — input gate (no linux_username)
// =============================================================================

func TestSyncUserSystemActions_NoLinuxUsername_NoOps(t *testing.T) {
	m, st := newManagerForTest(t)
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	// Note: no setLinuxUsername — the user lands without one.

	require.NoError(t, m.SyncUserSystemActions(context.Background(), userID))

	user, err := st.Repos().User.Get(context.Background(), userID)
	require.NoError(t, err)
	assert.Empty(t, user.SystemUserActionID, "no linux_username → manager must NOT have created a USER action")
	assert.Empty(t, user.SystemSshActionID, "no linux_username → no SSH action either")
	assert.Empty(t, user.SystemTtyActionID, "no linux_username → no TTY action either")
}

// =============================================================================
// SyncUserSystemActions — provisioning disabled (cleanup branch)
// =============================================================================

func TestSyncUserSystemActions_ProvisioningDisabled_NoActionsCreated(t *testing.T) {
	m, st := newManagerForTest(t)
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	// Note: no enableGlobalProvisioning — the user lands with provisioning OFF.

	require.NoError(t, m.SyncUserSystemActions(context.Background(), userID))

	user, err := st.Repos().User.Get(context.Background(), userID)
	require.NoError(t, err)
	assert.Empty(t, user.SystemUserActionID,
		"provisioning disabled + no prior action → cleanup branch is a no-op (nothing to delete)")
}

// =============================================================================
// SyncUserSystemActions — happy path with provisioning enabled
// =============================================================================

func TestSyncUserSystemActions_GlobalProvisioning_CreatesUserAction(t *testing.T) {
	m, st := newManagerForTest(t)
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	enableGlobalProvisioning(t, st)

	require.NoError(t, m.SyncUserSystemActions(context.Background(), userID))

	user, err := st.Repos().User.Get(context.Background(), userID)
	require.NoError(t, err)
	require.NotEmpty(t, user.SystemUserActionID,
		"provisioning enabled + linux_username → manager must create + link a system USER action")

	// Action row landed in actions_projection.
	action, err := st.Queries().GetActionByID(context.Background(), user.SystemUserActionID)
	require.NoError(t, err)
	assert.Equal(t, "system:user-provision:"+userID, action.Name)
	assert.NotEmpty(t, action.Signature, "system actions MUST be signed at create time")
}

// =============================================================================
// SyncUserSystemActions — idempotent on re-run (update branch)
// =============================================================================

func TestSyncUserSystemActions_SecondRun_UpdatesExistingAction(t *testing.T) {
	m, st := newManagerForTest(t)
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	enableGlobalProvisioning(t, st)

	require.NoError(t, m.SyncUserSystemActions(context.Background(), userID))
	user1, err := st.Repos().User.Get(context.Background(), userID)
	require.NoError(t, err)
	originalActionID := user1.SystemUserActionID
	require.NotEmpty(t, originalActionID)

	// Re-run with no state change. The manager must reach the update
	// branch (not the create branch) so the action ID stays stable —
	// otherwise downstream assignments would dangle.
	require.NoError(t, m.SyncUserSystemActions(context.Background(), userID))
	user2, err := st.Repos().User.Get(context.Background(), userID)
	require.NoError(t, err)
	assert.Equal(t, originalActionID, user2.SystemUserActionID,
		"second sync MUST keep the same action ID — re-creating would orphan the assignment row")
}

// =============================================================================
// CleanupDeletedUserActions — emits delete + unlink for each action
// =============================================================================

func TestCleanupDeletedUserActions_RemovesAllSystemActions(t *testing.T) {
	m, st := newManagerForTest(t)
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	enableGlobalProvisioning(t, st)

	require.NoError(t, m.SyncUserSystemActions(context.Background(), userID))
	user, err := st.Repos().User.Get(context.Background(), userID)
	require.NoError(t, err)
	require.NotEmpty(t, user.SystemUserActionID, "precondition: user has a system action")

	// CleanupDeletedUserActions takes the projection row as-of pre-delete
	// (the caller is expected to load it BEFORE emitting UserDeleted).
	require.NoError(t, m.CleanupDeletedUserActions(context.Background(), user))

	// User's link columns are now empty — confirms the cleanup
	// emitted UserSystemActionLinked with action_id="".
	after, err := st.Repos().User.Get(context.Background(), userID)
	require.NoError(t, err)
	assert.Empty(t, after.SystemUserActionID, "cleanup MUST clear system_user_action_id")
}

// =============================================================================
// SyncUserSystemActions — provisioning disabled cleans up prior action
// =============================================================================

func TestSyncUserSystemActions_DisablingProvisioningCleansUpExistingAction(t *testing.T) {
	m, st := newManagerForTest(t)
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	enableGlobalProvisioning(t, st)

	// First sync creates the action.
	require.NoError(t, m.SyncUserSystemActions(context.Background(), userID))
	user, err := st.Repos().User.Get(context.Background(), userID)
	require.NoError(t, err)
	require.NotEmpty(t, user.SystemUserActionID)

	// Flip provisioning OFF via a follow-up server_settings update.
	disabled := false
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "server_settings", StreamID: "singleton",
		EventType: "ServerSettingUpdated",
		Data:      map[string]any{"user_provisioning_enabled": disabled},
		ActorType: "system", ActorID: "test",
	}))

	// Second sync must take the cleanup branch.
	require.NoError(t, m.SyncUserSystemActions(context.Background(), userID))
	after, err := st.Repos().User.Get(context.Background(), userID)
	require.NoError(t, err)
	assert.Empty(t, after.SystemUserActionID,
		"provisioning flipped off → cleanup branch must clear the prior link")
}
