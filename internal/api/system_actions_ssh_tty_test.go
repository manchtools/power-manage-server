package api

// SSH + TTY path coverage for SystemActionManager — extends the
// #151 manager tests (PR #218) to the syncSshAccessAction and
// syncTtyUserAction branches that PR deferred. Same fixture
// pattern: testcontainer Postgres, NoOpSigner, side effects
// asserted via the projection.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// enablePerUserSshAccess flips ssh_access_enabled=true on a user via
// the typed UserSshSettingsUpdated event so syncSshAccessAction
// takes the create-action branch.
func enablePerUserSshAccess(t *testing.T, st *store.Store, userID string) {
	t.Helper()
	enabled := true
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "user", StreamID: userID,
		EventType: "UserSshSettingsUpdated",
		Data:      map[string]any{"ssh_access_enabled": enabled},
		ActorType: "system", ActorID: "test",
	}))
}

// =============================================================================
// SSH path — provisioning + per-user SSH access enabled
// =============================================================================

func TestSyncUserSystemActions_SshAccessEnabled_CreatesSshAction(t *testing.T) {
	m, st := newManagerForTest(t)
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	enablePerUserSshAccess(t, st, userID)

	require.NoError(t, m.SyncUserSystemActions(context.Background(), userID))

	user, err := st.Queries().GetUserByID(context.Background(), userID)
	require.NoError(t, err)
	require.NotEmpty(t, user.SystemSshActionID,
		"per-user SSH access enabled → manager must create + link a system SSH action")

	action, err := st.Queries().GetActionByID(context.Background(), user.SystemSshActionID)
	require.NoError(t, err)
	assert.Equal(t, "system:ssh-access:"+userID, action.Name,
		"system SSH action name pattern is 'system:ssh-access:<userID>' — the listener + audit redactor key on this prefix")
	assert.NotEmpty(t, action.Signature, "system SSH actions MUST be signed at create time")
}

func TestSyncUserSystemActions_SshAccessDisabled_CleansUpPriorSshAction(t *testing.T) {
	m, st := newManagerForTest(t)
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	enablePerUserSshAccess(t, st, userID)

	require.NoError(t, m.SyncUserSystemActions(context.Background(), userID))
	user, err := st.Queries().GetUserByID(context.Background(), userID)
	require.NoError(t, err)
	require.NotEmpty(t, user.SystemSshActionID, "precondition: SSH action exists")

	// Flip per-user SSH access off — UserSshSettingsUpdated with the
	// pointer set to false (vs nil which would preserve).
	disabled := false
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "user", StreamID: userID,
		EventType: "UserSshSettingsUpdated",
		Data:      map[string]any{"ssh_access_enabled": disabled},
		ActorType: "system", ActorID: "test",
	}))

	require.NoError(t, m.SyncUserSystemActions(context.Background(), userID))
	after, err := st.Queries().GetUserByID(context.Background(), userID)
	require.NoError(t, err)
	assert.Empty(t, after.SystemSshActionID,
		"SSH access flipped off → cleanup branch must clear system_ssh_action_id")
}

// =============================================================================
// TTY path — gated on the StartTerminal permission
// =============================================================================

func TestSyncUserSystemActions_StartTerminalPerm_CreatesTtyAction(t *testing.T) {
	m, st := newManagerForTest(t)
	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")

	// Grant StartTerminal via a role assignment. The manager's TTY
	// gate calls GetUserPermissionsWithGroups, which walks roles.
	roleID := testutil.CreateTestRole(t, st, actorID, "TerminalUser", []string{"StartTerminal"})
	testutil.AssignRoleToTestUser(t, st, actorID, userID, roleID)

	require.NoError(t, m.SyncUserSystemActions(context.Background(), userID))

	user, err := st.Queries().GetUserByID(context.Background(), userID)
	require.NoError(t, err)
	require.NotEmpty(t, user.SystemTtyActionID,
		"user holding StartTerminal → manager must create + link a system TTY action")

	action, err := st.Queries().GetActionByID(context.Background(), user.SystemTtyActionID)
	require.NoError(t, err)
	assert.Equal(t, "system:tty-user:"+userID, action.Name,
		"TTY action name is 'system:tty-user:<userID>' — the resolution engine keys on this prefix")
	assert.NotEmpty(t, action.Signature, "system TTY actions MUST be signed at create time")
}

func TestSyncUserSystemActions_NoStartTerminalPerm_CleansUpPriorTtyAction(t *testing.T) {
	m, st := newManagerForTest(t)
	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	roleID := testutil.CreateTestRole(t, st, actorID, "TerminalUser", []string{"StartTerminal"})
	testutil.AssignRoleToTestUser(t, st, actorID, userID, roleID)

	require.NoError(t, m.SyncUserSystemActions(context.Background(), userID))
	user, err := st.Queries().GetUserByID(context.Background(), userID)
	require.NoError(t, err)
	require.NotEmpty(t, user.SystemTtyActionID, "precondition: TTY action exists")

	// Revoke the role. Permission walk should now return no
	// StartTerminal → cleanup branch.
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "user_role", StreamID: userID + ":" + roleID,
		EventType: "UserRoleRevoked",
		Data:      map[string]any{"user_id": userID, "role_id": roleID},
		ActorType: "user", ActorID: actorID,
	}))

	require.NoError(t, m.SyncUserSystemActions(context.Background(), userID))
	after, err := st.Queries().GetUserByID(context.Background(), userID)
	require.NoError(t, err)
	assert.Empty(t, after.SystemTtyActionID,
		"StartTerminal permission revoked → cleanup branch must clear system_tty_action_id")
}
