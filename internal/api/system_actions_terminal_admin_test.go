package api

// TerminalAdmin global system-action bootstrap coverage —
// manchtools/power-manage-server#70 (paired with
// manchtools/power-manage-server#7).
//
// The pair `system:terminal-admin-limited:global` and
// `system:terminal-admin-full:global` are created idempotently at
// server startup. The reconciler (S3 — added in a subsequent slice)
// fills users[]; this slice only covers existence + signing +
// the wire-correct access_level on both actions.
//
// Fixture pattern matches system_actions_ssh_tty_test.go: real
// testcontainer Postgres + NoOpSigner + projection-state assertions.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// Name constants — the listener, audit redactor, and resolution layer
// will all key on these strings, so a typo here breaks the fan-out
// silently. Pin them in tests separately so a search-and-replace
// can't drift the producer and the consumer in lock-step undetected.
const (
	globalTerminalAdminLimitedActionName = "system:terminal-admin-limited:global"
	globalTerminalAdminFullActionName    = "system:terminal-admin-full:global"
)

func TestBootstrapGlobalTerminalAdminActions_CreatesBothActions(t *testing.T) {
	m, st := newManagerForTest(t)

	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	limited, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminLimitedActionName)
	require.NoError(t, err, "Limited global action must be created at bootstrap")
	assert.True(t, limited.IsSystem, "global TerminalAdmin actions MUST set is_system=true")
	// Action-signing rewrite: signing happens at DISPATCH over the full
	// SignedActionEnvelope, not at create time. The bootstrap pins the params
	// blob (so dispatch/audit has it) but persists no dispatch-grade signature.
	assert.NotEmpty(t, limited.ParamsCanonical, "global TerminalAdmin actions MUST pin their params blob at create time")
	assert.Empty(t, limited.Signature, "no dispatch-grade signature is persisted at create time — signing happens at dispatch")

	full, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminFullActionName)
	require.NoError(t, err, "Full global action must be created at bootstrap")
	assert.True(t, full.IsSystem)
	assert.NotEmpty(t, full.ParamsCanonical)
	assert.Empty(t, full.Signature)

	assert.NotEqual(t, limited.ID, full.ID, "Limited and Full actions must have distinct IDs")
}

func TestBootstrapGlobalTerminalAdminActions_Idempotent_NoDuplicates(t *testing.T) {
	m, st := newManagerForTest(t)

	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))
	beforeLimited, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminLimitedActionName)
	require.NoError(t, err)
	beforeFull, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminFullActionName)
	require.NoError(t, err)

	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	afterLimited, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminLimitedActionName)
	require.NoError(t, err)
	afterFull, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminFullActionName)
	require.NoError(t, err)

	assert.Equal(t, beforeLimited.ID, afterLimited.ID,
		"second bootstrap call must NOT create a duplicate Limited action")
	assert.Equal(t, beforeFull.ID, afterFull.ID,
		"second bootstrap call must NOT create a duplicate Full action")
}

func TestBootstrapGlobalTerminalAdminActions_Idempotent_DoesNotReSign(t *testing.T) {
	m, st := newManagerForTest(t)

	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))
	beforeLimited, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminLimitedActionName)
	require.NoError(t, err)
	beforeFull, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminFullActionName)
	require.NoError(t, err)
	beforeLimitedUpdated := beforeLimited.UpdatedAt
	beforeFullUpdated := beforeFull.UpdatedAt

	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	afterLimited, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminLimitedActionName)
	require.NoError(t, err)
	afterFull, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminFullActionName)
	require.NoError(t, err)

	// The reconciler (S3) re-signs on every users[] change. The
	// bootstrap MUST NOT trigger an unnecessary re-sign — otherwise
	// every server start would invalidate every agent's cached copy
	// of these actions, even when nothing changed. Pin the updated_at
	// timestamp.
	assert.Equal(t, beforeLimitedUpdated, afterLimited.UpdatedAt,
		"second bootstrap call must NOT re-sign the Limited action (no churn on every server start)")
	assert.Equal(t, beforeFullUpdated, afterFull.UpdatedAt,
		"second bootstrap call must NOT re-sign the Full action")
}

func TestBootstrapGlobalTerminalAdminActions_LimitedHasCorrectAccessLevel(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	limited, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminLimitedActionName)
	require.NoError(t, err)

	var params pm.AdminPolicyParams
	require.NoError(t, protojson.Unmarshal(limited.Params, &params),
		"Limited action's params must unmarshal as AdminPolicyParams")
	assert.Equal(t, pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_LIMITED, params.AccessLevel,
		"Limited action MUST carry the new TERMINAL_ADMIN_LIMITED enum value — otherwise the agent routes to the wrong template")
	assert.Empty(t, params.Users,
		"bootstrap creates the action with NO members; the reconciler fills users[]")
}

func TestBootstrapGlobalTerminalAdminActions_FullHasCorrectAccessLevel(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	full, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminFullActionName)
	require.NoError(t, err)

	var params pm.AdminPolicyParams
	require.NoError(t, protojson.Unmarshal(full.Params, &params))
	assert.Equal(t, pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_FULL, params.AccessLevel,
		"Full action MUST carry the new TERMINAL_ADMIN_FULL enum value")
	assert.Empty(t, params.Users)
}

func TestBootstrapGlobalTerminalAdminActions_ActionTypeIsAdminPolicy(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	limited, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminLimitedActionName)
	require.NoError(t, err)
	full, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminFullActionName)
	require.NoError(t, err)

	assert.Equal(t, int32(pm.ActionType_ACTION_TYPE_ADMIN_POLICY), limited.ActionType,
		"both globals are AdminPolicy actions — the agent's executor dispatch in sudo.go keys on this")
	assert.Equal(t, int32(pm.ActionType_ACTION_TYPE_ADMIN_POLICY), full.ActionType)
}

// =============================================================================
// ReconcileGlobalTerminalAdminActions — S3 of #70.
//
// Recomputes users[] on both globals based on the permission cohort.
// #7 Model Y: a user enters the LIMITED cohort iff they hold an UNSCOPED
// TerminalAdminLimited grant AND are non-disabled / non-deleted / have a
// linux_username. StartTerminal is NOT required — it drives the pm-tty
// account (a separate concern); the sudo policy is inert/harmless when
// no account exists. FULL is the same shape against TerminalAdminFull.
// (Device-group-scoped grants drive the per-scope actions, not these.)
//
// The reconciler MUST be a no-op when nothing has changed — repeated
// ticks under a steady population must not churn the signature, or
// every agent re-pulls these actions on every reconcile tick.
// =============================================================================

// loadAdminPolicy is a test helper that unmarshals a global action's
// Params into the typed proto. Centralises the boilerplate so each
// test reads as a single intent assertion. Returns a pointer so the
// embedded protoimpl.MessageState's Mutex isn't copied by value (go
// vet flags that).
func loadAdminPolicy(t *testing.T, st *store.Store, name string) *pm.AdminPolicyParams {
	t.Helper()
	row, err := st.Queries().GetActionByName(context.Background(), name)
	require.NoError(t, err, "global action %s missing — was BootstrapGlobalTerminalAdminActions called?", name)
	var params pm.AdminPolicyParams
	require.NoError(t, protojson.Unmarshal(row.Params, &params))
	return &params
}

// grantPermsViaRole is a test helper that creates a role with the
// given permissions and assigns it to userID.
func grantPermsViaRole(t *testing.T, st *store.Store, actorID, userID, roleName string, perms []string) string {
	t.Helper()
	roleID := testutil.CreateTestRole(t, st, actorID, roleName, perms)
	testutil.AssignRoleToTestUser(t, st, actorID, userID, roleID)
	return roleID
}

func TestReconcileGlobalTerminalAdmin_AddsHolderWithBothPerms(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	grantPermsViaRole(t, st, actorID, userID, "TerminalAdminUser",
		[]string{"StartTerminal", "TerminalAdminLimited"})

	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))

	limited := loadAdminPolicy(t, st, globalTerminalAdminLimitedActionName)
	assert.Equal(t, []string{"pm-tty-alice"}, limited.Users,
		"user holding StartTerminal + TerminalAdminLimited must be in the Limited cohort as pm-tty-<linuxusername>")
}

// #7 Model Y: a user with TerminalAdminLimited alone (no StartTerminal)
// MUST enter the Limited cohort — the sudo cohort is driven by
// TerminalAdmin alone (StartTerminal drives only the pm-tty account, a
// separate concern). The sudo policy is harmless/inert on devices where
// the account doesn't exist. This reverses the pre-#7 intersection gate.
func TestReconcileGlobalTerminalAdmin_IncludesHolderWithoutStartTerminal(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	grantPermsViaRole(t, st, actorID, userID, "TerminalAdminOnly",
		[]string{"TerminalAdminLimited"})

	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))

	limited := loadAdminPolicy(t, st, globalTerminalAdminLimitedActionName)
	assert.Equal(t, []string{"pm-tty-alice"}, limited.Users,
		"user with TerminalAdminLimited (even without StartTerminal) must enter the cohort")
}

// A user with StartTerminal alone (no TerminalAdmin*) must NOT enter any
// sudo cohort — StartTerminal grants the account/session, not sudo.
func TestReconcileGlobalTerminalAdmin_ExcludesStartTerminalOnly(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	grantPermsViaRole(t, st, actorID, userID, "TerminalOnly", []string{"StartTerminal"})

	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))

	assert.Empty(t, loadAdminPolicy(t, st, globalTerminalAdminLimitedActionName).Users,
		"StartTerminal alone grants no sudo cohort membership")
	assert.Empty(t, loadAdminPolicy(t, st, globalTerminalAdminFullActionName).Users)
}

// A device-group-SCOPED TerminalAdmin grant must NOT enter the GLOBAL
// cohort — it drives the per-scope action (follow-up). Only unscoped
// (global) grants feed the global actions.
func TestReconcileGlobalTerminalAdmin_ExcludesScopedGrant(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	roleID := testutil.CreateTestRole(t, st, actorID, "ScopedTA", []string{"TerminalAdminLimited"})
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "user_role",
		StreamID:   userID + ":" + roleID + ":dg-1",
		EventType:  string(eventtypes.UserRoleAssigned),
		Data: map[string]any{
			"user_id": userID, "role_id": roleID,
			"scope_kind": "device_group", "scope_id": "dg-1",
		},
		ActorType: "user", ActorID: actorID,
	}))

	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))

	assert.Empty(t, loadAdminPolicy(t, st, globalTerminalAdminLimitedActionName).Users,
		"a device-group-scoped TerminalAdmin grant must NOT enter the global cohort")
}

func TestReconcileGlobalTerminalAdmin_RemovesRevokedHolder(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	roleID := grantPermsViaRole(t, st, actorID, userID, "TerminalAdminUser",
		[]string{"StartTerminal", "TerminalAdminLimited"})
	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))
	require.Equal(t, []string{"pm-tty-alice"}, loadAdminPolicy(t, st, globalTerminalAdminLimitedActionName).Users,
		"precondition: alice is in the cohort")

	// Revoke the role's permissions — the user no longer holds either perm
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "user_role", StreamID: userID + ":" + roleID,
		EventType: "UserRoleRevoked",
		Data:      map[string]any{"user_id": userID, "role_id": roleID},
		ActorType: "user", ActorID: actorID,
	}))

	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))
	limited := loadAdminPolicy(t, st, globalTerminalAdminLimitedActionName)
	assert.Empty(t, limited.Users, "revoked user must be removed from the cohort on next reconcile")
}

// Users without a linux_username are skipped by the reconciler — the
// pm-tty-<linuxusername> derivation has nothing to derive against.
// Pin the gate so a future refactor that drops the precondition can't
// land an empty / "pm-tty-" entry in the cohort.
func TestReconcileGlobalTerminalAdmin_ExcludesUserWithoutLinuxUsername(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	// Deliberately do NOT call setLinuxUsername.
	grantPermsViaRole(t, st, actorID, userID, "TerminalAdminUser",
		[]string{"StartTerminal", "TerminalAdminLimited"})

	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))

	limited := loadAdminPolicy(t, st, globalTerminalAdminLimitedActionName)
	assert.Empty(t, limited.Users,
		"user without linux_username must NOT enter the cohort — the pm-tty-* derivation has nothing to derive against")
}

func TestReconcileGlobalTerminalAdmin_DisabledUserExcluded(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	grantPermsViaRole(t, st, actorID, userID, "TerminalAdminUser",
		[]string{"StartTerminal", "TerminalAdminLimited"})
	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))
	require.Equal(t, []string{"pm-tty-alice"}, loadAdminPolicy(t, st, globalTerminalAdminLimitedActionName).Users,
		"precondition")

	require.NoError(t, st.AppendEvent(context.Background(), testutil.DisableEvent(userID)))

	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))
	limited := loadAdminPolicy(t, st, globalTerminalAdminLimitedActionName)
	assert.Empty(t, limited.Users,
		"disabled user must be removed from the cohort even though their permissions are still held; the sudoers fragment must not name a disabled account")
}

func TestReconcileGlobalTerminalAdmin_GroupRoleGrantsCounted(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	roleID := testutil.CreateTestRole(t, st, actorID, "TerminalAdminUser",
		[]string{"StartTerminal", "TerminalAdminLimited"})
	groupID := testutil.CreateTestUserGroup(t, st, actorID, "TerminalAdmins")
	testutil.AddUserToTestGroup(t, st, actorID, groupID, userID)
	testutil.AssignRoleToTestGroup(t, st, actorID, groupID, roleID)

	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))

	limited := loadAdminPolicy(t, st, globalTerminalAdminLimitedActionName)
	assert.Equal(t, []string{"pm-tty-alice"}, limited.Users,
		"user holding the permissions via user_group role must enter the cohort — group-derived permissions are first-class")
}

// Idempotency: re-running the reconciler with no membership change
// must NOT touch the action's signature/updated_at. Every agent caches
// these actions; spurious re-signs would invalidate every cached copy
// on every reconcile tick.
func TestReconcileGlobalTerminalAdmin_NoOpWhenUsersUnchanged(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	grantPermsViaRole(t, st, actorID, userID, "TerminalAdminUser",
		[]string{"StartTerminal", "TerminalAdminLimited"})

	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))
	before, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminLimitedActionName)
	require.NoError(t, err)
	beforeUpdated := before.UpdatedAt

	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))
	after, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminLimitedActionName)
	require.NoError(t, err)

	assert.Equal(t, beforeUpdated, after.UpdatedAt,
		"second reconcile call with identical cohort must NOT re-sign — no params change means no cache invalidation for agents")
}

func TestReconcileGlobalTerminalAdmin_FullAndLimitedDisjointHolders(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")

	u1 := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, u1, "alice")
	grantPermsViaRole(t, st, actorID, u1, "LimitedHolder",
		[]string{"StartTerminal", "TerminalAdminLimited"})

	u2 := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, u2, "bob")
	grantPermsViaRole(t, st, actorID, u2, "FullHolder",
		[]string{"StartTerminal", "TerminalAdminFull"})

	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))

	limited := loadAdminPolicy(t, st, globalTerminalAdminLimitedActionName)
	full := loadAdminPolicy(t, st, globalTerminalAdminFullActionName)
	assert.Equal(t, []string{"pm-tty-alice"}, limited.Users,
		"Limited cohort must contain alice (Limited holder) only")
	assert.Equal(t, []string{"pm-tty-bob"}, full.Users,
		"Full cohort must contain bob (Full holder) only")
}

func TestReconcileGlobalTerminalAdmin_HolderOfBothPermsIsInBothCohorts(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	grantPermsViaRole(t, st, actorID, userID, "BothLevels",
		[]string{"StartTerminal", "TerminalAdminLimited", "TerminalAdminFull"})

	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))

	limited := loadAdminPolicy(t, st, globalTerminalAdminLimitedActionName)
	full := loadAdminPolicy(t, st, globalTerminalAdminFullActionName)
	assert.Equal(t, []string{"pm-tty-alice"}, limited.Users,
		"user holding both perms enters both cohorts")
	assert.Equal(t, []string{"pm-tty-alice"}, full.Users)
}

// Pre-requisite: bootstrap must run before reconcile. Surfaces the
// dependency clearly so a future caller can't accidentally invert the
// order and get a silent failure.
func TestReconcileGlobalTerminalAdmin_FailsLoudlyIfBootstrapSkipped(t *testing.T) {
	m, _ := newManagerForTest(t)
	// Deliberately do NOT call BootstrapGlobalTerminalAdminActions.

	err := m.ReconcileGlobalTerminalAdminActions(context.Background())
	require.Error(t, err,
		"reconcile must surface a clear error when the global actions do not exist — silent no-op would mask a wiring bug at server startup")
}

// =============================================================================
// S4 — wiring: SyncAllUsersSystemActions must also reconcile the
// globals, so the periodic sweep + every fan-out event the listener
// classifies as SyncOpSyncAll both keep the cohort up to date without
// every caller needing to know about the new reconciler.
// =============================================================================

// =============================================================================
// S7 — audit event on membership removal.
//
// The reconciler emits one TerminalAdminMembershipRevoked event per
// previously-present pm-tty-* user that was dropped from a global
// action's users[]. The event carries enough context (user_id,
// linux_username, action_id, access_level) for audit consumers to
// render a meaningful row without re-reading the action's params.
//
// Adds and no-op ticks do NOT emit the event — only removals.
// =============================================================================

// loadMembershipRevokedEvents reads the terminal_admin_membership
// stream events for the given action ID. The reconciler emits one
// event per removal under (stream_type=terminal_admin_membership,
// stream_id=<action_id>) so audit consumers can read a per-action
// revocation history.
func loadMembershipRevokedEvents(t *testing.T, st *store.Store, actionID string) []store.PersistedEvent {
	t.Helper()
	events, err := st.LoadStream(context.Background(), "terminal_admin_membership", actionID)
	require.NoError(t, err)
	return events
}

func TestReconcileGlobalTerminalAdmin_EmitsRevokedEvent_OnRemoval(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	roleID := grantPermsViaRole(t, st, actorID, userID, "TerminalAdminUser",
		[]string{"StartTerminal", "TerminalAdminLimited"})
	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))

	limited, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminLimitedActionName)
	require.NoError(t, err)

	// Revoke + reconcile — should emit ONE TerminalAdminMembershipRevoked
	// event for pm-tty-alice on the Limited action.
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "user_role", StreamID: userID + ":" + roleID,
		EventType: "UserRoleRevoked",
		Data:      map[string]any{"user_id": userID, "role_id": roleID},
		ActorType: "user", ActorID: actorID,
	}))
	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))

	events := loadMembershipRevokedEvents(t, st, limited.ID)
	require.Len(t, events, 1,
		"reconciler must emit exactly one TerminalAdminMembershipRevoked event when pm-tty-alice is removed from the Limited cohort")

	var data map[string]any
	require.NoError(t, json.Unmarshal(events[0].Data, &data))
	assert.Equal(t, userID, data["user_id"],
		"event payload must carry the human user_id (audit consumers key on this)")
	assert.Equal(t, "alice", data["linux_username"],
		"event payload must carry the bare linux_username (audit composes the pm-tty- prefix itself)")
	assert.Equal(t, limited.ID, data["action_id"],
		"event payload must point at the affected action")
	assert.Equal(t, "ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_LIMITED", data["access_level"],
		"event payload must carry the wire-string access_level so audit can distinguish Limited vs Full revocations")
}

func TestReconcileGlobalTerminalAdmin_NoEvent_OnAddition(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	grantPermsViaRole(t, st, actorID, userID, "TerminalAdminUser",
		[]string{"StartTerminal", "TerminalAdminLimited"})

	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))

	limited, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminLimitedActionName)
	require.NoError(t, err)
	events := loadMembershipRevokedEvents(t, st, limited.ID)
	assert.Empty(t, events,
		"reconciler must NOT emit revoked events when a user enters the cohort — only removals are audited; the role-grant itself is already audited by the role layer")
}

func TestReconcileGlobalTerminalAdmin_NoEvent_OnNoOpTick(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	grantPermsViaRole(t, st, actorID, userID, "TerminalAdminUser",
		[]string{"StartTerminal", "TerminalAdminLimited"})
	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))

	// Second tick — same cohort. Must not emit any new revocation events.
	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))

	limited, err := st.Queries().GetActionByName(context.Background(), globalTerminalAdminLimitedActionName)
	require.NoError(t, err)
	events := loadMembershipRevokedEvents(t, st, limited.ID)
	assert.Empty(t, events,
		"no-op reconcile tick must not emit revocation events — the periodic sweep would otherwise log every steady-state tick as a revocation")
}

func TestSyncAllUsersSystemActions_ReconcilesTerminalAdminGlobals(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	grantPermsViaRole(t, st, actorID, userID, "TerminalAdminUser",
		[]string{"StartTerminal", "TerminalAdminLimited"})

	// SyncAllUsersSystemActions is the entry point the periodic sweep
	// + fan-out-event listener call. It must reconcile the globals as
	// part of its sweep so cohort updates land without the caller
	// needing to invoke a separate method.
	require.NoError(t, m.SyncAllUsersSystemActions(context.Background()))

	limited := loadAdminPolicy(t, st, globalTerminalAdminLimitedActionName)
	assert.Equal(t, []string{"pm-tty-alice"}, limited.Users,
		"SyncAllUsersSystemActions must end by reconciling the global TerminalAdmin actions — periodic sweep + fan-out events depend on this")
}
