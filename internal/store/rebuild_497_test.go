package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestRebuildAll_497_ReplaysEveryProjection is the #497 acceptance test: a
// FULL RebuildAll() (every target, FK-ordered) run against a fully-seeded
// schema must reproduce the previously-unreplayable projections 1:1 — most
// critically the three data-loss cases a users rebuild used to destroy:
// RBAC grants (user_roles), 2FA enrollments (totp), and SSO identity links.
//
// It seeds one of each, snapshots the live-projected state, runs the whole
// rebuild (which TRUNCATEs every projection and replays from the event
// store), and asserts each row returns identical.
func TestRebuildAll_497_ReplaysEveryProjection(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	ctx := context.Background()

	// --- seed a graph that touches every #497 projection ---
	adminEmail := testutil.NewID() + "@admin.com"
	adminID := testutil.CreateTestUser(t, st, adminEmail, "pass", "admin")

	userEmail := testutil.NewID() + "@user.com"
	userID := testutil.CreateTestUser(t, st, userEmail, "pass", "user")

	// RBAC grant on the user_role stream (the grant a users rebuild lost).
	roleID := testutil.CreateTestRole(t, st, adminID, "auditor", []string{"user:read"})
	testutil.AssignRoleToTestUser(t, st, adminID, userID, roleID)

	// 2FA enrollment (FK child of users_projection).
	testutil.SetupTOTP(t, st, enc, userID, userEmail)

	// SSO provider + identity link (FK children of providers/users).
	providerID := testutil.CreateTestIdentityProvider(t, st, enc, adminID, "Okta", "okta")
	linkID := testutil.CreateTestIdentityLink(t, st, userID, providerID, "ext-123", userEmail)

	// Server settings: flip a value via an event so the singleton diverges
	// from its migration-seeded default.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "server_settings",
		StreamID:   "global",
		EventType:  "ServerSettingUpdated",
		Data:       map[string]any{"ssh_access_for_all": true},
		ActorType:  "user",
		ActorID:    adminID,
	}))

	// --- snapshot the live-projected state ---
	rolesBefore, err := st.Queries().GetUserRoles(ctx, userID)
	require.NoError(t, err)
	require.Len(t, rolesBefore, 1, "precondition: the grant projected")

	totpBefore, err := st.Queries().GetTOTPByUserID(ctx, userID)
	require.NoError(t, err)
	require.NotEmpty(t, totpBefore.SecretEncrypted, "precondition: TOTP projected")

	linkBefore, err := st.Queries().GetIdentityLinkByID(ctx, linkID)
	require.NoError(t, err)

	providerBefore, err := st.Queries().GetIdentityProviderByID(ctx, providerID)
	require.NoError(t, err)

	settingsBefore, err := st.Queries().GetServerSettings(ctx)
	require.NoError(t, err)
	require.True(t, settingsBefore.SshAccessForAll, "precondition: settings event projected")

	// --- full rebuild: TRUNCATE every projection, replay from events ---
	res, err := st.RebuildAll(ctx)
	require.NoError(t, err, "a full rebuild must succeed for every target")
	names := map[string]bool{}
	for _, tr := range res.Targets {
		names[tr.Name] = true
	}
	for _, required := range []string{
		"users", "totp", "identity_providers", "security_alerts",
		"lps_passwords", "luks_keys", "server_settings",
		"compliance_policies", "compliance_results",
	} {
		assert.Truef(t, names[required], "full rebuild must include the %q target", required)
	}

	// --- assert every projection returned 1:1 ---

	// HIGH PRIORITY 1 — RBAC grant survived.
	rolesAfter, err := st.Queries().GetUserRoles(ctx, userID)
	require.NoError(t, err)
	require.Len(t, rolesAfter, 1, "the post-creation role grant must survive a full rebuild (RBAC data-loss regression)")
	assert.Equal(t, rolesBefore[0].ID, rolesAfter[0].ID)

	// HIGH PRIORITY 2 — 2FA enrollment survived.
	totpAfter, err := st.Queries().GetTOTPByUserID(ctx, userID)
	require.NoError(t, err, "TOTP enrollment must survive a full rebuild (2FA data-loss regression)")
	assert.Equal(t, totpBefore.SecretEncrypted, totpAfter.SecretEncrypted, "encrypted TOTP secret byte-identical")
	assert.Equal(t, totpBefore.BackupCodesHash, totpAfter.BackupCodesHash)

	// HIGH PRIORITY 3 — SSO identity link survived.
	linkAfter, err := st.Queries().GetIdentityLinkByID(ctx, linkID)
	require.NoError(t, err, "SSO identity link must survive a full rebuild (SSO data-loss regression)")
	assert.Equal(t, linkBefore.ExternalID, linkAfter.ExternalID)
	assert.Equal(t, linkBefore.UserID, linkAfter.UserID)
	assert.Equal(t, linkBefore.ProviderID, linkAfter.ProviderID)

	// Provider survived.
	providerAfter, err := st.Queries().GetIdentityProviderByID(ctx, providerID)
	require.NoError(t, err)
	assert.Equal(t, providerBefore.Slug, providerAfter.Slug)
	assert.Equal(t, providerBefore.ClientSecretEncrypted, providerAfter.ClientSecretEncrypted,
		"encrypted IdP client secret byte-identical")

	// Singleton server settings reproduced (re-seed + replay, not lost).
	settingsAfter, err := st.Queries().GetServerSettings(ctx)
	require.NoError(t, err, "the singleton server_settings row must be re-seeded and reproduced")
	assert.True(t, settingsAfter.SshAccessForAll, "the ServerSettingUpdated value must survive the rebuild")
}

// TestRebuildAll_497_UserRolesTargetInIsolation pins the RBAC replay
// through the merged users target (spec 21: user_roles_projection is
// co-owned by ApplyUser and ApplyUserRole, so the "user_roles" target
// was folded into "users"): a targeted rebuild reproduces BOTH the
// creation-time role_ids and the post-creation grant.
func TestRebuildAll_497_UserRolesTargetInIsolation(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@u.com", "pass", "user")
	roleID := testutil.CreateTestRole(t, st, adminID, "role1", []string{"user:read"})
	testutil.AssignRoleToTestUser(t, st, adminID, userID, roleID)

	before, err := st.Queries().GetUserRoles(ctx, userID)
	require.NoError(t, err)
	require.Len(t, before, 1)

	// Wipe the projection out from under the pipeline, then rebuild only it.
	_, err = st.TestingPool().Exec(ctx, "TRUNCATE user_roles_projection")
	require.NoError(t, err)
	gone, err := st.Queries().GetUserRoles(ctx, userID)
	require.NoError(t, err)
	require.Empty(t, gone, "precondition: the truncate took")

	res, err := st.RebuildAll(ctx, "users")
	require.NoError(t, err)
	users := findTargetResult(t, res, "users")
	assert.Positive(t, users.EventsApplied, "the user + user_role events must replay")

	after, err := st.Queries().GetUserRoles(ctx, userID)
	require.NoError(t, err)
	require.Len(t, after, len(before), "the pre-truncate role set must be re-derived exactly")
	assert.Equal(t, roleID, after[0].ID, "the post-creation grant must survive")
}
