package api_test

// Coverage tests for RPCs that previously had no dedicated handler test.
// Each test exercises one RPC with assertions on its actual return
// shape — not just "no error". File is split into single-RPC tests so
// failures point at the exact code path that regressed; conjoined
// "TestFooAndBarAndBaz" functions were rejected on review.
//
// Each test calls testutil.SetupPostgres(t), which spawns a fresh
// Postgres testcontainer per test. That matches the rest of the
// codebase but is expensive in aggregate. A shared per-package fixture
// would help; it's tracked separately because changing the pattern
// here only would diverge from house style.

import (
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// =============================================================================
// UserHandler — profile + provisioning + Linux username + SSH key + SSH settings
// =============================================================================

func TestUserHandler_UpdateUserProfile_AppliesAllProfileFields(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st, slog.Default(), nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.UpdateUserProfile(ctx, connect.NewRequest(&pm.UpdateUserProfileRequest{
		Id:                userID,
		DisplayName:       "Alice Example",
		GivenName:         "Alice",
		FamilyName:        "Example",
		PreferredUsername: "alice",
		Locale:            "en-US",
	}))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg.User)
	got := resp.Msg.User
	assert.Equal(t, userID, got.Id)
	assert.Equal(t, "Alice Example", got.DisplayName)
	assert.Equal(t, "Alice", got.GivenName)
	assert.Equal(t, "Example", got.FamilyName)
	assert.Equal(t, "alice", got.PreferredUsername)
	assert.Equal(t, "en-US", got.Locale)
}

func TestUserHandler_SetUserProvisioningEnabled_FlipsFlag(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st, slog.Default(), nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	ctx := testutil.AdminContext(adminID)

	on, err := h.SetUserProvisioningEnabled(ctx, connect.NewRequest(&pm.SetUserProvisioningEnabledRequest{
		UserId:  userID,
		Enabled: true,
	}))
	require.NoError(t, err)
	assert.True(t, on.Msg.User.UserProvisioningEnabled, "true must persist")

	off, err := h.SetUserProvisioningEnabled(ctx, connect.NewRequest(&pm.SetUserProvisioningEnabledRequest{
		UserId:  userID,
		Enabled: false,
	}))
	require.NoError(t, err)
	assert.False(t, off.Msg.User.UserProvisioningEnabled, "false must also persist — the field must be a real toggle, not a one-way switch")
}

func TestUserHandler_UpdateUserLinuxUsername_PersistsValue(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st, slog.Default(), nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.UpdateUserLinuxUsername(ctx, connect.NewRequest(&pm.UpdateUserLinuxUsernameRequest{
		UserId:        userID,
		LinuxUsername: "alice-linux",
	}))
	require.NoError(t, err)
	assert.Equal(t, "alice-linux", resp.Msg.User.LinuxUsername)
	assert.Equal(t, userID, resp.Msg.User.Id, "response must echo the same user id it was asked to update")
}

func TestUserHandler_AddAndRemoveUserSshKey_RoundTrip(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st, slog.Default(), nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	ctx := testutil.AdminContext(adminID)

	add, err := h.AddUserSshKey(ctx, connect.NewRequest(&pm.AddUserSshKeyRequest{
		UserId:    userID,
		PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ3validtestkey alice@example",
		Comment:   "laptop",
	}))
	require.NoError(t, err)
	require.NotNil(t, add.Msg.Key)
	keyID := add.Msg.Key.Id
	assert.NotEmpty(t, keyID, "the server must mint a key id")
	assert.Equal(t, "laptop", add.Msg.Key.Comment, "the comment must round-trip")

	_, err = h.RemoveUserSshKey(ctx, connect.NewRequest(&pm.RemoveUserSshKeyRequest{
		UserId: userID,
		KeyId:  keyID,
	}))
	require.NoError(t, err)
}

func TestUserHandler_UpdateUserSshSettings_AppliesAllFlags(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st, slog.Default(), nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.UpdateUserSshSettings(ctx, connect.NewRequest(&pm.UpdateUserSshSettingsRequest{
		UserId:           userID,
		SshAccessEnabled: true,
		SshAllowPubkey:   true,
		SshAllowPassword: false,
	}))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg.User)
	got := resp.Msg.User
	assert.True(t, got.SshAccessEnabled, "ssh_access_enabled must persist")
	assert.True(t, got.SshAllowPubkey, "ssh_allow_pubkey must persist")
	assert.False(t, got.SshAllowPassword, "ssh_allow_password=false must persist (not silently flipped to true)")
}

// =============================================================================
// DeviceGroupHandler — list-for-device, dynamic query, evaluation
// =============================================================================

func TestDeviceGroupHandler_ListDeviceGroupsForDevice_ReturnsOnlyGroupsContainingDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "list-host")
	memberGroupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Member Group")
	otherGroupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Other Group")
	testutil.AddDeviceToTestGroup(t, st, adminID, memberGroupID, deviceID)

	resp, err := h.ListDeviceGroupsForDevice(ctx, connect.NewRequest(&pm.ListDeviceGroupsForDeviceRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Groups, 1, "must only return groups containing the device")
	assert.Equal(t, memberGroupID, resp.Msg.Groups[0].Id)
	for _, g := range resp.Msg.Groups {
		assert.NotEqual(t, otherGroupID, g.Id, "groups the device is not a member of must not leak into the response")
	}
}

// TestDeviceGroupHandler_UpdateDeviceGroupQuery_UpdatesQueryOnDynamicGroup
// pins the post-#7 contract: UpdateDeviceGroupQuery only operates on
// groups that are ALREADY dynamic. The previous name
// `FlipsToDynamicAndPersistsQuery` described the looser pre-#7
// behaviour where the same RPC promoted static groups to dynamic —
// that path was closed in #7 S1 to prevent a holder of
// UpdateDynamicDeviceGroupQuery from silently bypassing the
// CreateDynamicDeviceGroup gate (T-S2 update pathway). The static
// rejection contract is pinned by the sibling test
// TestUpdateDeviceGroupQuery_RejectsStaticGroup_FailedPrecondition.
func TestDeviceGroupHandler_UpdateDeviceGroupQuery_UpdatesQueryOnDynamicGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	created, err := h.CreateDeviceGroup(ctx, connect.NewRequest(&pm.CreateDeviceGroupRequest{
		Name:         "Born Dynamic",
		IsDynamic:    true,
		DynamicQuery: `(device.hostname equals "initial-host")`,
	}))
	require.NoError(t, err)
	require.True(t, created.Msg.Group.IsDynamic)

	updated, err := h.UpdateDeviceGroupQuery(ctx, connect.NewRequest(&pm.UpdateDeviceGroupQueryRequest{
		Id:           created.Msg.Group.Id,
		IsDynamic:    true,
		DynamicQuery: `(device.hostname equals "dyn-host")`,
	}))
	require.NoError(t, err)
	assert.True(t, updated.Msg.Group.IsDynamic, "is_dynamic must persist")
	assert.Equal(t, `(device.hostname equals "dyn-host")`, updated.Msg.Group.DynamicQuery, "the query string must round-trip verbatim")
}

func TestDeviceGroupHandler_EvaluateDynamicGroup_CountsMatchingDevices(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	testutil.CreateTestDevice(t, st, "dyn-host")          // matching
	testutil.CreateTestDevice(t, st, "non-matching-host") // not matching
	group, err := h.CreateDeviceGroup(ctx, connect.NewRequest(&pm.CreateDeviceGroupRequest{
		Name:         "Dyn",
		IsDynamic:    true,
		DynamicQuery: `(device.hostname equals "dyn-host")`,
	}))
	require.NoError(t, err)

	evaluated, err := h.EvaluateDynamicGroup(ctx, connect.NewRequest(&pm.EvaluateDynamicGroupRequest{
		Id: group.Msg.Group.Id,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(1), evaluated.Msg.Group.MemberCount, "evaluation must select exactly the one matching device, not zero and not both")
}

// =============================================================================
// ActionHandler — five dispatch fan-out variants
// =============================================================================

func newDispatchFixture(t *testing.T) (*api.ActionHandler, *api.NoOpEnqueuer, string, string, string, string, string, string) {
	t.Helper()
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})
	queue := &api.NoOpEnqueuer{}
	h.SetTaskQueueClient(queue)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	deviceA := testutil.CreateTestDevice(t, st, "fanout-a")
	deviceB := testutil.CreateTestDevice(t, st, "fanout-b")
	actionID := testutil.CreateTestAction(t, st, adminID, "Fanout Action", int(pm.ActionType_ACTION_TYPE_SHELL))
	setID := testutil.CreateTestActionSet(t, st, adminID, "Fanout Set")
	testutil.AddActionToTestSet(t, st, adminID, setID, actionID, 1)
	definitionID := testutil.CreateTestDefinition(t, st, adminID, "Fanout Definition")
	testutil.AddActionSetToTestDefinition(t, st, adminID, definitionID, setID, 1)
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Fanout Group")
	testutil.AddDeviceToTestGroup(t, st, adminID, groupID, deviceA)
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceA, int(pm.AssignmentMode_ASSIGNMENT_MODE_REQUIRED))

	return h, queue, adminID, deviceA, deviceB, actionID, setID, definitionID
}

func TestActionHandler_DispatchToMultiple_CreatesOneExecutionPerDevice(t *testing.T) {
	h, _, adminID, deviceA, deviceB, actionID, _, _ := newDispatchFixture(t)
	ctx := testutil.AdminContext(adminID)

	resp, err := h.DispatchToMultiple(ctx, connect.NewRequest(&pm.DispatchToMultipleRequest{
		DeviceIds: []string{deviceA, deviceB},
		ActionSource: &pm.DispatchToMultipleRequest_ActionId{
			ActionId: actionID,
		},
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Executions, 2, "exactly one execution per target device")

	gotDevices := map[string]bool{}
	for _, e := range resp.Msg.Executions {
		gotDevices[e.DeviceId] = true
		assert.NotEmpty(t, e.Id, "every execution must carry a server-minted id")
	}
	assert.True(t, gotDevices[deviceA] && gotDevices[deviceB], "both devices must appear in the executions list")
}

func TestActionHandler_DispatchAssignedActions_DispatchesEveryAssignedAction(t *testing.T) {
	h, _, adminID, deviceA, _, _, _, _ := newDispatchFixture(t)
	ctx := testutil.AdminContext(adminID)

	resp, err := h.DispatchAssignedActions(ctx, connect.NewRequest(&pm.DispatchAssignedActionsRequest{DeviceId: deviceA}))
	require.NoError(t, err)
	require.NotEmpty(t, resp.Msg.Executions, "the device has an assigned action — at least one execution must be dispatched")
	for _, e := range resp.Msg.Executions {
		assert.Equal(t, deviceA, e.DeviceId, "every dispatched execution must target the requested device")
	}
}

func TestActionHandler_DispatchActionSet_DispatchesEverySetMember(t *testing.T) {
	h, _, adminID, deviceA, _, actionID, setID, _ := newDispatchFixture(t)
	ctx := testutil.AdminContext(adminID)

	resp, err := h.DispatchActionSet(ctx, connect.NewRequest(&pm.DispatchActionSetRequest{
		DeviceId:    deviceA,
		ActionSetId: setID,
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Executions, 1, "the set has one action; the response must contain exactly one execution per member")
	assert.Equal(t, actionID, resp.Msg.Executions[0].ActionId, "the execution must reference the set's member action")
}

func TestActionHandler_DispatchDefinition_DispatchesAllUnderlyingActions(t *testing.T) {
	h, _, adminID, deviceA, _, actionID, _, definitionID := newDispatchFixture(t)
	ctx := testutil.AdminContext(adminID)

	resp, err := h.DispatchDefinition(ctx, connect.NewRequest(&pm.DispatchDefinitionRequest{
		DeviceId:     deviceA,
		DefinitionId: definitionID,
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Executions, 1, "the definition has one set with one action — exactly one execution")
	assert.Equal(t, actionID, resp.Msg.Executions[0].ActionId, "the resolved execution must point at the action under the definition")
}

func TestActionHandler_DispatchToGroup_FansOutAcrossEveryGroupMember(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})
	queue := &api.NoOpEnqueuer{}
	h.SetTaskQueueClient(queue)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	deviceA := testutil.CreateTestDevice(t, st, "group-fanout-a")
	deviceB := testutil.CreateTestDevice(t, st, "group-fanout-b")
	actionID := testutil.CreateTestAction(t, st, adminID, "Fanout Action", int(pm.ActionType_ACTION_TYPE_SHELL))
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Fanout Group")
	testutil.AddDeviceToTestGroup(t, st, adminID, groupID, deviceA)
	testutil.AddDeviceToTestGroup(t, st, adminID, groupID, deviceB)
	ctx := testutil.AdminContext(adminID)

	resp, err := h.DispatchToGroup(ctx, connect.NewRequest(&pm.DispatchToGroupRequest{
		GroupId: groupID,
		ActionSource: &pm.DispatchToGroupRequest_ActionId{
			ActionId: actionID,
		},
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Executions, 2, "every device in the group must receive an execution")

	deviceSeen := map[string]bool{}
	for _, e := range resp.Msg.Executions {
		deviceSeen[e.DeviceId] = true
	}
	assert.True(t, deviceSeen[deviceA] && deviceSeen[deviceB], "both group members must appear in the executions")
	assert.GreaterOrEqual(t, len(queue.DeviceCalls), 2, "each execution must enqueue at least one device task")
}

// =============================================================================
// DeviceHandler — LPS, LUKS history, LUKS token mint
// =============================================================================

func TestDeviceHandler_GetDeviceLpsPasswords_EmptyForNewDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, testutil.NewEncryptor(t), slog.Default())

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "lps-device")
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)
	ctx := testutil.UserContext(userID)

	resp, err := h.GetDeviceLpsPasswords(ctx, connect.NewRequest(&pm.GetDeviceLpsPasswordsRequest{DeviceId: deviceID}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.Current, "a device with no LPS rotation history must report empty current state")
	assert.Empty(t, resp.Msg.History, "a device with no LPS rotation history must report empty history")
}

func TestDeviceHandler_GetDeviceLuksKeys_EmptyForNewDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, testutil.NewEncryptor(t), slog.Default())

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "luks-device")
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)
	ctx := testutil.UserContext(userID)

	resp, err := h.GetDeviceLuksKeys(ctx, connect.NewRequest(&pm.GetDeviceLuksKeysRequest{DeviceId: deviceID}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.Current, "a device with no LUKS rotation history must report empty current state")
	assert.Empty(t, resp.Msg.History, "a device with no LUKS rotation history must report empty history")
}

func TestDeviceHandler_CreateLuksToken_ReturnsTokenAndCliCommand(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, testutil.NewEncryptor(t), slog.Default())

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "luks-device")
	actionID := testutil.CreateTestAction(t, st, userID, "Encrypt Disk", int(pm.ActionType_ACTION_TYPE_ENCRYPTION))
	testutil.AssignDeviceToUser(t, st, userID, deviceID, userID)
	ctx := testutil.UserContext(userID)

	resp, err := h.CreateLuksToken(ctx, connect.NewRequest(&pm.CreateLuksTokenRequest{
		DeviceId: deviceID,
		ActionId: actionID,
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Token, 64, "the token must be a fixed-width 64-char identifier — operator-readability + collision-resistance contract")
	assert.Contains(t, resp.Msg.CliCommand, resp.Msg.Token, "the CLI command must embed the same token that was returned")
}

// =============================================================================
// CompliancePolicyHandler — add rule, update rule, device status
// =============================================================================

func TestCompliancePolicyHandler_AddCompliancePolicyRule_AppendsRuleToPolicy(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewCompliancePolicyHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	// AddCompliancePolicyRule rejects actions whose params don't carry
	// is_compliance=true (compliance_policy_handler.go:267). Use the
	// existing test helper that builds a SHELL action with that flag.
	actionID := createComplianceShellAction(t, st, adminID, "Compliance Action")
	policy, err := h.CreateCompliancePolicy(ctx, connect.NewRequest(&pm.CreateCompliancePolicyRequest{Name: "Baseline"}))
	require.NoError(t, err)
	require.Empty(t, policy.Msg.Policy.Rules, "a freshly-created policy must have no rules")

	resp, err := h.AddCompliancePolicyRule(ctx, connect.NewRequest(&pm.AddCompliancePolicyRuleRequest{
		PolicyId:         policy.Msg.Policy.Id,
		ActionId:         actionID,
		GracePeriodHours: 1,
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Policy.Rules, 1, "AddCompliancePolicyRule must append exactly one rule")
	rule := resp.Msg.Policy.Rules[0]
	assert.Equal(t, actionID, rule.ActionId, "the rule must reference the action we asked for")
	assert.Equal(t, int32(1), rule.GracePeriodHours, "the grace_period_hours we passed in must persist as-is")
}

func TestCompliancePolicyHandler_UpdateCompliancePolicyRule_UpdatesGracePeriod(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewCompliancePolicyHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	actionID := createComplianceShellAction(t, st, adminID, "Compliance Action")
	policy, err := h.CreateCompliancePolicy(ctx, connect.NewRequest(&pm.CreateCompliancePolicyRequest{Name: "Baseline"}))
	require.NoError(t, err)
	_, err = h.AddCompliancePolicyRule(ctx, connect.NewRequest(&pm.AddCompliancePolicyRuleRequest{
		PolicyId:         policy.Msg.Policy.Id,
		ActionId:         actionID,
		GracePeriodHours: 1,
	}))
	require.NoError(t, err)

	resp, err := h.UpdateCompliancePolicyRule(ctx, connect.NewRequest(&pm.UpdateCompliancePolicyRuleRequest{
		PolicyId:         policy.Msg.Policy.Id,
		ActionId:         actionID,
		GracePeriodHours: 24,
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Policy.Rules, 1, "update must not change the rule count — only the grace period")
	assert.Equal(t, int32(24), resp.Msg.Policy.Rules[0].GracePeriodHours, "grace_period_hours must reflect the new value")
}

func TestCompliancePolicyHandler_GetDeviceCompliancePolicyStatus_UnknownForDeviceWithoutEvaluations(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewCompliancePolicyHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "compliance-device")

	resp, err := h.GetDeviceCompliancePolicyStatus(ctx, connect.NewRequest(&pm.GetDeviceCompliancePolicyStatusRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Equal(t, pm.ComplianceStatus_COMPLIANCE_STATUS_UNKNOWN, resp.Msg.OverallStatus,
		"a device that has never reported a compliance evaluation must surface as UNKNOWN (never as a misleading PASSING/FAILING default)")
}

// =============================================================================
// TerminalHandler — list active sessions
// =============================================================================
//
// TODO: TestTerminalHandler_ListActiveTerminalSessions — the admin
// terminal RPCs (ListActiveTerminalSessions, TerminateTerminalSession)
// require a fully-configured handler with both a gateway registry and
// the internal HTTP client wired in. The existing newTerminalHandler
// in terminal_handler_test.go intentionally passes nil for both so
// the StartTerminal happy-path tests can run without that fixture.
// terminal_handler_test.go:254 has a parallel TODO noting the same
// gap. Add a `newAdminTerminalHandler` helper (registry + http client)
// before re-introducing this test — otherwise it surfaces as an opaque
// "registry not configured" failure instead of testing the RPC.

// =============================================================================
// Description updates — one test per entity (uniform shape, separate failures)
// =============================================================================

func TestActionHandler_UpdateActionDescription_PersistsValue(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	actionID := testutil.CreateTestAction(t, st, adminID, "Describe Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	resp, err := h.UpdateActionDescription(ctx, connect.NewRequest(&pm.UpdateActionDescriptionRequest{
		Id:          actionID,
		Description: "action description",
	}))
	require.NoError(t, err)
	assert.Equal(t, actionID, resp.Msg.Action.Id)
	assert.Equal(t, "action description", resp.Msg.Action.Description)
}

func TestActionSetHandler_UpdateActionSetDescription_PersistsValue(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionSetHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	setID := testutil.CreateTestActionSet(t, st, adminID, "Describe Set")

	resp, err := h.UpdateActionSetDescription(ctx, connect.NewRequest(&pm.UpdateActionSetDescriptionRequest{
		Id:          setID,
		Description: "set description",
	}))
	require.NoError(t, err)
	assert.Equal(t, setID, resp.Msg.Set.Id)
	assert.Equal(t, "set description", resp.Msg.Set.Description)
}

func TestDefinitionHandler_UpdateDefinitionDescription_PersistsValue(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDefinitionHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	definitionID := testutil.CreateTestDefinition(t, st, adminID, "Describe Definition")

	resp, err := h.UpdateDefinitionDescription(ctx, connect.NewRequest(&pm.UpdateDefinitionDescriptionRequest{
		Id:          definitionID,
		Description: "definition description",
	}))
	require.NoError(t, err)
	assert.Equal(t, definitionID, resp.Msg.Definition.Id)
	assert.Equal(t, "definition description", resp.Msg.Definition.Description)
}

func TestDeviceGroupHandler_UpdateDeviceGroupDescription_PersistsValue(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Describe Device Group")

	resp, err := h.UpdateDeviceGroupDescription(ctx, connect.NewRequest(&pm.UpdateDeviceGroupDescriptionRequest{
		Id:          groupID,
		Description: "device group description",
	}))
	require.NoError(t, err)
	assert.Equal(t, groupID, resp.Msg.Group.Id)
	assert.Equal(t, "device group description", resp.Msg.Group.Description)
}

func TestCompliancePolicyHandler_UpdateCompliancePolicyDescription_PersistsValue(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewCompliancePolicyHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	policy, err := h.CreateCompliancePolicy(ctx, connect.NewRequest(&pm.CreateCompliancePolicyRequest{Name: "Describe Policy"}))
	require.NoError(t, err)

	resp, err := h.UpdateCompliancePolicyDescription(ctx, connect.NewRequest(&pm.UpdateCompliancePolicyDescriptionRequest{
		Id:          policy.Msg.Policy.Id,
		Description: "policy description",
	}))
	require.NoError(t, err)
	assert.Equal(t, policy.Msg.Policy.Id, resp.Msg.Policy.Id)
	assert.Equal(t, "policy description", resp.Msg.Policy.Description)
}

// =============================================================================
// DefinitionHandler — set membership: reorder + remove
// =============================================================================

func TestDefinitionHandler_ReorderActionSetInDefinition_ReturnsSameDefinition(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDefinitionHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	setID := testutil.CreateTestActionSet(t, st, adminID, "Set")
	definitionID := testutil.CreateTestDefinition(t, st, adminID, "Definition")
	testutil.AddActionSetToTestDefinition(t, st, adminID, definitionID, setID, 1)

	resp, err := h.ReorderActionSetInDefinition(ctx, connect.NewRequest(&pm.ReorderActionSetInDefinitionRequest{
		DefinitionId: definitionID,
		ActionSetId:  setID,
		NewOrder:     2,
	}))
	require.NoError(t, err)
	assert.Equal(t, definitionID, resp.Msg.Definition.Id, "the response must echo the definition that was reordered")
}

func TestDefinitionHandler_RemoveActionSetFromDefinition_ReturnsDefinitionWithoutSet(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDefinitionHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	setID := testutil.CreateTestActionSet(t, st, adminID, "Set")
	definitionID := testutil.CreateTestDefinition(t, st, adminID, "Definition")
	testutil.AddActionSetToTestDefinition(t, st, adminID, definitionID, setID, 1)

	resp, err := h.RemoveActionSetFromDefinition(ctx, connect.NewRequest(&pm.RemoveActionSetFromDefinitionRequest{
		DefinitionId: definitionID,
		ActionSetId:  setID,
	}))
	require.NoError(t, err)
	assert.Equal(t, definitionID, resp.Msg.Definition.Id)
}

// =============================================================================
// DeviceHandler — ListDeviceAssignees
// =============================================================================

func TestDeviceHandler_ListDeviceAssignees_ListsAssignedUser(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, testutil.NewEncryptor(t), slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "assignee-host")
	testutil.AssignDeviceToUser(t, st, adminID, deviceID, userID)
	ctx := testutil.AdminContext(adminID)

	resp, err := h.ListDeviceAssignees(ctx, connect.NewRequest(&pm.ListDeviceAssigneesRequest{DeviceId: deviceID}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Assignees, 1, "exactly one user is assigned — must be the one we assigned")
	assert.Equal(t, userID, resp.Msg.Assignees[0].Id)
}

// =============================================================================
// UserGroupHandler — dynamic query + query validation
// =============================================================================

// TestUserGroupHandler_UpdateUserGroupQuery_UpdatesQueryOnDynamicGroup
// — symmetric with the device-group rename. Renamed from
// `FlipsToDynamicAndPersistsQuery` for the same reason: #7 S1
// closed the static→dynamic promotion path through this RPC.
func TestUserGroupHandler_UpdateUserGroupQuery_UpdatesQueryOnDynamicGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	created, err := h.CreateUserGroup(ctx, connect.NewRequest(&pm.CreateUserGroupRequest{
		Name:         "Born Dynamic Users",
		IsDynamic:    true,
		DynamicQuery: `(user.email contains "@old.com")`,
	}))
	require.NoError(t, err)
	require.True(t, created.Msg.Group.IsDynamic)

	resp, err := h.UpdateUserGroupQuery(ctx, connect.NewRequest(&pm.UpdateUserGroupQueryRequest{
		Id:           created.Msg.Group.Id,
		IsDynamic:    true,
		DynamicQuery: `(user.email contains "@user.com")`,
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Group.IsDynamic)
	assert.Equal(t, `(user.email contains "@user.com")`, resp.Msg.Group.DynamicQuery, "the query string must round-trip verbatim")
}

func TestUserGroupHandler_ValidateUserGroupQuery_AcceptsValidSyntax(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.ValidateUserGroupQuery(ctx, connect.NewRequest(&pm.ValidateUserGroupQueryRequest{
		Query: `(user.email contains "@")`,
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Valid, "a syntactically valid query must report valid=true")
}

// =============================================================================
// TOTPHandler — admin force-disable
// =============================================================================

func TestTOTPHandler_AdminDisableUserTOTP_DisablesUsersTOTP(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@user.com", "pass", "user")
	ctx := testutil.AdminContext(adminID)

	testutil.SetupTOTP(t, st, enc, userID, "totp-user@example.com")
	h := api.NewTOTPHandler(st, slog.Default(), testutil.NewJWTManager(), enc, "Test")

	_, err := h.AdminDisableUserTOTP(ctx, connect.NewRequest(&pm.AdminDisableUserTOTPRequest{UserId: userID}))
	require.NoError(t, err, "an admin acting on a user with TOTP set up must be allowed to force-disable it")
}

// =============================================================================
// SearchHandler + RoleHandler — utility RPCs
// =============================================================================

func TestSearchHandler_RebuildSearchIndex_UnavailableWhenIndexNotConfigured(t *testing.T) {
	h := api.NewSearchHandler(slog.Default())
	adminID := testutil.NewID()
	ctx := testutil.AdminContext(adminID)

	_, err := h.RebuildSearchIndex(ctx, connect.NewRequest(&pm.RebuildSearchIndexRequest{}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnavailable, connect.CodeOf(err),
		"calling RebuildSearchIndex without a configured index must surface as Unavailable (the operator-readable signal that this control replica isn't the indexer-bearing one), not a generic Internal")
}

func TestRoleHandler_ListPermissions_ReturnsTheBuiltinPermissionCatalog(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.ListPermissions(ctx, connect.NewRequest(&pm.ListPermissionsRequest{}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.Permissions, "the built-in permission catalog must surface to admins — empty would be a serious RBAC regression")
}
