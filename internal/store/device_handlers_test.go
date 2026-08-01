package store_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/device"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

type deviceHandlerFixture struct {
	t          *testing.T
	store      *store.Store
	raw        *pgxpool.Pool
	handlers   *device.Handlers
	now        time.Time
	actorID    string
	directID   string
	groupID    string
	outsideID  string
	userID     string
	userGroup  string
	scopeGroup string
	closed     []string
}

func newDeviceHandlerFixture(t *testing.T) *deviceHandlerFixture {
	t.Helper()
	st, raw := setupPostgres(t)
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	f := &deviceHandlerFixture{
		t: t, store: st, raw: raw, now: now,
		actorID: newID(), directID: newID(), groupID: newID(), outsideID: newID(),
		userID: newID(), userGroup: newID(), scopeGroup: newID(),
	}
	fingerprint := strings.Repeat("a", 64)
	expires := now.Add(24 * time.Hour)
	_, err := st.WithAudit(context.Background(), mutationOp(), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		for id, email := range map[string]string{
			f.actorID: "actor@example.test",
			f.userID:  "subject@example.test",
		} {
			if _, err := tx.InsertUser(ctx, db.InsertUserParams{
				ID: id, Email: email, DisplayName: email, LinuxUsername: "test",
				LinuxUid: 200001, CreatedAt: &now,
			}); err != nil {
				return err
			}
		}
		if _, err := tx.InsertUserGroup(ctx, db.InsertUserGroupParams{
			ID: f.userGroup, Name: "operators", CreatedAt: now, CreatedBy: f.actorID,
		}); err != nil {
			return err
		}
		if _, err := tx.InsertUserGroupMember(ctx, db.InsertUserGroupMemberParams{
			GroupID: f.userGroup, UserID: f.actorID, AddedAt: now, AddedBy: f.actorID,
		}); err != nil {
			return err
		}
		for _, d := range []db.InsertDeviceParams{
			{
				ID: f.directID, Hostname: "direct", AgentVersion: "1.0.0",
				AgentSealingPublicKey: bytes.Repeat([]byte{1}, 32), CertFingerprint: &fingerprint,
				CertNotAfter: &expires, RegisteredAt: &now, LastSeenAt: &now,
			},
			{
				ID: f.groupID, Hostname: "group", AgentVersion: "1.0.0",
				AgentSealingPublicKey: bytes.Repeat([]byte{2}, 32), RegisteredAt: &now, LastSeenAt: &now,
			},
			{
				ID: f.outsideID, Hostname: "outside", AgentVersion: "1.0.0",
				AgentSealingPublicKey: bytes.Repeat([]byte{3}, 32), RegisteredAt: &now, LastSeenAt: &now,
			},
		} {
			if _, err := tx.InsertDevice(ctx, d); err != nil {
				return err
			}
			rec.Effect(deviceEffect(d.ID))
		}
		if _, err := tx.AssignDeviceUser(ctx, db.AssignDeviceUserParams{
			DeviceID: f.directID, UserID: f.actorID, AssignedAt: now, AssignedBy: f.actorID,
		}); err != nil {
			return err
		}
		if _, err := tx.AssignDeviceGroup(ctx, db.AssignDeviceGroupParams{
			DeviceID: f.groupID, GroupID: f.userGroup, AssignedAt: now, AssignedBy: f.actorID,
		}); err != nil {
			return err
		}
		return nil
	})
	require.NoError(t, err)

	_, err = raw.Exec(context.Background(), `
		INSERT INTO device_groups (id, name, inventory_interval_minutes)
		VALUES ($1, 'scope', 720)`, f.scopeGroup)
	require.NoError(t, err)
	_, err = raw.Exec(context.Background(), `
		INSERT INTO device_group_members (group_id, device_id) VALUES ($1, $2)`, f.scopeGroup, f.groupID)
	require.NoError(t, err)
	_, err = raw.Exec(context.Background(), `
		INSERT INTO device_inventory (device_id, table_name, rows, collected_at)
		VALUES
			($1, 'os_version', '[{"name":"Debian"}]', $2),
			($1, 'system_info', '[{"hostname":"group"}]', $2)`, f.groupID, now.Add(-time.Hour))
	require.NoError(t, err)

	f.handlers = device.New(device.Config{
		Store:  st,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:    func() time.Time { return now },
		CloseStream: func(id string) {
			f.closed = append(f.closed, id)
		},
	})
	return f
}

func (f *deviceHandlerFixture) actor(perms ...string) context.Context {
	f.t.Helper()
	return auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser, Email: "actor@example.test", Permissions: perms,
	})
}

func TestDeviceHandlers_ValidateBeforeAuthentication(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	_, err := f.handlers.GetDevice(context.Background(), connect.NewRequest(&pmv1.GetDeviceRequest{Id: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.GetDeviceInventory(context.Background(),
		connect.NewRequest(&pmv1.GetDeviceInventoryRequest{DeviceId: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.GetOSQueryResult(context.Background(),
		connect.NewRequest(&pmv1.GetOSQueryResultRequest{QueryId: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.GetDeviceLogResult(context.Background(),
		connect.NewRequest(&pmv1.GetDeviceLogResultRequest{QueryId: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.GetDeviceCompliance(context.Background(),
		connect.NewRequest(&pmv1.GetDeviceComplianceRequest{DeviceId: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.GetDeviceCompliancePolicyStatus(context.Background(),
		connect.NewRequest(&pmv1.GetDeviceCompliancePolicyStatusRequest{DeviceId: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.GetExecution(context.Background(),
		connect.NewRequest(&pmv1.GetExecutionRequest{Id: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = f.handlers.GetDevice(context.Background(), connect.NewRequest(&pmv1.GetDeviceRequest{Id: f.directID}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.GetDeviceInventory(context.Background(),
		connect.NewRequest(&pmv1.GetDeviceInventoryRequest{DeviceId: f.directID}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.GetOSQueryResult(context.Background(),
		connect.NewRequest(&pmv1.GetOSQueryResultRequest{QueryId: newID()}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.GetDeviceLogResult(context.Background(),
		connect.NewRequest(&pmv1.GetDeviceLogResultRequest{QueryId: newID()}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.GetDeviceCompliance(context.Background(),
		connect.NewRequest(&pmv1.GetDeviceComplianceRequest{DeviceId: f.directID}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.GetDeviceCompliancePolicyStatus(context.Background(),
		connect.NewRequest(&pmv1.GetDeviceCompliancePolicyStatusRequest{DeviceId: f.directID}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.GetExecution(context.Background(),
		connect.NewRequest(&pmv1.GetExecutionRequest{Id: newID()}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.ListExecutions(context.Background(),
		connect.NewRequest(&pmv1.ListExecutionsRequest{}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestDeviceHandlers_AssignedAndScopedReads(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	assignedCtx := f.actor("GetDevice:assigned", "ListDevices:assigned")

	for _, id := range []string{f.directID, f.groupID} {
		resp, err := f.handlers.GetDevice(assignedCtx, connect.NewRequest(&pmv1.GetDeviceRequest{Id: id}))
		require.NoError(t, err)
		assert.Equal(t, id, resp.Msg.Device.Id)
	}
	_, err := f.handlers.GetDevice(assignedCtx, connect.NewRequest(&pmv1.GetDeviceRequest{Id: f.outsideID}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "assigned-only reads must not reveal other devices")

	list, err := f.handlers.ListDevices(assignedCtx, connect.NewRequest(&pmv1.ListDevicesRequest{}))
	require.NoError(t, err)
	require.Len(t, list.Msg.Devices, 2)
	ids := []string{list.Msg.Devices[0].Id, list.Msg.Devices[1].Id}
	sort.Strings(ids)
	want := []string{f.directID, f.groupID}
	sort.Strings(want)
	assert.Equal(t, want, ids)
	assert.Equal(t, int32(2), list.Msg.TotalCount)
	firstPage, err := f.handlers.ListDevices(assignedCtx, connect.NewRequest(&pmv1.ListDevicesRequest{PageSize: 1}))
	require.NoError(t, err)
	require.Len(t, firstPage.Msg.Devices, 1)
	require.NotEmpty(t, firstPage.Msg.NextPageToken)
	secondPage, err := f.handlers.ListDevices(assignedCtx, connect.NewRequest(&pmv1.ListDevicesRequest{
		PageSize: 1, PageToken: firstPage.Msg.NextPageToken,
	}))
	require.NoError(t, err)
	require.Len(t, secondPage.Msg.Devices, 1)
	assert.Empty(t, secondPage.Msg.NextPageToken)
	assert.NotEqual(t, firstPage.Msg.Devices[0].Id, secondPage.Msg.Devices[0].Id)
	assert.Equal(t, int32(2), secondPage.Msg.TotalCount)

	scopedCtx := auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser,
		Permissions: []string{"GetDevice", "ListDevices"},
		ScopedGrants: []auth.ScopedGrant{
			{Permission: "GetDevice", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: f.scopeGroup},
			{Permission: "ListDevices", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: f.scopeGroup},
		},
	})
	_, err = f.handlers.GetDevice(scopedCtx, connect.NewRequest(&pmv1.GetDeviceRequest{Id: f.outsideID}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "scope misses must not reveal existence")
	list, err = f.handlers.ListDevices(scopedCtx, connect.NewRequest(&pmv1.ListDevicesRequest{}))
	require.NoError(t, err)
	require.Len(t, list.Msg.Devices, 1)
	assert.Equal(t, f.groupID, list.Msg.Devices[0].Id)
	assert.NotNil(t, list.Msg.Devices[0].LastInventoryAt)
	assert.False(t, list.Msg.Devices[0].InventoryOverdue)
}

func TestDeviceHandlers_GetDeviceInventoryReadsDirectTables(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	ctx := auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser,
		Permissions: []string{"GetDeviceInventory"},
		ScopedGrants: []auth.ScopedGrant{{
			Permission: "GetDeviceInventory", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: f.scopeGroup,
		}},
	})

	response, err := f.handlers.GetDeviceInventory(ctx,
		connect.NewRequest(&pmv1.GetDeviceInventoryRequest{DeviceId: f.groupID}))
	require.NoError(t, err)
	require.Len(t, response.Msg.Tables, 2)
	assert.Equal(t, "os_version", response.Msg.Tables[0].TableName)
	require.Len(t, response.Msg.Tables[0].Rows, 1)
	assert.Equal(t, "Debian", response.Msg.Tables[0].Rows[0].Data["name"])
	assert.True(t, response.Msg.Tables[0].CollectedAt.AsTime().Equal(f.now.Add(-time.Hour)))
	assert.Equal(t, "system_info", response.Msg.Tables[1].TableName)

	filtered, err := f.handlers.GetDeviceInventory(ctx,
		connect.NewRequest(&pmv1.GetDeviceInventoryRequest{
			DeviceId: f.groupID, TableNames: []string{"system_info"},
		}))
	require.NoError(t, err)
	require.Len(t, filtered.Msg.Tables, 1)
	assert.Equal(t, "group", filtered.Msg.Tables[0].Rows[0].Data["hostname"])

	_, err = f.handlers.GetDeviceInventory(ctx,
		connect.NewRequest(&pmv1.GetDeviceInventoryRequest{DeviceId: f.outsideID}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "scope must not disclose the device")

	_, err = f.handlers.GetDeviceInventory(ctx,
		connect.NewRequest(&pmv1.GetDeviceInventoryRequest{
			DeviceId: f.groupID, TableNames: make([]string, 129),
		}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	assertSensitiveDeviceRead(t, f, powermanagev1connect.ControlServiceGetDeviceInventoryProcedure,
		"device_inventory", f.groupID)
}

func TestDeviceHandlers_GetDeviceInventoryRejectsInvalidStoredShape(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	_, err := f.raw.Exec(context.Background(),
		`UPDATE device_inventory SET rows = '{"not":"rows"}' WHERE device_id = $1`, f.groupID)
	require.NoError(t, err)

	_, err = f.handlers.GetDeviceInventory(f.actor("GetDeviceInventory"),
		connect.NewRequest(&pmv1.GetDeviceInventoryRequest{DeviceId: f.groupID}))
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err), "corrupt inventory must not look like an empty table")
}

func TestDeviceHandlers_GetOSQueryResultReadsDirectState(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	completedID, pendingID, staleID, outsideID := newID(), newID(), newID(), newID()
	for _, row := range []struct {
		id, deviceID string
		completed    bool
		createdAt    time.Time
		rows         string
	}{
		{completedID, f.groupID, true, f.now.Add(-time.Minute), `[{"package":"bash"}]`},
		{pendingID, f.groupID, false, f.now.Add(-time.Minute), `[]`},
		{staleID, f.groupID, false, f.now.Add(-6 * time.Minute), `[]`},
		{outsideID, f.outsideID, true, f.now.Add(-time.Minute), `[]`},
	} {
		_, err := f.raw.Exec(context.Background(), `
			INSERT INTO osquery_results
				(query_id, device_id, table_name, completed, success, rows, created_at)
			VALUES ($1, $2, 'packages', $3, $3, $4, $5)`,
			row.id, row.deviceID, row.completed, row.rows, row.createdAt)
		require.NoError(t, err)
	}
	ctx := auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser,
		Permissions: []string{"GetOSQueryResult"},
		ScopedGrants: []auth.ScopedGrant{{
			Permission: "GetOSQueryResult", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: f.scopeGroup,
		}},
	})

	completed, err := f.handlers.GetOSQueryResult(ctx,
		connect.NewRequest(&pmv1.GetOSQueryResultRequest{QueryId: completedID}))
	require.NoError(t, err)
	assert.True(t, completed.Msg.Completed)
	assert.True(t, completed.Msg.Success)
	require.Len(t, completed.Msg.Rows, 1)
	assert.Equal(t, "bash", completed.Msg.Rows[0].Data["package"])

	pending, err := f.handlers.GetOSQueryResult(ctx,
		connect.NewRequest(&pmv1.GetOSQueryResultRequest{QueryId: pendingID}))
	require.NoError(t, err)
	assert.False(t, pending.Msg.Completed)

	stale, err := f.handlers.GetOSQueryResult(ctx,
		connect.NewRequest(&pmv1.GetOSQueryResultRequest{QueryId: staleID}))
	require.NoError(t, err)
	assert.True(t, stale.Msg.Completed)
	assert.False(t, stale.Msg.Success)
	assert.Contains(t, stale.Msg.Error, "timed out")
	var storedCompleted bool
	require.NoError(t, f.raw.QueryRow(context.Background(),
		`SELECT completed FROM osquery_results WHERE query_id = $1`, staleID).Scan(&storedCompleted))
	assert.False(t, storedCompleted, "a read must not smuggle in an unaudited expiry mutation")

	_, err = f.handlers.GetOSQueryResult(ctx,
		connect.NewRequest(&pmv1.GetOSQueryResultRequest{QueryId: outsideID}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "scope must not disclose the result")
	_, err = f.handlers.GetOSQueryResult(ctx,
		connect.NewRequest(&pmv1.GetOSQueryResultRequest{QueryId: newID()}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	assertSensitiveDeviceRead(t, f, powermanagev1connect.ControlServiceGetOSQueryResultProcedure,
		"osquery_result", staleID)
}

func TestDeviceHandlers_GetOSQueryResultRejectsInvalidStoredShape(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	queryID := newID()
	_, err := f.raw.Exec(context.Background(), `
		INSERT INTO osquery_results
			(query_id, device_id, table_name, completed, success, rows, created_at)
		VALUES ($1, $2, 'packages', TRUE, TRUE, '{"not":"rows"}', $3)`, queryID, f.groupID, f.now)
	require.NoError(t, err)

	_, err = f.handlers.GetOSQueryResult(f.actor("GetOSQueryResult"),
		connect.NewRequest(&pmv1.GetOSQueryResultRequest{QueryId: queryID}))
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err), "corrupt rows must not look like an empty result")
}

func TestDeviceHandlers_GetDeviceLogResultReadsDirectState(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	completedID, staleID, outsideID := newID(), newID(), newID()
	for _, row := range []struct {
		id, deviceID string
		completed    bool
		createdAt    time.Time
		logs         string
	}{
		{completedID, f.groupID, true, f.now.Add(-time.Minute), "service started\n"},
		{staleID, f.groupID, false, f.now.Add(-6 * time.Minute), ""},
		{outsideID, f.outsideID, true, f.now.Add(-time.Minute), "hidden\n"},
	} {
		_, err := f.raw.Exec(context.Background(), `
			INSERT INTO log_query_results
				(query_id, device_id, completed, success, logs, created_at)
			VALUES ($1, $2, $3, $3, $4, $5)`,
			row.id, row.deviceID, row.completed, row.logs, row.createdAt)
		require.NoError(t, err)
	}
	ctx := auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser,
		Permissions: []string{"GetDeviceLogResult"},
		ScopedGrants: []auth.ScopedGrant{{
			Permission: "GetDeviceLogResult", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: f.scopeGroup,
		}},
	})

	completed, err := f.handlers.GetDeviceLogResult(ctx,
		connect.NewRequest(&pmv1.GetDeviceLogResultRequest{QueryId: completedID}))
	require.NoError(t, err)
	assert.True(t, completed.Msg.Completed)
	assert.True(t, completed.Msg.Success)
	assert.Equal(t, "service started\n", completed.Msg.Logs)

	stale, err := f.handlers.GetDeviceLogResult(ctx,
		connect.NewRequest(&pmv1.GetDeviceLogResultRequest{QueryId: staleID}))
	require.NoError(t, err)
	assert.True(t, stale.Msg.Completed)
	assert.False(t, stale.Msg.Success)
	assert.Empty(t, stale.Msg.Logs)
	assert.Contains(t, stale.Msg.Error, "timed out")
	var storedCompleted bool
	require.NoError(t, f.raw.QueryRow(context.Background(),
		`SELECT completed FROM log_query_results WHERE query_id = $1`, staleID).Scan(&storedCompleted))
	assert.False(t, storedCompleted, "a read must not smuggle in an unaudited expiry mutation")

	_, err = f.handlers.GetDeviceLogResult(ctx,
		connect.NewRequest(&pmv1.GetDeviceLogResultRequest{QueryId: outsideID}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "scope must not disclose the result")
	_, err = f.handlers.GetDeviceLogResult(ctx,
		connect.NewRequest(&pmv1.GetDeviceLogResultRequest{QueryId: newID()}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	assertSensitiveDeviceRead(t, f, powermanagev1connect.ControlServiceGetDeviceLogResultProcedure,
		"device_log_result", staleID)
}

func TestDeviceHandlers_GetDeviceComplianceReadsDirectState(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	policyID, graceActionID, failedActionID := newID(), newID(), newID()
	firstFailed := f.now.Add(-2 * time.Hour)
	_, err := f.raw.Exec(context.Background(), `
		UPDATE devices
		SET compliance_status = 2, compliance_checked_at = $2,
			compliance_total = 2, compliance_passing = 0
		WHERE id = $1`, f.groupID, f.now)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `
		INSERT INTO actions (id, name, action_type, params, created_by)
		VALUES
			($1, 'grace check', 1, '{}', $3),
			($2, 'failed check', 1, '{}', $3)`, graceActionID, failedActionID, f.actorID)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `
		INSERT INTO compliance_policies (id, name, created_by)
		VALUES ($1, 'baseline', $2)`, policyID, f.actorID)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `
		INSERT INTO compliance_policy_rules (policy_id, action_id, grace_period_hours)
		VALUES ($1, $2, 4), ($1, $3, 0)`, policyID, graceActionID, failedActionID)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `
		INSERT INTO compliance_results
			(device_id, action_id, compliant, detection_output, checked_at)
		VALUES
			($1, $2, FALSE, '{"exitCode":1,"stdout":"grace drift"}', $4),
			($1, $3, FALSE, '{"exitCode":2,"stderr":"failed drift"}', $4)`,
		f.groupID, graceActionID, failedActionID, f.now)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `
		INSERT INTO compliance_policy_evaluation
			(device_id, policy_id, action_id, compliant, first_failed_at, status, checked_at)
		VALUES
			($1, $2, $3, FALSE, $5, 3, $6),
			($1, $2, $4, FALSE, $5, 2, $6)`,
		f.groupID, policyID, graceActionID, failedActionID, firstFailed, f.now)
	require.NoError(t, err)
	ctx := f.actor("GetDeviceCompliance", "GetDeviceCompliancePolicyStatus")

	complianceResponse, err := f.handlers.GetDeviceCompliance(ctx,
		connect.NewRequest(&pmv1.GetDeviceComplianceRequest{DeviceId: f.groupID}))
	require.NoError(t, err)
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT, complianceResponse.Msg.Status)
	require.Len(t, complianceResponse.Msg.Checks, 2)
	checks := make(map[string]*pmv1.ComplianceCheckResult, len(complianceResponse.Msg.Checks))
	for _, check := range complianceResponse.Msg.Checks {
		checks[check.ActionId] = check
	}
	assert.Equal(t, int32(1), checks[graceActionID].DetectionOutput.ExitCode)
	assert.Equal(t, "failed drift", checks[failedActionID].DetectionOutput.Stderr)

	policyResponse, err := f.handlers.GetDeviceCompliancePolicyStatus(ctx,
		connect.NewRequest(&pmv1.GetDeviceCompliancePolicyStatusRequest{DeviceId: f.groupID}))
	require.NoError(t, err)
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT, policyResponse.Msg.OverallStatus)
	require.Len(t, policyResponse.Msg.Policies, 1)
	policy := policyResponse.Msg.Policies[0]
	assert.Equal(t, policyID, policy.PolicyId)
	assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT, policy.Status)
	require.Len(t, policy.Rules, 2)
	for _, rule := range policy.Rules {
		if rule.ActionId == graceActionID {
			assert.Equal(t, pmv1.ComplianceStatus_COMPLIANCE_STATUS_IN_GRACE_PERIOD, rule.Status)
			assert.True(t, rule.GraceExpiresAt.AsTime().Equal(firstFailed.Add(4*time.Hour)))
		}
	}
	assertSensitiveDeviceRead(t, f, powermanagev1connect.ControlServiceGetDeviceComplianceProcedure,
		"device_compliance", f.groupID)
	assertSensitiveDeviceRead(t, f, powermanagev1connect.ControlServiceGetDeviceCompliancePolicyStatusProcedure,
		"device_compliance_policy_status", f.groupID)

	_, err = f.raw.Exec(context.Background(), `
		UPDATE compliance_results SET detection_output = '{"unknown":"field"}'
		WHERE device_id = $1 AND action_id = $2`, f.groupID, graceActionID)
	require.NoError(t, err)
	_, err = f.handlers.GetDeviceCompliance(ctx,
		connect.NewRequest(&pmv1.GetDeviceComplianceRequest{DeviceId: f.groupID}))
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err), "invalid output must not be silently dropped")
}

func TestDeviceHandlers_ExecutionReadsUseDirectKeysetAndScope(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	actionID := newID()
	groupExecutionID, directExecutionID, outsideExecutionID := newID(), newID(), newID()
	_, err := f.raw.Exec(context.Background(), `
		INSERT INTO actions (id, name, action_type, params, created_by)
		VALUES ($1, 'catalog execution', 200, '{}', $2)`, actionID, f.actorID)
	require.NoError(t, err)
	for _, row := range []struct {
		id, deviceID, status string
		actionID             *string
		actionType           int32
		output               string
	}{
		{groupExecutionID, f.groupID, "success", &actionID, 200, `{"exitCode":0,"stdout":"done"}`},
		{directExecutionID, f.directID, "pending", nil, 500, ``},
		{outsideExecutionID, f.outsideID, "failed", &actionID, 200, `{"exitCode":1,"stderr":"hidden"}`},
	} {
		_, err := f.raw.Exec(context.Background(), `
			INSERT INTO executions
				(id, device_id, action_id, action_type, desired_state, status, output,
				 created_at, created_by_type, created_by_id)
			VALUES ($1, $2, $3, $4, 0, $5, $6, $7, 'user', $8)`,
			row.id, row.deviceID, row.actionID, row.actionType, row.status,
			nullJSON(row.output), f.now, f.actorID)
		require.NoError(t, err)
	}
	scoped := auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser,
		Permissions: []string{"GetExecution", "ListExecutions"},
		ScopedGrants: []auth.ScopedGrant{
			{Permission: "GetExecution", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: f.scopeGroup},
			{Permission: "ListExecutions", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: f.scopeGroup},
		},
	})

	got, err := f.handlers.GetExecution(scoped,
		connect.NewRequest(&pmv1.GetExecutionRequest{Id: groupExecutionID}))
	require.NoError(t, err)
	assert.Equal(t, "catalog execution", got.Msg.Execution.ActionName)
	assert.Equal(t, "done", got.Msg.Execution.Output.Stdout)
	_, err = f.handlers.GetExecution(scoped,
		connect.NewRequest(&pmv1.GetExecutionRequest{Id: outsideExecutionID}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "scope must not disclose the execution")

	listed, err := f.handlers.ListExecutions(scoped,
		connect.NewRequest(&pmv1.ListExecutionsRequest{}))
	require.NoError(t, err)
	require.Len(t, listed.Msg.Executions, 1)
	assert.Equal(t, groupExecutionID, listed.Msg.Executions[0].Id)
	assert.Equal(t, int32(1), listed.Msg.TotalCount)

	assigned := f.actor("GetExecution:assigned", "ListExecutions:assigned")
	first, err := f.handlers.ListExecutions(assigned,
		connect.NewRequest(&pmv1.ListExecutionsRequest{PageSize: 1}))
	require.NoError(t, err)
	require.Len(t, first.Msg.Executions, 1)
	assert.NotEmpty(t, first.Msg.NextPageToken)
	second, err := f.handlers.ListExecutions(assigned,
		connect.NewRequest(&pmv1.ListExecutionsRequest{PageSize: 1, PageToken: first.Msg.NextPageToken}))
	require.NoError(t, err)
	require.Len(t, second.Msg.Executions, 1)
	assert.Empty(t, second.Msg.NextPageToken)
	assert.NotEqual(t, first.Msg.Executions[0].Id, second.Msg.Executions[0].Id)
	assert.Equal(t, int32(2), second.Msg.TotalCount)

	searched, err := f.handlers.ListExecutions(assigned,
		connect.NewRequest(&pmv1.ListExecutionsRequest{
			Search: "catalog", TypeFilter: pmv1.ActionType_ACTION_TYPE_SHELL,
			StatusFilter: pmv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
		}))
	require.NoError(t, err)
	require.Len(t, searched.Msg.Executions, 1)
	assert.Equal(t, groupExecutionID, searched.Msg.Executions[0].Id)
	_, err = f.handlers.ListExecutions(assigned,
		connect.NewRequest(&pmv1.ListExecutionsRequest{StatusFilter: pmv1.ExecutionStatus(99)}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	assertSensitiveDeviceRead(t, f, powermanagev1connect.ControlServiceGetExecutionProcedure,
		"execution", groupExecutionID)
	operation, err := latestOperationFor(t, f.store, f.raw,
		powermanagev1connect.ControlServiceListExecutionsProcedure)
	require.NoError(t, err)
	assert.Equal(t, string(store.ClassSensitiveRead), operation.OperationClass)
	effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
	require.NoError(t, err)
	assert.Empty(t, effects, "a collection read has no fabricated resource effect")
}

func nullJSON(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func TestDeviceHandlers_SensitiveReadFailsClosedWhenEvidenceFails(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	_, err := f.raw.Exec(context.Background(), `
		ALTER TABLE audit_operations ADD CONSTRAINT reject_inventory_evidence
		CHECK (request_descriptor <> '/powermanage.v1.ControlService/GetDeviceInventory')`)
	require.NoError(t, err)

	_, err = f.handlers.GetDeviceInventory(f.actor("GetDeviceInventory"),
		connect.NewRequest(&pmv1.GetDeviceInventoryRequest{DeviceId: f.groupID}))
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
}

func TestDeviceHandlers_MutationsAreAuditedCRUD(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	ctx := f.actor(
		"SetDeviceLabel", "RemoveDeviceLabel", "AssignDevice", "UnassignDevice",
		"ListDeviceAssignees", "SetDeviceSyncInterval", "SetDeviceInventoryInterval", "DeleteDevice",
	)

	setLabel, err := f.handlers.SetDeviceLabel(ctx, connect.NewRequest(&pmv1.SetDeviceLabelRequest{
		Id: f.directID, Key: "env", Value: "prod",
	}))
	require.NoError(t, err)
	assert.Equal(t, "prod", setLabel.Msg.Device.Labels["env"])
	removedLabel, err := f.handlers.RemoveDeviceLabel(ctx, connect.NewRequest(&pmv1.RemoveDeviceLabelRequest{
		Id: f.directID, Key: "env",
	}))
	require.NoError(t, err)
	assert.NotContains(t, removedLabel.Msg.Device.Labels, "env")

	assigned, err := f.handlers.AssignDevice(ctx, connect.NewRequest(&pmv1.AssignDeviceRequest{
		DeviceId: f.directID,
		UserIds:  []string{f.userID, f.userID},
		GroupIds: []string{f.userGroup, f.userGroup},
	}))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{f.actorID, f.userID}, assigned.Msg.Device.AssignedUserIds)
	assert.Equal(t, []string{f.userGroup}, assigned.Msg.Device.AssignedGroupIds)

	assignees, err := f.handlers.ListDeviceAssignees(ctx, connect.NewRequest(&pmv1.ListDeviceAssigneesRequest{DeviceId: f.directID}))
	require.NoError(t, err)
	require.Len(t, assignees.Msg.Assignees, 3)

	_, err = f.handlers.UnassignDevice(ctx, connect.NewRequest(&pmv1.UnassignDeviceRequest{
		DeviceId: f.directID, UserId: f.userID, GroupId: f.userGroup,
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.UnassignDevice(ctx, connect.NewRequest(&pmv1.UnassignDeviceRequest{
		DeviceId: f.directID, UserId: f.userID,
	}))
	require.NoError(t, err)

	updated, err := f.handlers.SetDeviceSyncInterval(ctx, connect.NewRequest(&pmv1.SetDeviceSyncIntervalRequest{
		Id: f.directID, SyncIntervalMinutes: 60,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(60), updated.Msg.Device.SyncIntervalMinutes)
	updated, err = f.handlers.SetDeviceInventoryInterval(ctx, connect.NewRequest(&pmv1.SetDeviceInventoryIntervalRequest{
		Id: f.directID, InventoryIntervalMinutes: 1440,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(1440), updated.Msg.Device.InventoryIntervalMinutes)

	_, err = f.handlers.DeleteDevice(ctx, connect.NewRequest(&pmv1.DeleteDeviceRequest{Id: f.directID}))
	require.NoError(t, err)
	assert.Equal(t, []string{f.directID}, f.closed)
	revoked, err := store.NewRevocationChecker(f.store).IsRevoked(context.Background(), strings.Repeat("a", 64))
	require.NoError(t, err)
	assert.True(t, revoked)
	_, err = f.store.GetDevice(context.Background(), f.directID)
	assert.True(t, store.IsNotFound(err))

	for _, procedure := range device.MutationProcedures() {
		operation, err := latestOperationFor(t, f.store, f.raw, procedure)
		require.NoError(t, err, procedure)
		effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
		require.NoError(t, err, procedure)
		assert.NotEmpty(t, effects, procedure)
	}

	operation, err := latestOperationFor(t, f.store, f.raw, powermanagev1connect.ControlServiceDeleteDeviceProcedure)
	require.NoError(t, err)
	assert.Equal(t, "DeleteDevice", operation.AuthorizationDetail)
	effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 1)
	assert.Equal(t, f.directID, effects[0].ResourceID)
	assert.Equal(t, "DELETE", effects[0].Action)
}

func TestDeviceHandlers_DeleteRollsBackWhenRevocationFails(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	fingerprint := strings.Repeat("a", 64)
	_, err := f.raw.Exec(context.Background(), `
		ALTER TABLE revoked_certificates
		ADD CONSTRAINT reject_fixture_fingerprint CHECK (fingerprint <> repeat('a', 64))`)
	require.NoError(t, err)

	_, err = f.handlers.DeleteDevice(f.actor("DeleteDevice"), connect.NewRequest(&pmv1.DeleteDeviceRequest{Id: f.directID}))
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
	_, err = f.store.GetDevice(context.Background(), f.directID)
	require.NoError(t, err, "the device deletion must roll back with revocation")
	assert.Empty(t, f.closed, "an uncommitted revocation must not close the live stream")
	revoked, err := store.NewRevocationChecker(f.store).IsRevoked(context.Background(), fingerprint)
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestDeviceHandlers_MountsExactSurface(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	mounted := f.handlers.Mount(http.NewServeMux())
	want := []string{
		powermanagev1connect.ControlServiceListDevicesProcedure,
		powermanagev1connect.ControlServiceGetDeviceProcedure,
		powermanagev1connect.ControlServiceGetDeviceInventoryProcedure,
		powermanagev1connect.ControlServiceGetOSQueryResultProcedure,
		powermanagev1connect.ControlServiceGetDeviceLogResultProcedure,
		powermanagev1connect.ControlServiceGetDeviceComplianceProcedure,
		powermanagev1connect.ControlServiceGetDeviceCompliancePolicyStatusProcedure,
		powermanagev1connect.ControlServiceGetExecutionProcedure,
		powermanagev1connect.ControlServiceListExecutionsProcedure,
		powermanagev1connect.ControlServiceSetDeviceLabelProcedure,
		powermanagev1connect.ControlServiceRemoveDeviceLabelProcedure,
		powermanagev1connect.ControlServiceAssignDeviceProcedure,
		powermanagev1connect.ControlServiceUnassignDeviceProcedure,
		powermanagev1connect.ControlServiceListDeviceAssigneesProcedure,
		powermanagev1connect.ControlServiceSetDeviceSyncIntervalProcedure,
		powermanagev1connect.ControlServiceSetDeviceInventoryIntervalProcedure,
		powermanagev1connect.ControlServiceDeleteDeviceProcedure,
	}
	assert.Equal(t, want, mounted)
	assert.Equal(t, []string{
		powermanagev1connect.ControlServiceGetDeviceInventoryProcedure,
		powermanagev1connect.ControlServiceGetOSQueryResultProcedure,
		powermanagev1connect.ControlServiceGetDeviceLogResultProcedure,
		powermanagev1connect.ControlServiceGetDeviceComplianceProcedure,
		powermanagev1connect.ControlServiceGetDeviceCompliancePolicyStatusProcedure,
		powermanagev1connect.ControlServiceGetExecutionProcedure,
		powermanagev1connect.ControlServiceListExecutionsProcedure,
	}, device.SensitiveReadProcedures())
	classified := append(device.MutationProcedures(), device.ReadProcedures()...)
	classified = append(classified, device.SensitiveReadProcedures()...)
	assert.ElementsMatch(t, want, classified, "every mounted procedure must have exactly one audit class")
}

func assertSensitiveDeviceRead(
	t *testing.T,
	f *deviceHandlerFixture,
	procedure, resourceType, resourceID string,
) {
	t.Helper()
	operation, err := latestOperationFor(t, f.store, f.raw, procedure)
	require.NoError(t, err)
	assert.Equal(t, string(store.ClassSensitiveRead), operation.OperationClass)
	effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 1)
	assert.Equal(t, resourceType, effects[0].ResourceType)
	assert.Equal(t, resourceID, effects[0].ResourceID)
	assert.Equal(t, "READ", effects[0].Action)
}

func latestOperationFor(t *testing.T, st *store.Store, raw *pgxpool.Pool, procedure string) (store.AuditOperationRow, error) {
	t.Helper()
	var operationID string
	if err := raw.QueryRow(context.Background(), `
		SELECT operation_id
		FROM audit_operations
		WHERE request_descriptor = $1
		ORDER BY chain_seq DESC
		LIMIT 1`, procedure).Scan(&operationID); err != nil {
		return store.AuditOperationRow{}, err
	}
	return st.GetAuditOperation(context.Background(), operationID)
}
