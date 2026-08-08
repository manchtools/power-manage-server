package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/manchtools/power-manage/server/internal/testdb"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/connection"
	pmcrypto "github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/device"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/terminal"
)

type deviceHandlerFixture struct {
	t          *testing.T
	store      *store.Store
	raw        *testdb.DB
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
	encryptor  *pmcrypto.Encryptor
	sender     *fakeAgentSender
	tokens     *terminal.TokenStore
	sessions   *connection.TerminalSessionRegistry
	connected  map[string]bool
}

type fakeAgentSender struct {
	messages []*pmv1.ServerMessage
	err      error
}

func (s *fakeAgentSender) Send(_ string, message *pmv1.ServerMessage) error {
	s.messages = append(s.messages, message)
	return s.err
}

func newDeviceHandlerFixture(t *testing.T) *deviceHandlerFixture {
	t.Helper()
	st, raw := setupSQLite(t)
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	encryptor, err := pmcrypto.NewEncryptor(strings.Repeat("01", 32))
	require.NoError(t, err)
	f := &deviceHandlerFixture{
		t: t, store: st, raw: raw, now: now,
		actorID: newID(), directID: newID(), groupID: newID(), outsideID: newID(),
		userID: newID(), userGroup: newID(), scopeGroup: newID(),
		encryptor: encryptor, sender: &fakeAgentSender{},
		sessions: connection.NewTerminalSessionRegistry(), connected: make(map[string]bool),
	}
	f.tokens = terminal.NewTokenStore(terminal.NewMemoryBackend(func() time.Time { return now }),
		terminal.WithClock(func() time.Time { return now }))
	f.connected[f.directID], f.connected[f.groupID], f.connected[f.outsideID] = true, true, true
	fingerprint := strings.Repeat("a", 64)
	expires := now.Add(24 * time.Hour)
	_, err = st.WithAudit(context.Background(), mutationOp(), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		for id, email := range map[string]string{
			f.actorID: "actor@example.test",
			f.userID:  "subject@example.test",
		} {
			if _, err := tx.InsertUser(ctx, db.InsertUserParams{
				ProvisioningSource: store.UserProvisioningSourceSCIM,
				ID:                 id, Email: email, DisplayName: email, LinuxUsername: "test",
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
		Store:            st,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:              func() time.Time { return now },
		Decryptor:        encryptor,
		AgentSender:      f.sender,
		TerminalTokens:   f.tokens,
		TerminalSessions: f.sessions,
		TerminalURL:      "wss://control.example.test/terminal",
		IsConnected:      func(id string) bool { return f.connected[id] },
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
	_, err = f.handlers.CancelExecution(context.Background(),
		connect.NewRequest(&pmv1.CancelExecutionRequest{ExecutionId: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.ListLpsPasswords(context.Background(),
		connect.NewRequest(&pmv1.ListLpsPasswordsRequest{DeviceId: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.RevealLpsPassword(context.Background(),
		connect.NewRequest(&pmv1.RevealLpsPasswordRequest{Id: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.ListLuksKeys(context.Background(),
		connect.NewRequest(&pmv1.ListLuksKeysRequest{DeviceId: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.RevealLuksKey(context.Background(),
		connect.NewRequest(&pmv1.RevealLuksKeyRequest{Id: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.CreateLuksToken(context.Background(),
		connect.NewRequest(&pmv1.CreateLuksTokenRequest{DeviceId: "bad", ActionId: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.RevokeLuksDeviceKey(context.Background(),
		connect.NewRequest(&pmv1.RevokeLuksDeviceKeyRequest{DeviceId: "bad", ActionId: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.DispatchOSQuery(context.Background(),
		connect.NewRequest(&pmv1.DispatchOSQueryRequest{DeviceId: "bad", Table: "packages"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.QueryDeviceLogs(context.Background(),
		connect.NewRequest(&pmv1.QueryDeviceLogsRequest{DeviceId: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.RefreshDeviceInventory(context.Background(),
		connect.NewRequest(&pmv1.RefreshDeviceInventoryRequest{DeviceId: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.StartTerminal(context.Background(),
		connect.NewRequest(&pmv1.StartTerminalRequest{DeviceId: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.StopTerminal(context.Background(),
		connect.NewRequest(&pmv1.StopTerminalRequest{SessionId: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.TerminateTerminalSession(context.Background(),
		connect.NewRequest(&pmv1.TerminateTerminalSessionRequest{SessionId: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.ListActiveTerminalSessions(context.Background(),
		connect.NewRequest(&pmv1.ListActiveTerminalSessionsRequest{PageToken: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	_, err = f.handlers.DispatchOSQuery(context.Background(),
		connect.NewRequest(&pmv1.DispatchOSQueryRequest{DeviceId: f.directID}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "custom shape validation must precede authentication")

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
	_, err = f.handlers.CancelExecution(context.Background(),
		connect.NewRequest(&pmv1.CancelExecutionRequest{ExecutionId: newID()}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.ListLpsPasswords(context.Background(),
		connect.NewRequest(&pmv1.ListLpsPasswordsRequest{DeviceId: f.directID}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.RevealLpsPassword(context.Background(),
		connect.NewRequest(&pmv1.RevealLpsPasswordRequest{Id: newID()}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.ListLuksKeys(context.Background(),
		connect.NewRequest(&pmv1.ListLuksKeysRequest{DeviceId: f.directID}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.RevealLuksKey(context.Background(),
		connect.NewRequest(&pmv1.RevealLuksKeyRequest{Id: newID()}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.CreateLuksToken(context.Background(),
		connect.NewRequest(&pmv1.CreateLuksTokenRequest{DeviceId: f.directID, ActionId: newID()}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.RevokeLuksDeviceKey(context.Background(),
		connect.NewRequest(&pmv1.RevokeLuksDeviceKeyRequest{DeviceId: f.directID, ActionId: newID()}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.DispatchOSQuery(context.Background(),
		connect.NewRequest(&pmv1.DispatchOSQueryRequest{DeviceId: f.directID, Table: "packages"}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.QueryDeviceLogs(context.Background(),
		connect.NewRequest(&pmv1.QueryDeviceLogsRequest{DeviceId: f.directID}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.RefreshDeviceInventory(context.Background(),
		connect.NewRequest(&pmv1.RefreshDeviceInventoryRequest{DeviceId: f.directID}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.StartTerminal(context.Background(),
		connect.NewRequest(&pmv1.StartTerminalRequest{DeviceId: f.directID}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.StopTerminal(context.Background(),
		connect.NewRequest(&pmv1.StopTerminalRequest{SessionId: newID()}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.TerminateTerminalSession(context.Background(),
		connect.NewRequest(&pmv1.TerminateTerminalSessionRequest{SessionId: newID()}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.ListActiveTerminalSessions(context.Background(),
		connect.NewRequest(&pmv1.ListActiveTerminalSessionsRequest{}))
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

	complianceCtx := f.actor("GetDeviceCompliance:assigned", "GetDeviceCompliancePolicyStatus:assigned")
	for _, id := range []string{f.directID, f.groupID} {
		_, err = f.handlers.GetDeviceCompliance(complianceCtx,
			connect.NewRequest(&pmv1.GetDeviceComplianceRequest{DeviceId: id}))
		require.NoError(t, err)
		_, err = f.handlers.GetDeviceCompliancePolicyStatus(complianceCtx,
			connect.NewRequest(&pmv1.GetDeviceCompliancePolicyStatusRequest{DeviceId: id}))
		require.NoError(t, err)
	}
	_, err = f.handlers.GetDeviceCompliance(complianceCtx,
		connect.NewRequest(&pmv1.GetDeviceComplianceRequest{DeviceId: f.outsideID}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "assigned compliance must not reveal other devices")
	_, err = f.handlers.GetDeviceCompliancePolicyStatus(complianceCtx,
		connect.NewRequest(&pmv1.GetDeviceCompliancePolicyStatusRequest{DeviceId: f.outsideID}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "assigned policy status must not reveal other devices")

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
	f := newComplianceIngestFixture(t)
	firstFailed := f.now.Add(-2 * time.Hour)
	graceActionID := f.complianceAction(t, "grace check")
	failedActionID := f.complianceAction(t, "failed check")
	policyID := f.policy(t, "baseline", map[string]int32{graceActionID: 4, failedActionID: 0})
	f.report(t, f.groupID, graceActionID, pmv1.ExecutionStatus_EXECUTION_STATUS_FAILED, false,
		&pmv1.CommandOutput{ExitCode: 1, Stdout: "grace drift"}, firstFailed)
	f.report(t, f.groupID, failedActionID, pmv1.ExecutionStatus_EXECUTION_STATUS_FAILED, false,
		&pmv1.CommandOutput{ExitCode: 2, Stderr: "failed drift"}, firstFailed)
	ctx := f.ctx

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
	assertSensitiveDeviceRead(t, f.deviceHandlerFixture,
		powermanagev1connect.ControlServiceGetDeviceComplianceProcedure,
		"device_compliance", f.groupID)
	assertSensitiveDeviceRead(t, f.deviceHandlerFixture,
		powermanagev1connect.ControlServiceGetDeviceCompliancePolicyStatusProcedure,
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
		deliveryID := seedDelivery(t, f.raw, row.deviceID, f.now)
		_, err := f.raw.Exec(context.Background(), `
			INSERT INTO executions
				(id, delivery_id, device_id, action_id, action_type, desired_state, status, output,
				 created_at, created_by_type, created_by_id)
			VALUES ($1, $2, $3, $4, $5, 0, $6, $7, $8, 'user', $9)`,
			row.id, deliveryID, row.deviceID, row.actionID, row.actionType, row.status,
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

	global := f.actor("GetExecution", "ListExecutions")
	first, err := f.handlers.ListExecutions(global,
		connect.NewRequest(&pmv1.ListExecutionsRequest{PageSize: 2}))
	require.NoError(t, err)
	require.Len(t, first.Msg.Executions, 2)
	assert.NotEmpty(t, first.Msg.NextPageToken)
	second, err := f.handlers.ListExecutions(global,
		connect.NewRequest(&pmv1.ListExecutionsRequest{PageSize: 2, PageToken: first.Msg.NextPageToken}))
	require.NoError(t, err)
	require.Len(t, second.Msg.Executions, 1)
	assert.Empty(t, second.Msg.NextPageToken)
	assert.NotContains(t, []string{first.Msg.Executions[0].Id, first.Msg.Executions[1].Id}, second.Msg.Executions[0].Id)
	assert.Equal(t, int32(3), second.Msg.TotalCount)

	searched, err := f.handlers.ListExecutions(global,
		connect.NewRequest(&pmv1.ListExecutionsRequest{
			Search: "catalog", TypeFilter: pmv1.ActionType_ACTION_TYPE_SHELL,
			StatusFilter: pmv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
		}))
	require.NoError(t, err)
	require.Len(t, searched.Msg.Executions, 1)
	assert.Equal(t, groupExecutionID, searched.Msg.Executions[0].Id)
	_, err = f.handlers.ListExecutions(global,
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

func TestDeviceHandlers_CancelExecutionIsDirectAndIdempotent(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	pendingID, terminalID, rollbackID := newID(), newID(), newID()
	deliveryID := seedDelivery(t, f.raw, f.directID, f.now)
	for _, row := range []struct{ id, status string }{
		{pendingID, "pending"}, {terminalID, "success"}, {rollbackID, "scheduled"},
	} {
		_, err := f.raw.Exec(context.Background(), `
			INSERT INTO executions
				(id, delivery_id, device_id, action_type, desired_state, status, created_at, created_by_type, created_by_id)
			VALUES ($1, $2, $3, 200, 0, $4, $5, 'user', $6)`,
			row.id, deliveryID, f.directID, row.status, f.now, f.actorID)
		require.NoError(t, err)
	}
	ctx := f.actor("CancelExecution")

	cancelled, err := f.handlers.CancelExecution(ctx,
		connect.NewRequest(&pmv1.CancelExecutionRequest{ExecutionId: pendingID}))
	require.NoError(t, err)
	assert.Equal(t, pmv1.ExecutionStatus_EXECUTION_STATUS_CANCELLED, cancelled.Msg.Execution.Status)
	assert.NotNil(t, cancelled.Msg.Execution.CompletedAt)
	operation, err := latestOperationFor(t, f.store, f.raw,
		powermanagev1connect.ControlServiceCancelExecutionProcedure)
	require.NoError(t, err)
	effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 1)
	assert.Equal(t, "execution", effects[0].ResourceType)
	assert.Equal(t, pendingID, effects[0].ResourceID)
	assert.Equal(t, "CANCEL", effects[0].Action)

	unchanged, err := f.handlers.CancelExecution(ctx,
		connect.NewRequest(&pmv1.CancelExecutionRequest{ExecutionId: terminalID}))
	require.NoError(t, err)
	assert.Equal(t, pmv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS, unchanged.Msg.Execution.Status)
	operation, err = latestOperationFor(t, f.store, f.raw,
		powermanagev1connect.ControlServiceCancelExecutionProcedure)
	require.NoError(t, err)
	effects, err = f.store.ListAuditEffects(context.Background(), operation.OperationID)
	require.NoError(t, err)
	assert.Empty(t, effects, "an idempotent no-op has no fabricated state-change effect")

	rejectAuditOperation(t, f.raw, "/powermanage.v1.ControlService/CancelExecution")
	_, err = f.handlers.CancelExecution(ctx,
		connect.NewRequest(&pmv1.CancelExecutionRequest{ExecutionId: rollbackID}))
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
	rolledBack, err := f.store.GetExecution(context.Background(), rollbackID)
	require.NoError(t, err)
	assert.Equal(t, "scheduled", rolledBack.Status, "audit failure must roll the cancellation back")
}

func TestDeviceHandlers_SecretListsAreMetadataAndRevealsAreIndividuallyAudited(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	lpsActionID, luksActionID := newID(), newID()
	_, err := f.raw.Exec(context.Background(), `
		INSERT INTO actions (id, name, action_type, params, created_by) VALUES
			($1, 'Local admin', $2, '{}', $3),
			($4, 'Root disk', $5, '{}', $3)`,
		lpsActionID, int32(pmv1.ActionType_ACTION_TYPE_LPS), f.actorID,
		luksActionID, int32(pmv1.ActionType_ACTION_TYPE_ENCRYPTION))
	require.NoError(t, err)
	// The reveal handlers compute the at-rest AAD from the row's immutable id
	// (secret.ID), not from the username/device_path shared by every rotation
	// row. Generate the row ids first, then seal the CURRENT row's ciphertext
	// under its own id: only the revealed (current) row need open.
	lpsIDs := make([]string, 5)
	luksIDs := make([]string, 5)
	for i := range lpsIDs {
		lpsIDs[i], luksIDs[i] = newID(), newID()
	}
	password, err := f.encryptor.EncryptWithContext("local-secret",
		pmcrypto.SecretAADForRow(f.directID, lpsActionID, "lps", lpsIDs[0]))
	require.NoError(t, err)
	passphrase, err := f.encryptor.EncryptWithContext("disk-secret",
		pmcrypto.SecretAADForRow(f.directID, luksActionID, "luks", luksIDs[0]))
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		current := i == 0
		rotatedAt := f.now.Add(-time.Duration(i) * time.Hour)
		_, err = f.raw.Exec(context.Background(), `
			INSERT INTO lps_passwords
				(id, device_id, action_id, username, password, rotated_at, rotation_reason, is_current)
			VALUES ($1, $2, $3, 'localadmin', $4, $5, 'scheduled', $6)`,
			lpsIDs[i], f.directID, lpsActionID, password, rotatedAt, current)
		require.NoError(t, err)
		_, err = f.raw.Exec(context.Background(), `
			INSERT INTO luks_keys
				(id, device_id, action_id, device_path, passphrase, rotated_at,
				 rotation_reason, is_current, revocation_status)
			VALUES ($1, $2, $3, '/dev/vda', $4, $5, 'initial', $6, 'dispatched')`,
			luksIDs[i], f.directID, luksActionID, passphrase, rotatedAt, current)
		require.NoError(t, err)
	}

	lps, err := f.handlers.ListLpsPasswords(f.actor("ListLpsPasswords"),
		connect.NewRequest(&pmv1.ListLpsPasswordsRequest{DeviceId: f.directID}))
	require.NoError(t, err)
	require.Len(t, lps.Msg.Current, 1)
	require.Len(t, lps.Msg.History, 3)
	assert.Equal(t, lpsIDs[0], lps.Msg.Current[0].Id)
	assert.Equal(t, "direct", lps.Msg.History[0].DeviceHostname)
	assert.Equal(t, "Local admin", lps.Msg.Current[0].ActionName)

	luks, err := f.handlers.ListLuksKeys(f.actor("ListLuksKeys"),
		connect.NewRequest(&pmv1.ListLuksKeysRequest{DeviceId: f.directID}))
	require.NoError(t, err)
	require.Len(t, luks.Msg.Current, 1)
	require.Len(t, luks.Msg.History, 3)
	assert.Equal(t, luksIDs[0], luks.Msg.Current[0].Id)
	assert.Equal(t, "Root disk", luks.Msg.Current[0].ActionName)
	assert.Equal(t, pmv1.LuksRevocationStatus_LUKS_REVOCATION_STATUS_DISPATCHED,
		luks.Msg.Current[0].RevocationStatus)

	assertSensitiveDeviceRead(t, f,
		powermanagev1connect.ControlServiceListLpsPasswordsProcedure,
		"device_lps_passwords", f.directID)
	assertSensitiveDeviceRead(t, f,
		powermanagev1connect.ControlServiceListLuksKeysProcedure,
		"device_luks_keys", f.directID)

	_, err = f.handlers.RevealLpsPassword(f.actor("ListLpsPasswords"),
		connect.NewRequest(&pmv1.RevealLpsPasswordRequest{Id: lpsIDs[0]}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err),
		"metadata access must not imply plaintext access")
	lpsReveal, err := f.handlers.RevealLpsPassword(f.actor("RevealLpsPassword"),
		connect.NewRequest(&pmv1.RevealLpsPasswordRequest{Id: lpsIDs[0]}))
	require.NoError(t, err)
	assert.Equal(t, "local-secret", lpsReveal.Msg.Password)
	assertSecretReveal(t, f, powermanagev1connect.ControlServiceRevealLpsPasswordProcedure,
		"lps_password", lpsIDs[0], f.directID, lpsActionID)

	luksReveal, err := f.handlers.RevealLuksKey(f.actor("RevealLuksKey"),
		connect.NewRequest(&pmv1.RevealLuksKeyRequest{Id: luksIDs[0]}))
	require.NoError(t, err)
	assert.Equal(t, "disk-secret", luksReveal.Msg.Passphrase)
	assertSecretReveal(t, f, powermanagev1connect.ControlServiceRevealLuksKeyProcedure,
		"luks_key", luksIDs[0], f.directID, luksActionID)

	_, err = f.raw.Exec(context.Background(), `
		UPDATE lps_passwords SET password = 'enc:v1:not-base64'
		WHERE id = $1`, lpsIDs[0])
	require.NoError(t, err)
	_, err = f.handlers.ListLpsPasswords(f.actor("ListLpsPasswords"),
		connect.NewRequest(&pmv1.ListLpsPasswordsRequest{DeviceId: f.directID}))
	require.NoError(t, err, "metadata listing must not open ciphertext")
	_, err = f.handlers.RevealLpsPassword(f.actor("RevealLpsPassword"),
		connect.NewRequest(&pmv1.RevealLpsPasswordRequest{Id: lpsIDs[0]}))
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err), "corrupt ciphertext must fail closed")
	_, err = f.raw.Exec(context.Background(), `
		UPDATE lps_passwords SET password = 'legacy-plaintext'
		WHERE id = $1`, lpsIDs[0])
	require.NoError(t, err)
	_, err = f.handlers.RevealLpsPassword(f.actor("RevealLpsPassword"),
		connect.NewRequest(&pmv1.RevealLpsPasswordRequest{Id: lpsIDs[0]}))
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err), "plaintext storage must not get a compatibility path")

	rejectAuditOperation(t, f.raw, "/powermanage.v1.ControlService/RevealLuksKey")
	blocked, err := f.handlers.RevealLuksKey(f.actor("RevealLuksKey"),
		connect.NewRequest(&pmv1.RevealLuksKeyRequest{Id: luksIDs[1]}))
	assert.Nil(t, blocked)
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err),
		"audit persistence failure must prevent the plaintext response")
}

func TestDeviceHandlers_CreateLuksTokenIsOwnerOnlyHashedAndAudited(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	actionID := newID()
	_, err := f.raw.Exec(context.Background(), `
		INSERT INTO actions (id, name, action_type, params, created_by)
		VALUES ($1, 'Encryption', $2,
			'{"presharedKey":"enc:v1:stored","userPassphraseMinLength":24,"userPassphraseComplexity":"LPS_PASSWORD_COMPLEXITY_COMPLEX"}', $3)`,
		actionID, int32(pmv1.ActionType_ACTION_TYPE_ENCRYPTION), f.actorID)
	require.NoError(t, err)
	ctx := f.actor("CreateLuksToken")

	issued, err := f.handlers.CreateLuksToken(ctx, connect.NewRequest(&pmv1.CreateLuksTokenRequest{
		DeviceId: f.directID, ActionId: actionID,
	}))
	require.NoError(t, err)
	_, err = ulid.ParseStrict(issued.Msg.Token)
	require.NoError(t, err)
	assert.Contains(t, issued.Msg.Uri, issued.Msg.Token)
	// F2: the advertised command must NOT carry the token on argv —
	// /proc/<pid>/cmdline is world-readable and the client reads the passphrase
	// before it dials, so an argv token is exposed for the whole typing window
	// while being the sole authorization for a root daemon that writes LUKS
	// keyslots. It must not advertise sudo either: the sudoers rule was removed
	// precisely so this client is unprivileged, and an operator copying the
	// string back would reinstate the escalation.
	assert.NotContains(t, issued.Msg.CliCommand, issued.Msg.Token,
		"CliCommand must not put the one-time LUKS token on argv")
	assert.NotContains(t, issued.Msg.CliCommand, "sudo",
		"the LUKS passphrase client is unprivileged; advertising sudo reinstates the removed escalation")
	assert.Contains(t, issued.Msg.CliCommand, "luks set-passphrase",
		"CliCommand must still name the command the operator runs")
	hash := sha256.Sum256([]byte(issued.Msg.Token))
	var storedHash string
	var minLength, complexity int32
	var expiresAt time.Time
	err = f.raw.QueryRow(context.Background(), `
		SELECT token, min_length, complexity, expires_at
		FROM luks_tokens WHERE device_id = $1 AND action_id = $2`,
		f.directID, actionID).Scan(&storedHash, &minLength, &complexity, &expiresAt)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(hash[:]), storedHash)
	assert.NotEqual(t, issued.Msg.Token, storedHash)
	assert.Equal(t, int32(24), minLength)
	assert.Equal(t, int32(pmv1.LpsPasswordComplexity_LPS_PASSWORD_COMPLEXITY_COMPLEX), complexity)
	assert.True(t, expiresAt.Equal(f.now.Add(24*time.Hour)))
	operation, err := latestOperationFor(t, f.store, f.raw,
		powermanagev1connect.ControlServiceCreateLuksTokenProcedure)
	require.NoError(t, err)
	effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 1)
	assert.Equal(t, "luks_token", effects[0].ResourceType)
	assert.NotContains(t, strings.Join(effects[0].ChangedFields, ","), "token")

	_, err = f.handlers.CreateLuksToken(ctx, connect.NewRequest(&pmv1.CreateLuksTokenRequest{
		DeviceId: f.groupID, ActionId: actionID,
	}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err),
		"group-derived visibility is not direct device ownership")

	_, err = f.raw.Exec(context.Background(), `PRAGMA ignore_check_constraints = ON`)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `UPDATE actions SET params = '"corrupt"' WHERE id = $1`, actionID)
	require.NoError(t, err)
	_, err = f.handlers.CreateLuksToken(ctx, connect.NewRequest(&pmv1.CreateLuksTokenRequest{
		DeviceId: f.directID, ActionId: actionID,
	}))
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err), "corrupt policy must not fall back")
	_, err = f.raw.Exec(context.Background(), `UPDATE actions SET params = '{}' WHERE id = $1`, actionID)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `PRAGMA ignore_check_constraints = OFF`)
	require.NoError(t, err)

	rejectAuditOperation(t, f.raw, "/powermanage.v1.ControlService/CreateLuksToken")
	_, err = f.handlers.CreateLuksToken(ctx, connect.NewRequest(&pmv1.CreateLuksTokenRequest{
		DeviceId: f.directID, ActionId: actionID,
	}))
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
	var tokenCount int
	err = f.raw.QueryRow(context.Background(), `
		SELECT COUNT(*) FROM luks_tokens WHERE device_id = $1 AND action_id = $2`,
		f.directID, actionID).Scan(&tokenCount)
	require.NoError(t, err)
	assert.Equal(t, 1, tokenCount, "audit failure must roll the token insert back")
}

func TestDeviceHandlers_RevokeLuksDeviceKeyUsesDirectMTLSStream(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	actionID := newID()
	ctx := f.actor("RevokeLuksDeviceKey")

	_, err := f.handlers.RevokeLuksDeviceKey(f.actor(), connect.NewRequest(&pmv1.RevokeLuksDeviceKeyRequest{
		DeviceId: f.directID, ActionId: actionID,
	}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	_, err = f.handlers.RevokeLuksDeviceKey(ctx, connect.NewRequest(&pmv1.RevokeLuksDeviceKeyRequest{
		DeviceId: f.directID, ActionId: actionID,
	}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	seedCurrentLuksKeys(t, f, actionID, 2)
	_, err = f.handlers.RevokeLuksDeviceKey(ctx, connect.NewRequest(&pmv1.RevokeLuksDeviceKeyRequest{
		DeviceId: f.directID, ActionId: actionID,
	}))
	require.NoError(t, err)
	require.Len(t, f.sender.messages, 1)
	message := f.sender.messages[0]
	_, err = ulid.ParseStrict(message.Id)
	require.NoError(t, err)
	require.NotNil(t, message.GetRevokeLuksDeviceKey())
	assert.Equal(t, actionID, message.GetRevokeLuksDeviceKey().ActionId)

	var dispatched int
	err = f.raw.QueryRow(context.Background(), `
		SELECT count(*) FROM luks_keys
		WHERE device_id = $1 AND action_id = $2 AND revocation_status = 'dispatched'`,
		f.directID, actionID).Scan(&dispatched)
	require.NoError(t, err)
	assert.Equal(t, 2, dispatched)
	operation, err := latestOperationFor(t, f.store, f.raw,
		powermanagev1connect.ControlServiceRevokeLuksDeviceKeyProcedure)
	require.NoError(t, err)
	effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 1)
	assert.Equal(t, "luks_key_action", effects[0].ResourceType)
	assert.Equal(t, actionID, effects[0].ResourceID)
	assert.Equal(t, int64(2), *effects[0].AfterCount)

	_, err = f.handlers.RevokeLuksDeviceKey(ctx, connect.NewRequest(&pmv1.RevokeLuksDeviceKeyRequest{
		DeviceId: f.directID, ActionId: actionID,
	}))
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
	assert.Len(t, f.sender.messages, 1, "a pending revocation must not be sent twice")

	require.NoError(t, f.handlers.CompleteLuksKeyRevocation(context.Background(), f.directID,
		&pmv1.RevokeLuksDeviceKeyResult{ActionId: actionID, Success: true}))
	var succeeded int
	err = f.raw.QueryRow(context.Background(), `
		SELECT count(*) FROM luks_keys
		WHERE device_id = $1 AND action_id = $2 AND revocation_status = 'success'
		  AND revocation_error IS NULL`, f.directID, actionID).Scan(&succeeded)
	require.NoError(t, err)
	assert.Equal(t, 2, succeeded)

	// A replay is absorbed by the conditional update and preserved as rejected
	// evidence instead of changing the terminal state again.
	require.NoError(t, f.handlers.CompleteLuksKeyRevocation(context.Background(), f.directID,
		&pmv1.RevokeLuksDeviceKeyResult{ActionId: actionID, Success: false, Error: "stale"}))
	resultOperation, err := latestOperationFor(t, f.store, f.raw,
		"powermanage.v1.AgentService.Stream/RevokeLuksDeviceKeyResult")
	require.NoError(t, err)
	resultEffects, err := f.store.ListAuditEffects(context.Background(), resultOperation.OperationID)
	require.NoError(t, err)
	require.Len(t, resultEffects, 1)
	assert.Equal(t, string(store.EffectRejected), resultEffects[0].Outcome)
}

func TestDeviceHandlers_RevokeLuksDeviceKeyRecordsUnavailableDevice(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	actionID := newID()
	seedCurrentLuksKeys(t, f, actionID, 1)
	f.sender.err = errors.New("agent not connected")

	_, err := f.handlers.RevokeLuksDeviceKey(f.actor("RevokeLuksDeviceKey"),
		connect.NewRequest(&pmv1.RevokeLuksDeviceKeyRequest{DeviceId: f.directID, ActionId: actionID}))
	assert.Equal(t, connect.CodeUnavailable, connect.CodeOf(err))
	var status string
	var detail *string
	err = f.raw.QueryRow(context.Background(), `
		SELECT revocation_status, revocation_error FROM luks_keys
		WHERE device_id = $1 AND action_id = $2 AND is_current = TRUE`,
		f.directID, actionID).Scan(&status, &detail)
	require.NoError(t, err)
	assert.Equal(t, "failed", status)
	require.NotNil(t, detail)
	assert.Equal(t, "device unavailable", *detail, "transport internals must not enter durable state")
	operation, err := latestOperationFor(t, f.store, f.raw,
		powermanagev1connect.ControlServiceRevokeLuksDeviceKeyProcedure)
	require.NoError(t, err)
	effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 2)
	assert.Equal(t, string(store.EffectApplied), effects[0].Outcome)
	assert.Equal(t, string(store.EffectFailed), effects[1].Outcome)
}

func TestDeviceHandlers_RevokeLuksDeviceKeyAuditFailurePreventsSend(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	actionID := newID()
	seedCurrentLuksKeys(t, f, actionID, 1)
	rejectAuditOperation(t, f.raw, "/powermanage.v1.ControlService/RevokeLuksDeviceKey")

	_, err := f.handlers.RevokeLuksDeviceKey(f.actor("RevokeLuksDeviceKey"),
		connect.NewRequest(&pmv1.RevokeLuksDeviceKeyRequest{DeviceId: f.directID, ActionId: actionID}))
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
	assert.Empty(t, f.sender.messages, "the irreversible command must not leave before its audit commits")
	var status *string
	err = f.raw.QueryRow(context.Background(), `
		SELECT revocation_status FROM luks_keys
		WHERE device_id = $1 AND action_id = $2 AND is_current = TRUE`,
		f.directID, actionID).Scan(&status)
	require.NoError(t, err)
	assert.Nil(t, status, "the state mutation must roll back with failed audit evidence")
}

func seedCurrentLuksKeys(t *testing.T, f *deviceHandlerFixture, actionID string, count int) {
	t.Helper()
	_, err := f.raw.Exec(context.Background(), `
		INSERT INTO actions (id, name, action_type, params, created_by)
		VALUES ($1, 'Encryption', $2, '{}', $3)
		ON CONFLICT (id) DO NOTHING`,
		actionID, int32(pmv1.ActionType_ACTION_TYPE_ENCRYPTION), f.actorID)
	require.NoError(t, err)
	for i := 0; i < count; i++ {
		_, err = f.raw.Exec(context.Background(), `
			INSERT INTO luks_keys
				(id, device_id, action_id, device_path, passphrase, rotated_at, rotation_reason, is_current)
			VALUES ($1, $2, $3, $4, 'enc:v1:test', $5, 'scheduled', TRUE)`,
			newID(), f.directID, actionID, fmt.Sprintf("/dev/test%d", i), f.now)
		require.NoError(t, err)
	}
}

func TestDeviceHandlers_InstantQueriesUseDirectStreamAndSQLiteResults(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	ctx := f.actor("DispatchOSQuery", "QueryDeviceLogs", "RefreshDeviceInventory")

	osquery, err := f.handlers.DispatchOSQuery(ctx, connect.NewRequest(&pmv1.DispatchOSQueryRequest{
		DeviceId: f.directID, Table: "packages", Columns: []string{"name"}, Limit: 25,
	}))
	require.NoError(t, err)
	require.Len(t, f.sender.messages, 1)
	queryFrame := f.sender.messages[0]
	assert.Equal(t, osquery.Msg.QueryId, queryFrame.Id)
	require.NotNil(t, queryFrame.GetQuery())
	assert.Equal(t, "packages", queryFrame.GetQuery().Table)
	assert.Equal(t, []string{"name"}, queryFrame.GetQuery().Columns)
	var osCompleted, osSuccess bool
	var osTable string
	err = f.raw.QueryRow(context.Background(), `
		SELECT table_name, completed, success FROM osquery_results WHERE query_id = $1`,
		osquery.Msg.QueryId).Scan(&osTable, &osCompleted, &osSuccess)
	require.NoError(t, err)
	assert.Equal(t, "packages", osTable)
	assert.False(t, osCompleted)
	assert.False(t, osSuccess)

	logs, err := f.handlers.QueryDeviceLogs(ctx, connect.NewRequest(&pmv1.QueryDeviceLogsRequest{
		DeviceId: f.directID, Lines: 100, Unit: "sshd.service", Priority: "warning",
	}))
	require.NoError(t, err)
	require.Len(t, f.sender.messages, 2)
	logFrame := f.sender.messages[1]
	assert.Equal(t, logs.Msg.QueryId, logFrame.Id)
	require.NotNil(t, logFrame.GetLogQuery())
	assert.Equal(t, "sshd.service", logFrame.GetLogQuery().Unit)
	var logCompleted bool
	require.NoError(t, f.raw.QueryRow(context.Background(), `
		SELECT completed FROM log_query_results WHERE query_id = $1`, logs.Msg.QueryId).Scan(&logCompleted))
	assert.False(t, logCompleted)

	_, err = f.handlers.RefreshDeviceInventory(ctx,
		connect.NewRequest(&pmv1.RefreshDeviceInventoryRequest{DeviceId: f.directID}))
	require.NoError(t, err)
	require.Len(t, f.sender.messages, 3)
	refreshFrame := f.sender.messages[2]
	require.NotNil(t, refreshFrame.GetRequestInventory())
	assert.Equal(t, refreshFrame.Id, refreshFrame.GetRequestInventory().QueryId)

	for _, procedure := range []string{
		powermanagev1connect.ControlServiceDispatchOSQueryProcedure,
		powermanagev1connect.ControlServiceQueryDeviceLogsProcedure,
		powermanagev1connect.ControlServiceRefreshDeviceInventoryProcedure,
	} {
		operation, err := latestOperationFor(t, f.store, f.raw, procedure)
		require.NoError(t, err, procedure)
		effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
		require.NoError(t, err, procedure)
		assert.NotEmpty(t, effects, procedure)
	}

	_, err = f.handlers.DispatchOSQuery(ctx, connect.NewRequest(&pmv1.DispatchOSQueryRequest{
		DeviceId: f.directID, Table: "packages", RawSql: "select 1",
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestDeviceHandlers_InstantQuerySendFailureIsTerminalAndGeneric(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	f.sender.err = errors.New("write tcp 10.0.0.1: secret transport detail")
	ctx := f.actor("DispatchOSQuery", "QueryDeviceLogs", "RefreshDeviceInventory")

	_, err := f.handlers.DispatchOSQuery(ctx, connect.NewRequest(&pmv1.DispatchOSQueryRequest{
		DeviceId: f.directID, RawSql: "select version from os_version",
	}))
	assert.Equal(t, connect.CodeUnavailable, connect.CodeOf(err))
	require.Len(t, f.sender.messages, 1)
	osID := f.sender.messages[0].GetQuery().QueryId
	var completed, success bool
	var storedError, tableName string
	err = f.raw.QueryRow(context.Background(), `
		SELECT completed, success, error, table_name FROM osquery_results WHERE query_id = $1`, osID).
		Scan(&completed, &success, &storedError, &tableName)
	require.NoError(t, err)
	assert.True(t, completed)
	assert.False(t, success)
	assert.Equal(t, "device unavailable", storedError)
	assert.Equal(t, "raw_sql", tableName)

	_, err = f.handlers.QueryDeviceLogs(ctx, connect.NewRequest(&pmv1.QueryDeviceLogsRequest{
		DeviceId: f.directID,
	}))
	assert.Equal(t, connect.CodeUnavailable, connect.CodeOf(err))
	require.Len(t, f.sender.messages, 2)
	logID := f.sender.messages[1].GetLogQuery().QueryId
	err = f.raw.QueryRow(context.Background(), `
		SELECT completed, success, error FROM log_query_results WHERE query_id = $1`, logID).
		Scan(&completed, &success, &storedError)
	require.NoError(t, err)
	assert.True(t, completed)
	assert.False(t, success)
	assert.Equal(t, "device unavailable", storedError)

	_, err = f.handlers.RefreshDeviceInventory(ctx,
		connect.NewRequest(&pmv1.RefreshDeviceInventoryRequest{DeviceId: f.directID}))
	assert.Equal(t, connect.CodeUnavailable, connect.CodeOf(err))
	refreshOperation, err := latestOperationFor(t, f.store, f.raw,
		powermanagev1connect.ControlServiceRefreshDeviceInventoryProcedure)
	require.NoError(t, err)
	refreshEffects, err := f.store.ListAuditEffects(context.Background(), refreshOperation.OperationID)
	require.NoError(t, err)
	require.Len(t, refreshEffects, 2)
	assert.Equal(t, string(store.EffectFailed), refreshEffects[1].Outcome)
}

func TestDeviceHandlers_AgentQueryResultsAndInventoryCommitDirectly(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	ctx := f.actor("DispatchOSQuery", "QueryDeviceLogs")
	osquery, err := f.handlers.DispatchOSQuery(ctx, connect.NewRequest(&pmv1.DispatchOSQueryRequest{
		DeviceId: f.directID, Table: "packages",
	}))
	require.NoError(t, err)
	logs, err := f.handlers.QueryDeviceLogs(ctx, connect.NewRequest(&pmv1.QueryDeviceLogsRequest{
		DeviceId: f.directID, Lines: 10,
	}))
	require.NoError(t, err)

	// A result from another authenticated device cannot claim this query.
	require.NoError(t, f.handlers.CompleteOSQueryResult(context.Background(), f.outsideID,
		&pmv1.OSQueryResult{QueryId: osquery.Msg.QueryId, Success: true}))
	var completed bool
	require.NoError(t, f.raw.QueryRow(context.Background(), `
		SELECT completed FROM osquery_results WHERE query_id = $1`, osquery.Msg.QueryId).Scan(&completed))
	assert.False(t, completed)

	require.NoError(t, f.handlers.CompleteOSQueryResult(context.Background(), f.directID,
		&pmv1.OSQueryResult{
			QueryId: osquery.Msg.QueryId, Success: true,
			Rows: []*pmv1.OSQueryRow{{Data: map[string]string{"name": "bash"}}},
		}))
	var rowsJSON []byte
	var success bool
	require.NoError(t, f.raw.QueryRow(context.Background(), `
		SELECT completed, success, rows FROM osquery_results WHERE query_id = $1`, osquery.Msg.QueryId).
		Scan(&completed, &success, &rowsJSON))
	assert.True(t, completed)
	assert.True(t, success)
	assert.JSONEq(t, `[{"name":"bash"}]`, string(rowsJSON))

	require.NoError(t, f.handlers.CompleteLogQueryResult(context.Background(), f.directID,
		&pmv1.LogQueryResult{QueryId: logs.Msg.QueryId, Success: true, Logs: "service started\n"}))
	var storedLogs string
	require.NoError(t, f.raw.QueryRow(context.Background(), `
		SELECT completed, success, logs FROM log_query_results WHERE query_id = $1`, logs.Msg.QueryId).
		Scan(&completed, &success, &storedLogs))
	assert.True(t, completed)
	assert.True(t, success)
	assert.Equal(t, "service started\n", storedLogs)

	require.NoError(t, f.handlers.StoreDeviceInventory(context.Background(), f.directID,
		&pmv1.DeviceInventory{Tables: []*pmv1.InventoryTable{
			{TableName: "os_version", Rows: []*pmv1.OSQueryRow{{Data: map[string]string{"name": "Debian"}}}},
			{TableName: "system_info", Rows: []*pmv1.OSQueryRow{{Data: map[string]string{"hostname": "direct"}}}},
		}}))
	var inventoryCount int
	require.NoError(t, f.raw.QueryRow(context.Background(), `
		SELECT count(*) FROM device_inventory WHERE device_id = $1 AND collected_at = $2`,
		f.directID, f.now).Scan(&inventoryCount))
	assert.Equal(t, 2, inventoryCount)

	err = f.handlers.StoreDeviceInventory(context.Background(), f.directID,
		&pmv1.DeviceInventory{Tables: []*pmv1.InventoryTable{
			{TableName: "os_version"}, {TableName: "os_version"},
		}})
	assert.Error(t, err, "duplicate table names must not create order-dependent state")
}

func TestDeviceHandlers_OSQueryAuditFailurePreventsSendAndPendingRow(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	rejectAuditOperation(t, f.raw, "/powermanage.v1.ControlService/DispatchOSQuery")
	_, err := f.handlers.DispatchOSQuery(f.actor("DispatchOSQuery"),
		connect.NewRequest(&pmv1.DispatchOSQueryRequest{DeviceId: f.directID, Table: "packages"}))
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
	assert.Empty(t, f.sender.messages)
	var count int
	require.NoError(t, f.raw.QueryRow(context.Background(), `SELECT count(*) FROM osquery_results`).Scan(&count))
	assert.Zero(t, count)
}

func TestDeviceHandlers_TerminalLifecycleUsesInProcessSessionTruth(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	startCtx := f.actor("StartTerminal")

	_, err := f.handlers.StartTerminal(f.actor(), connect.NewRequest(&pmv1.StartTerminalRequest{
		DeviceId: f.directID,
	}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	f.connected[f.directID] = false
	_, err = f.handlers.StartTerminal(startCtx, connect.NewRequest(&pmv1.StartTerminalRequest{
		DeviceId: f.directID,
	}))
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
	f.connected[f.directID] = true

	started, err := f.handlers.StartTerminal(startCtx, connect.NewRequest(&pmv1.StartTerminalRequest{
		DeviceId: f.directID,
	}))
	require.NoError(t, err)
	assert.Equal(t, "wss://control.example.test/terminal", started.Msg.TerminalUrl)
	assert.Equal(t, "pm-tty-test", started.Msg.TtyUser)
	assert.Empty(t, f.sender.messages, "the PTY starts only after the browser redeems its token")
	stored, err := f.store.GetOpenTerminalSession(context.Background(), started.Msg.SessionId)
	require.NoError(t, err)
	assert.Equal(t, int32(80), stored.Cols)
	assert.Equal(t, int32(24), stored.Rows)

	validated, err := f.tokens.Validate(context.Background(), started.Msg.SessionId, started.Msg.SessionToken)
	require.NoError(t, err)
	assert.Equal(t, f.directID, validated.DeviceID)
	_, err = f.tokens.Validate(context.Background(), started.Msg.SessionId, started.Msg.SessionToken)
	assert.ErrorIs(t, err, terminal.ErrTokenNotFound, "the browser bearer must be single-use")
	f.sessions.Register(connection.NewTerminalSession(
		started.Msg.SessionId, validated.DeviceID, validated.UserID, validated.TtyUser,
		validated.Cols, validated.Rows,
	))

	listed, err := f.handlers.ListActiveTerminalSessions(f.actor("ListActiveTerminalSessions"),
		connect.NewRequest(&pmv1.ListActiveTerminalSessionsRequest{}))
	require.NoError(t, err)
	require.Len(t, listed.Msg.Sessions, 1)
	assert.Equal(t, started.Msg.SessionId, listed.Msg.Sessions[0].SessionId)
	assert.Equal(t, "actor@example.test", listed.Msg.Sessions[0].UserEmail)
	assert.Equal(t, "direct", listed.Msg.Sessions[0].DeviceHostname)
	assert.Equal(t, int32(1), listed.Msg.TotalCount)
	operation, err := latestOperationFor(t, f.store, f.raw,
		powermanagev1connect.ControlServiceListActiveTerminalSessionsProcedure)
	require.NoError(t, err)
	assert.Equal(t, string(store.ClassSensitiveRead), operation.OperationClass)

	nonOwner := auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.userID, Kind: auth.PrincipalUser, Permissions: []string{"StopTerminal"},
	})
	_, err = f.handlers.StopTerminal(nonOwner,
		connect.NewRequest(&pmv1.StopTerminalRequest{SessionId: started.Msg.SessionId}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	_, err = f.handlers.StopTerminal(f.actor("StopTerminal"),
		connect.NewRequest(&pmv1.StopTerminalRequest{SessionId: started.Msg.SessionId}))
	require.NoError(t, err)
	require.Len(t, f.sender.messages, 1)
	require.NotNil(t, f.sender.messages[0].GetTerminalStop())
	assert.Equal(t, started.Msg.SessionId, f.sender.messages[0].GetTerminalStop().SessionId)
	assert.Zero(t, f.sessions.Count())
	_, err = f.store.GetOpenTerminalSession(context.Background(), started.Msg.SessionId)
	assert.True(t, store.IsNotFound(err))

	_, err = f.handlers.StopTerminal(f.actor("StopTerminal"),
		connect.NewRequest(&pmv1.StopTerminalRequest{SessionId: started.Msg.SessionId}))
	require.NoError(t, err)
	assert.Len(t, f.sender.messages, 1, "the idempotent replay must not send another frame")
}

func TestDeviceHandlers_TerminalListFiltersScopesAndPagesLiveRegistry(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	startCtx := f.actor("StartTerminal")
	ids := make([]string, 0, 3)
	for _, deviceID := range []string{f.directID, f.groupID, f.outsideID} {
		started, err := f.handlers.StartTerminal(startCtx,
			connect.NewRequest(&pmv1.StartTerminalRequest{DeviceId: deviceID, Cols: 120, Rows: 40}))
		require.NoError(t, err)
		ids = append(ids, started.Msg.SessionId)
		f.sessions.Register(connection.NewTerminalSession(
			started.Msg.SessionId, deviceID, f.actorID, started.Msg.TtyUser, 120, 40,
		))
	}

	ctx := f.actor("ListActiveTerminalSessions")
	page1, err := f.handlers.ListActiveTerminalSessions(ctx,
		connect.NewRequest(&pmv1.ListActiveTerminalSessionsRequest{PageSize: 1}))
	require.NoError(t, err)
	require.Len(t, page1.Msg.Sessions, 1)
	assert.Equal(t, int32(3), page1.Msg.TotalCount)
	assert.NotEmpty(t, page1.Msg.NextPageToken)
	page2, err := f.handlers.ListActiveTerminalSessions(ctx,
		connect.NewRequest(&pmv1.ListActiveTerminalSessionsRequest{
			PageSize: 1, PageToken: page1.Msg.NextPageToken,
		}))
	require.NoError(t, err)
	require.Len(t, page2.Msg.Sessions, 1)
	assert.NotEqual(t, page1.Msg.Sessions[0].SessionId, page2.Msg.Sessions[0].SessionId)

	filtered, err := f.handlers.ListActiveTerminalSessions(ctx,
		connect.NewRequest(&pmv1.ListActiveTerminalSessionsRequest{DeviceId: f.directID}))
	require.NoError(t, err)
	require.Len(t, filtered.Msg.Sessions, 1)
	assert.Equal(t, f.directID, filtered.Msg.Sessions[0].DeviceId)

	scoped := auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser,
		Permissions: []string{"ListActiveTerminalSessions"},
		ScopedGrants: []auth.ScopedGrant{{
			Permission: "ListActiveTerminalSessions", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: f.scopeGroup,
		}},
	})
	scopedList, err := f.handlers.ListActiveTerminalSessions(scoped,
		connect.NewRequest(&pmv1.ListActiveTerminalSessionsRequest{}))
	require.NoError(t, err)
	require.Len(t, scopedList.Msg.Sessions, 1)
	assert.Equal(t, f.groupID, scopedList.Msg.Sessions[0].DeviceId)
	assert.Equal(t, int32(1), scopedList.Msg.TotalCount)
	assert.Len(t, ids, 3)
}

func TestDeviceHandlers_StartTerminalAppliesScopeBeforeExistence(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	ctx := auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser,
		Permissions: []string{"StartTerminal"},
		ScopedGrants: []auth.ScopedGrant{{
			Permission: "StartTerminal", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: f.scopeGroup,
		}},
	})
	_, err := f.handlers.StartTerminal(ctx,
		connect.NewRequest(&pmv1.StartTerminalRequest{DeviceId: f.groupID}))
	require.NoError(t, err)
	_, err = f.handlers.StartTerminal(ctx,
		connect.NewRequest(&pmv1.StartTerminalRequest{DeviceId: f.outsideID}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "scope misses must not disclose device existence")
	_, err = f.handlers.StartTerminal(ctx,
		connect.NewRequest(&pmv1.StartTerminalRequest{DeviceId: newID()}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "unknown and out-of-scope devices must look alike")
}

func TestDeviceHandlers_TerminateTerminalSurfacesSendFailureThenCommitsRetry(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	started, err := f.handlers.StartTerminal(f.actor("StartTerminal"),
		connect.NewRequest(&pmv1.StartTerminalRequest{DeviceId: f.directID}))
	require.NoError(t, err)
	_, err = f.tokens.Validate(context.Background(), started.Msg.SessionId, started.Msg.SessionToken)
	require.NoError(t, err)
	f.sessions.Register(connection.NewTerminalSession(
		started.Msg.SessionId, f.directID, f.actorID, started.Msg.TtyUser, 80, 24,
	))
	f.sender.err = errors.New("agent disconnected")
	_, err = f.handlers.TerminateTerminalSession(f.actor("TerminateTerminalSession"),
		connect.NewRequest(&pmv1.TerminateTerminalSessionRequest{
			SessionId: started.Msg.SessionId, Reason: "incident response",
		}))
	assert.Equal(t, connect.CodeUnavailable, connect.CodeOf(err))
	_, err = f.store.GetOpenTerminalSession(context.Background(), started.Msg.SessionId)
	require.NoError(t, err, "failed delivery must not claim the privileged shell is closed")
	assert.Equal(t, 1, f.sessions.Count())

	f.sender.err = nil
	_, err = f.handlers.TerminateTerminalSession(f.actor("TerminateTerminalSession"),
		connect.NewRequest(&pmv1.TerminateTerminalSessionRequest{
			SessionId: started.Msg.SessionId, Reason: "incident response",
		}))
	require.NoError(t, err)
	assert.Zero(t, f.sessions.Count())
	var reason string
	var terminatedBy *string
	require.NoError(t, f.raw.QueryRow(context.Background(), `
		SELECT exit_reason, terminated_by FROM terminal_sessions WHERE session_id = $1`,
		started.Msg.SessionId).Scan(&reason, &terminatedBy))
	assert.Equal(t, "incident response", reason)
	require.NotNil(t, terminatedBy)
	assert.Equal(t, f.actorID, *terminatedBy)

	_, err = f.handlers.TerminateTerminalSession(f.actor("TerminateTerminalSession"),
		connect.NewRequest(&pmv1.TerminateTerminalSessionRequest{SessionId: newID()}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestDeviceHandlers_SensitiveReadFailsClosedWhenEvidenceFails(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	rejectAuditOperation(t, f.raw, "/powermanage.v1.ControlService/GetDeviceInventory")

	_, err := f.handlers.GetDeviceInventory(f.actor("GetDeviceInventory"),
		connect.NewRequest(&pmv1.GetDeviceInventoryRequest{DeviceId: f.groupID}))
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
}

func TestDeviceHandlers_MutationsAreAuditedCRUD(t *testing.T) {
	f := newDeviceHandlerFixture(t)
	ctx := f.actor(
		"SetDeviceLabel", "RemoveDeviceLabel", "AssignDevice", "UnassignDevice",
		"ListDeviceAssignees", "SetDeviceSyncInterval", "SetDeviceInventoryInterval", "DeleteDevice",
		"CancelExecution", "CreateLuksToken", "RevokeLuksDeviceKey", "DispatchOSQuery",
		"QueryDeviceLogs", "RefreshDeviceInventory", "StartTerminal", "StopTerminal",
		"TerminateTerminalSession",
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
	executionID := newID()
	deliveryID := seedDelivery(t, f.raw, f.directID, f.now)
	_, err = f.raw.Exec(context.Background(), `
		INSERT INTO executions
			(id, delivery_id, device_id, action_type, desired_state, status, created_at, created_by_type, created_by_id)
		VALUES ($1, $2, $3, 200, 0, 'scheduled', $4, 'user', $5)`,
		executionID, deliveryID, f.directID, f.now, f.actorID)
	require.NoError(t, err)
	_, err = f.handlers.CancelExecution(ctx,
		connect.NewRequest(&pmv1.CancelExecutionRequest{ExecutionId: executionID}))
	require.NoError(t, err)
	encryptionActionID := newID()
	_, err = f.raw.Exec(context.Background(), `
		INSERT INTO actions (id, name, action_type, params, created_by)
		VALUES ($1, 'Encryption', $2, '{}', $3)`,
		encryptionActionID, int32(pmv1.ActionType_ACTION_TYPE_ENCRYPTION), f.actorID)
	require.NoError(t, err)
	_, err = f.handlers.CreateLuksToken(ctx,
		connect.NewRequest(&pmv1.CreateLuksTokenRequest{
			DeviceId: f.directID, ActionId: encryptionActionID,
		}))
	require.NoError(t, err)
	seedCurrentLuksKeys(t, f, encryptionActionID, 1)
	_, err = f.handlers.RevokeLuksDeviceKey(ctx,
		connect.NewRequest(&pmv1.RevokeLuksDeviceKeyRequest{
			DeviceId: f.directID, ActionId: encryptionActionID,
		}))
	require.NoError(t, err)
	_, err = f.handlers.DispatchOSQuery(ctx,
		connect.NewRequest(&pmv1.DispatchOSQueryRequest{DeviceId: f.directID, Table: "packages"}))
	require.NoError(t, err)
	_, err = f.handlers.QueryDeviceLogs(ctx,
		connect.NewRequest(&pmv1.QueryDeviceLogsRequest{DeviceId: f.directID, Lines: 10}))
	require.NoError(t, err)
	_, err = f.handlers.RefreshDeviceInventory(ctx,
		connect.NewRequest(&pmv1.RefreshDeviceInventoryRequest{DeviceId: f.directID}))
	require.NoError(t, err)
	graceful, err := f.handlers.StartTerminal(ctx,
		connect.NewRequest(&pmv1.StartTerminalRequest{DeviceId: f.directID}))
	require.NoError(t, err)
	_, err = f.handlers.StopTerminal(ctx,
		connect.NewRequest(&pmv1.StopTerminalRequest{SessionId: graceful.Msg.SessionId}))
	require.NoError(t, err)
	forced, err := f.handlers.StartTerminal(ctx,
		connect.NewRequest(&pmv1.StartTerminalRequest{DeviceId: f.directID}))
	require.NoError(t, err)
	_, err = f.handlers.TerminateTerminalSession(ctx,
		connect.NewRequest(&pmv1.TerminateTerminalSessionRequest{SessionId: forced.Msg.SessionId}))
	require.NoError(t, err)

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
	rejectRevocationFingerprint(t, f.raw, fingerprint)

	_, err := f.handlers.DeleteDevice(f.actor("DeleteDevice"), connect.NewRequest(&pmv1.DeleteDeviceRequest{Id: f.directID}))
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
		powermanagev1connect.ControlServiceCancelExecutionProcedure,
		powermanagev1connect.ControlServiceListLpsPasswordsProcedure,
		powermanagev1connect.ControlServiceRevealLpsPasswordProcedure,
		powermanagev1connect.ControlServiceListLuksKeysProcedure,
		powermanagev1connect.ControlServiceRevealLuksKeyProcedure,
		powermanagev1connect.ControlServiceCreateLuksTokenProcedure,
		powermanagev1connect.ControlServiceRevokeLuksDeviceKeyProcedure,
		powermanagev1connect.ControlServiceDispatchOSQueryProcedure,
		powermanagev1connect.ControlServiceRefreshDeviceInventoryProcedure,
		powermanagev1connect.ControlServiceQueryDeviceLogsProcedure,
		powermanagev1connect.ControlServiceStartTerminalProcedure,
		powermanagev1connect.ControlServiceStopTerminalProcedure,
		powermanagev1connect.ControlServiceListActiveTerminalSessionsProcedure,
		powermanagev1connect.ControlServiceTerminateTerminalSessionProcedure,
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
		powermanagev1connect.ControlServiceListLpsPasswordsProcedure,
		powermanagev1connect.ControlServiceRevealLpsPasswordProcedure,
		powermanagev1connect.ControlServiceListLuksKeysProcedure,
		powermanagev1connect.ControlServiceRevealLuksKeyProcedure,
		powermanagev1connect.ControlServiceListActiveTerminalSessionsProcedure,
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

func assertSecretReveal(
	t *testing.T,
	f *deviceHandlerFixture,
	procedure, secretType, secretID, deviceID, actionID string,
) {
	t.Helper()
	operation, err := latestOperationFor(t, f.store, f.raw, procedure)
	require.NoError(t, err)
	assert.Equal(t, string(store.ClassSensitiveRead), operation.OperationClass)
	effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
	require.NoError(t, err)
	require.Len(t, effects, 3)
	want := map[string]string{secretType: secretID, "device": deviceID, "action": actionID}
	for _, effect := range effects {
		assert.Equal(t, want[effect.ResourceType], effect.ResourceID)
		assert.Equal(t, "REVEAL", effect.Action)
		delete(want, effect.ResourceType)
	}
	assert.Empty(t, want)
}

func latestOperationFor(t *testing.T, st *store.Store, raw *testdb.DB, procedure string) (store.AuditOperationRow, error) {
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
