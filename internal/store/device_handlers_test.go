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

	_, err = f.handlers.GetDevice(context.Background(), connect.NewRequest(&pmv1.GetDeviceRequest{Id: f.directID}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.GetDeviceInventory(context.Background(),
		connect.NewRequest(&pmv1.GetDeviceInventoryRequest{DeviceId: f.directID}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
	_, err = f.handlers.GetOSQueryResult(context.Background(),
		connect.NewRequest(&pmv1.GetOSQueryResultRequest{QueryId: newID()}))
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
