package store_test

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

func TestDeviceCRUD_ViewsAndFilters(t *testing.T) {
	st, pool := setupSQLite(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	deviceIDs := []string{newID(), newID(), newID()}
	sort.Strings(deviceIDs)
	userID, userGroupID, deviceGroupID := newID(), newID(), newID()

	_, err := st.WithAudit(ctx, mutationOp(), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.InsertUser(ctx, db.InsertUserParams{
			ProvisioningSource: store.UserProvisioningSourceSCIM,
			ID:                 userID, Email: "operator@example.test", DisplayName: "Operator",
			LinuxUsername: "operator", LinuxUid: 200001, CreatedAt: &now,
		}); err != nil {
			return err
		}
		if _, err := tx.InsertUserGroup(ctx, db.InsertUserGroupParams{
			ID: userGroupID, Name: "operators", CreatedAt: now, CreatedBy: userID,
		}); err != nil {
			return err
		}
		if _, err := tx.InsertUserGroupMember(ctx, db.InsertUserGroupMemberParams{
			GroupID: userGroupID, UserID: userID, AddedAt: now, AddedBy: userID,
		}); err != nil {
			return err
		}

		for i, id := range deviceIDs {
			lastSeen := now.Add(-time.Duration(i) * 10 * time.Minute)
			if _, err := tx.InsertDevice(ctx, db.InsertDeviceParams{
				ID: id, Hostname: "device-" + id, AgentVersion: "1.0.0",
				AgentSealingPublicKey: bytes.Repeat([]byte{byte(i + 1)}, 32),
				RegisteredAt:          &now, LastSeenAt: &lastSeen,
			}); err != nil {
				return err
			}
			rec.Effect(deviceEffect(id))
		}

		if _, err := tx.SetDeviceLabel(ctx, db.SetDeviceLabelParams{DeviceID: deviceIDs[0], Key: "env", Value: "prod"}); err != nil {
			return err
		}
		if _, err := tx.SetDeviceLabel(ctx, db.SetDeviceLabelParams{DeviceID: deviceIDs[1], Key: "env", Value: "prod"}); err != nil {
			return err
		}
		if _, err := tx.SetDeviceLabel(ctx, db.SetDeviceLabelParams{DeviceID: deviceIDs[2], Key: "env", Value: "dev"}); err != nil {
			return err
		}
		if _, err := tx.AssignDeviceUser(ctx, db.AssignDeviceUserParams{
			DeviceID: deviceIDs[0], UserID: userID, AssignedAt: now, AssignedBy: userID,
		}); err != nil {
			return err
		}
		if _, err := tx.AssignDeviceGroup(ctx, db.AssignDeviceGroupParams{
			DeviceID: deviceIDs[1], GroupID: userGroupID, AssignedAt: now, AssignedBy: userID,
		}); err != nil {
			return err
		}
		return nil
	})
	require.NoError(t, err)

	// Scope setup belongs to the future device-group mutation slice. This
	// test only needs a real relation to prove the device list's read filter.
	_, err = pool.Exec(ctx, `INSERT INTO device_groups (id, name) VALUES ($1, 'scope-a')`, deviceGroupID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO device_group_members (group_id, device_id) VALUES ($1, $2)`, deviceGroupID, deviceIDs[1])
	require.NoError(t, err)

	view, err := st.GetDeviceView(ctx, deviceIDs[0])
	require.NoError(t, err)
	assert.Equal(t, "prod", view.Labels["env"])
	assert.Equal(t, []string{userID}, view.AssignedUserIDs)
	assert.Empty(t, view.AssignedGroupIDs)
	assignedToUser, err := st.IsDeviceAssignedToUser(ctx, deviceIDs[0], userID)
	require.NoError(t, err)
	assert.True(t, assignedToUser)
	assignedToUser, err = st.IsDeviceAssignedToUser(ctx, deviceIDs[1], userID)
	require.NoError(t, err)
	assert.True(t, assignedToUser, "membership in an assigned live user group confers assignment")
	assignedToUser, err = st.IsDeviceAssignedToUser(ctx, deviceIDs[2], userID)
	require.NoError(t, err)
	assert.False(t, assignedToUser)

	assigned := userID
	rows, err := st.ListDeviceViews(ctx, store.DeviceListFilter{
		Limit: 100, AssignedUserID: &assigned, OnlineSince: now.Add(-5 * time.Minute),
	})
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, deviceIDs[:2], []string{rows[0].ID, rows[1].ID})
	_, err = pool.Exec(ctx, `UPDATE user_groups SET is_deleted = TRUE WHERE id = $1`, userGroupID)
	require.NoError(t, err)
	assignedToUser, err = st.IsDeviceAssignedToUser(ctx, deviceIDs[1], userID)
	require.NoError(t, err)
	assert.False(t, assignedToUser, "a deleted user group must not confer assignment")
	rows, err = st.ListDeviceViews(ctx, store.DeviceListFilter{
		Limit: 100, AssignedUserID: &assigned, OnlineSince: now.Add(-5 * time.Minute),
	})
	require.NoError(t, err)
	require.Len(t, rows, 1, "a deleted user group must not keep granting device assignment")
	assert.Equal(t, deviceIDs[0], rows[0].ID)
	_, err = pool.Exec(ctx, `UPDATE user_groups SET is_deleted = FALSE WHERE id = $1`, userGroupID)
	require.NoError(t, err)

	rows, err = st.ListDeviceViews(ctx, store.DeviceListFilter{
		Limit: 100, Labels: map[string]string{"env": "prod"}, OnlineSince: now.Add(-5 * time.Minute),
	})
	require.NoError(t, err)
	require.Len(t, rows, 2)

	rows, err = st.ListDeviceViews(ctx, store.DeviceListFilter{
		Limit: 100, Status: store.DeviceStatusOnline, OnlineSince: now.Add(-5 * time.Minute),
	})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, deviceIDs[0], rows[0].ID)

	rows, err = st.ListDeviceViews(ctx, store.DeviceListFilter{
		Limit: 100, ScopeRestricted: true, ScopeGroupIDs: []string{deviceGroupID}, OnlineSince: now.Add(-5 * time.Minute),
	})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, deviceIDs[1], rows[0].ID)
	_, err = pool.Exec(ctx, `UPDATE device_groups SET is_deleted = TRUE WHERE id = $1`, deviceGroupID)
	require.NoError(t, err)
	rows, err = st.ListDeviceViews(ctx, store.DeviceListFilter{
		Limit: 100, ScopeRestricted: true, ScopeGroupIDs: []string{deviceGroupID}, OnlineSince: now.Add(-5 * time.Minute),
	})
	require.NoError(t, err)
	assert.Empty(t, rows, "a deleted device group must not keep granting scope visibility")
	_, err = pool.Exec(ctx, `UPDATE device_groups SET is_deleted = FALSE WHERE id = $1`, deviceGroupID)
	require.NoError(t, err)

	collectedAt := now.Add(-30 * time.Minute)
	_, err = pool.Exec(ctx, `
		INSERT INTO device_inventory (device_id, table_name, rows, collected_at)
		VALUES ($1, 'system_info', '[]', $2)`, deviceIDs[1], collectedAt)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		UPDATE device_groups SET inventory_interval_minutes = 720 WHERE id = $1`, deviceGroupID)
	require.NoError(t, err)
	view, err = st.GetDeviceView(ctx, deviceIDs[1])
	require.NoError(t, err)
	require.NotNil(t, view.LastInventoryAt)
	assert.WithinDuration(t, collectedAt, *view.LastInventoryAt, time.Microsecond)
	assert.Equal(t, int32(720), view.ResolvedInventoryIntervalMinutes,
		"a live group's shortest non-zero interval is inherited")
	viewsWithFreshness, err := st.ListDeviceViews(ctx, store.DeviceListFilter{Limit: 100})
	require.NoError(t, err)
	require.Len(t, viewsWithFreshness, 3)
	assert.Nil(t, viewsWithFreshness[0].LastInventoryAt)
	require.NotNil(t, viewsWithFreshness[1].LastInventoryAt)
	assert.Equal(t, int32(720), viewsWithFreshness[1].ResolvedInventoryIntervalMinutes)
	assert.Equal(t, int32(1440), viewsWithFreshness[2].ResolvedInventoryIntervalMinutes,
		"the server default applies without a device or group override")

	rows, err = st.ListDeviceViews(ctx, store.DeviceListFilter{
		AfterID: deviceIDs[0], Limit: 1, OnlineSince: now.Add(-5 * time.Minute),
	})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, deviceIDs[1], rows[0].ID)

	count, err := st.CountDeviceViews(ctx, store.DeviceListFilter{
		Labels: map[string]string{"env": "prod"}, OnlineSince: now.Add(-5 * time.Minute),
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	groups, err := st.ListDeviceGroupIDs(ctx, deviceIDs[1])
	require.NoError(t, err)
	assert.Equal(t, []string{deviceGroupID}, groups)

	_, err = st.WithAudit(ctx, mutationOp(), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		n, err := tx.SetDeviceSyncInterval(ctx, db.SetDeviceSyncIntervalParams{ID: deviceIDs[0], Minutes: 60})
		if err := requireOneRow("set sync interval", n, err); err != nil {
			return err
		}
		n, err = tx.SetDeviceInventoryInterval(ctx, db.SetDeviceInventoryIntervalParams{ID: deviceIDs[0], Minutes: 1440})
		if err := requireOneRow("set inventory interval", n, err); err != nil {
			return err
		}
		n, err = tx.RemoveDeviceLabel(ctx, db.RemoveDeviceLabelParams{DeviceID: deviceIDs[0], Key: "env"})
		if err := requireOneRow("remove label", n, err); err != nil {
			return err
		}
		n, err = tx.SoftDeleteDevice(ctx, deviceIDs[2])
		if err := requireOneRow("delete device", n, err); err != nil {
			return err
		}
		rec.Effect(store.AuditEffect{ResourceType: "device", ResourceID: deviceIDs[0], Action: "UPDATE", Outcome: store.EffectApplied})
		rec.Effect(store.AuditEffect{ResourceType: "device", ResourceID: deviceIDs[2], Action: "DELETE", Outcome: store.EffectApplied})
		return nil
	})
	require.NoError(t, err)

	view, err = st.GetDeviceView(ctx, deviceIDs[0])
	require.NoError(t, err)
	assert.Empty(t, view.Labels)
	assert.Equal(t, int32(60), view.SyncIntervalMinutes)
	assert.Equal(t, int32(1440), view.InventoryIntervalMinutes)
	_, err = st.GetDeviceView(ctx, deviceIDs[2])
	assert.True(t, store.IsNotFound(err))
}

func TestHeartbeatTelemetryUpdatesWithoutGrowingAudit(t *testing.T) {
	st, pool := setupSQLite(t)
	ctx := context.Background()
	before := time.Date(2026, 8, 2, 10, 0, 0, 0, time.UTC)
	after := before.Add(2 * time.Minute)
	deviceID := newID()

	_, err := st.WithAudit(ctx, mutationOp(), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		_, err := tx.InsertDevice(ctx, db.InsertDeviceParams{
			ID: deviceID, Hostname: "telemetry", AgentVersion: "1.0.0",
			AgentSealingPublicKey: bytes.Repeat([]byte{1}, 32), RegisteredAt: &before, LastSeenAt: &before,
		})
		if err == nil {
			rec.Effect(deviceEffect(deviceID))
		}
		return err
	})
	require.NoError(t, err)
	auditBefore, err := st.CountAuditOperations(ctx, "")
	require.NoError(t, err)

	require.NoError(t, st.RecordHeartbeatTelemetry(ctx, map[string]time.Time{deviceID: after}))

	var stored time.Time
	require.NoError(t, pool.QueryRow(ctx, `SELECT last_seen_at FROM devices WHERE id = $1`, deviceID).Scan(&stored))
	assert.True(t, stored.Equal(after), "stored heartbeat = %s, want %s", stored, after)
	rows, total, err := st.Search(ctx, store.SearchParams{Scope: "devices", Query: deviceID, Limit: 50})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, rows, 1)
	assert.Equal(t, fmt.Sprint(after.Unix()), rows[0].Fields["last_seen_at"],
		"heartbeat and searchable recency must commit together")
	auditAfter, err := st.CountAuditOperations(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, auditBefore, auditAfter, "heartbeat telemetry must not enter the audit chain")
}

func TestInsertDevice_RejectsInvalidAgentSealingKey(t *testing.T) {
	st, _ := setupSQLite(t)
	ctx := context.Background()
	now := time.Now().UTC()

	_, err := st.WithAudit(ctx, mutationOp(), func(ctx context.Context, tx *store.Tx, _ *store.AuditRecorder) error {
		_, err := tx.InsertDevice(ctx, db.InsertDeviceParams{
			ID: newID(), Hostname: "bad-key", AgentVersion: "1.0.0",
			AgentSealingPublicKey: bytes.Repeat([]byte{1}, 31), RegisteredAt: &now, LastSeenAt: &now,
		})
		return err
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "agent_sealing_public_key")
}

func requireOneRow(op string, n int64, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if n != 1 {
		return fmt.Errorf("%s: affected %d rows, want 1", op, n)
	}
	return nil
}
