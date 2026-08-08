package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/devicegroup"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

func deviceGroupOperation() store.AuditOperation {
	op := mutationOp()
	op.OperationID = newID()
	op.RequestDescriptor = "powermanage.v1.ControlService/DeviceGroupMutation"
	op.AuthorizationDetail = "DeviceGroupMutation"
	return op
}

func TestDeviceGroupState_CRUDAndManualMembershipAreAudited(t *testing.T) {
	st, raw := setupSQLite(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 1, 14, 0, 0, 0, time.UTC)
	state := devicegroup.NewState(devicegroup.Config{Store: st, Now: func() time.Time { return now }})

	deviceIDs := []string{newID(), newID()}
	seedOp := deviceGroupOperation()
	_, err := st.WithAudit(ctx, seedOp, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		for i, id := range deviceIDs {
			if _, err := tx.InsertDevice(ctx, generated.InsertDeviceParams{
				ID: id, Hostname: "device-" + string(rune('a'+i)),
				AgentSealingPublicKey: make([]byte, 32), RegisteredAt: &now,
			}); err != nil {
				return err
			}
			rec.Effect(store.AuditEffect{
				ResourceType: "device", ResourceID: id, Action: "CREATE", Outcome: store.EffectApplied,
				ChangedFields: []string{"hostname"},
			})
		}
		return nil
	})
	require.NoError(t, err)

	createOp := deviceGroupOperation()
	group, err := state.Create(ctx, createOp, devicegroup.CreateParams{
		Name: "workstations", Description: "managed endpoints", CreatedBy: createOp.ActorID,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(0), group.LiveMemberCount)

	addOp := deviceGroupOperation()
	added, err := state.AddDevices(ctx, addOp, group.ID, []string{deviceIDs[0], deviceIDs[1], deviceIDs[0]})
	require.NoError(t, err)
	assert.Equal(t, int64(2), added)
	added, err = state.AddDevices(ctx, deviceGroupOperation(), group.ID, deviceIDs)
	require.NoError(t, err)
	assert.Equal(t, int64(0), added, "repeating live members is idempotent")

	group, err = st.GetDeviceGroup(ctx, group.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), group.LiveMemberCount)
	members, err := st.ListDeviceGroupMembers(ctx, group.ID)
	require.NoError(t, err)
	require.Len(t, members, 2)
	assert.Equal(t, "device-a", members[0].Hostname)

	removeOp := deviceGroupOperation()
	require.NoError(t, state.RemoveDevice(ctx, removeOp, group.ID, deviceIDs[0]))
	err = state.RemoveDevice(ctx, deviceGroupOperation(), group.ID, deviceIDs[0])
	assert.ErrorIs(t, err, devicegroup.ErrMemberNotFound)

	renameOp := deviceGroupOperation()
	_, err = state.Rename(ctx, renameOp, group.ID, "renamed")
	require.NoError(t, err)
	descriptionOp := deviceGroupOperation()
	_, err = state.UpdateDescription(ctx, descriptionOp, group.ID, "direct state")
	require.NoError(t, err)
	syncOp := deviceGroupOperation()
	_, err = state.SetSyncInterval(ctx, syncOp, group.ID, 30)
	require.NoError(t, err)
	inventoryOp := deviceGroupOperation()
	_, err = state.SetInventoryInterval(ctx, inventoryOp, group.ID, 120)
	require.NoError(t, err)
	windowOp := deviceGroupOperation()
	_, err = state.SetMaintenanceWindow(ctx, windowOp, group.ID,
		[]byte(`{"schedule":[{"days":["mon"],"allow":"09:00-17:00"}]}`))
	require.NoError(t, err)

	group, err = st.GetDeviceGroup(ctx, group.ID)
	require.NoError(t, err)
	assert.Equal(t, "renamed", group.Name)
	assert.Equal(t, "direct state", group.Description)
	assert.Equal(t, int32(30), group.SyncIntervalMinutes)
	assert.Equal(t, int32(120), group.InventoryIntervalMinutes)
	assert.JSONEq(t, `{"schedule":[{"days":["mon"],"allow":"09:00-17:00"}]}`, string(group.MaintenanceWindow))

	for _, op := range []store.AuditOperation{createOp, addOp, removeOp, renameOp, descriptionOp, syncOp, inventoryOp, windowOp} {
		recorded, err := st.GetAuditOperation(ctx, op.OperationID)
		require.NoError(t, err)
		effects, err := st.ListAuditEffects(ctx, recorded.OperationID)
		require.NoError(t, err)
		assert.NotEmpty(t, effects)
	}

	_, err = raw.Exec(ctx, `INSERT INTO assignments
		(id, source_type, source_id, target_type, target_id)
		VALUES ($1, 'action', $2, 'device_group', $3)`, newID(), newID(), group.ID)
	require.NoError(t, err)
	deleteOp := deviceGroupOperation()
	require.NoError(t, state.Delete(ctx, deleteOp, group.ID))
	_, err = st.GetDeviceGroup(ctx, group.ID)
	assert.True(t, store.IsNotFound(err))
	var activeAssignments int
	require.NoError(t, raw.QueryRow(ctx,
		`SELECT COUNT(*) FROM assignments WHERE target_type = 'device_group' AND target_id = $1 AND is_deleted = FALSE`, group.ID).
		Scan(&activeAssignments))
	assert.Zero(t, activeAssignments)
}

func TestDeviceGroupState_DynamicShapeAndBoundsFailClosed(t *testing.T) {
	st, _ := setupSQLite(t)
	ctx := context.Background()
	state := devicegroup.NewState(devicegroup.Config{Store: st})

	missingQueryOp := deviceGroupOperation()
	_, err := state.Create(ctx, missingQueryOp, devicegroup.CreateParams{
		Name: "broken", CreatedBy: missingQueryOp.ActorID, Dynamic: true,
	})
	assert.ErrorIs(t, err, devicegroup.ErrInvalidQuery)
	invalidQueryOp := deviceGroupOperation()
	_, err = state.Create(ctx, invalidQueryOp, devicegroup.CreateParams{
		Name: "broken", CreatedBy: invalidQueryOp.ActorID, Dynamic: true, Query: "(",
	})
	assert.ErrorIs(t, err, devicegroup.ErrInvalidQuery)

	op := deviceGroupOperation()
	dynamic, err := state.Create(ctx, op, devicegroup.CreateParams{
		Name: "production", CreatedBy: op.ActorID, Dynamic: true,
		Query: `device.labels.env equals prod`,
	})
	require.NoError(t, err)
	_, err = state.AddDevices(ctx, deviceGroupOperation(), dynamic.ID, []string{newID()})
	assert.ErrorIs(t, err, devicegroup.ErrDynamicGroup)

	_, err = state.SetSyncInterval(ctx, deviceGroupOperation(), dynamic.ID, 1441)
	assert.ErrorIs(t, err, devicegroup.ErrInvalidInput)
	_, err = state.SetInventoryInterval(ctx, deviceGroupOperation(), dynamic.ID, 60)
	assert.ErrorIs(t, err, devicegroup.ErrInvalidInput)
	_, err = state.SetMaintenanceWindow(ctx, deviceGroupOperation(), dynamic.ID, []byte(`[]`))
	assert.ErrorIs(t, err, devicegroup.ErrInvalidInput)

	_, err = state.UpdateQuery(ctx, deviceGroupOperation(), dynamic.ID, true, "(")
	assert.True(t, errors.Is(err, devicegroup.ErrInvalidQuery))
}

// Converting a curated group into a rule-driven one is a supported mode change
// (target design §5.1): the group keeps its identifier, assignments, schedules
// and windows, which is the whole reason to convert rather than delete and
// recreate. The membership it had as a static group is NOT kept — a group that
// still listed hand-picked devices while claiming to be defined by a rule would
// report members its own rule does not select, for as long as it took someone
// to evaluate it.
//
// The opposite direction stays as it was: materializing a rule-driven group
// freezes the membership the rule last produced (see the user-group handler
// test, "materializing preserves the compiled membership").
func TestDeviceGroupState_ConvertingCuratedGroupToRuleClearsItsMembers(t *testing.T) {
	st, _ := setupSQLite(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 6, 9, 0, 0, 0, time.UTC)
	state := devicegroup.NewState(devicegroup.Config{Store: st, Now: func() time.Time { return now }})

	deviceIDs := []string{newID(), newID()}
	_, err := st.WithAudit(ctx, deviceGroupOperation(), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		for i, id := range deviceIDs {
			if _, err := tx.InsertDevice(ctx, generated.InsertDeviceParams{
				ID: id, Hostname: "curated-" + string(rune('a'+i)),
				AgentSealingPublicKey: make([]byte, 32), RegisteredAt: &now,
			}); err != nil {
				return err
			}
			rec.Effect(store.AuditEffect{
				ResourceType: "device", ResourceID: id, Action: "CREATE", Outcome: store.EffectApplied,
				ChangedFields: []string{"hostname"},
			})
		}
		return nil
	})
	require.NoError(t, err)

	createOp := deviceGroupOperation()
	group, err := state.Create(ctx, createOp, devicegroup.CreateParams{
		Name: "hand picked", CreatedBy: createOp.ActorID,
	})
	require.NoError(t, err)
	added, err := state.AddDevices(ctx, deviceGroupOperation(), group.ID, deviceIDs)
	require.NoError(t, err)
	require.Equal(t, int64(2), added)

	// A rejected query must not be a half-conversion: the mode, the query and the
	// membership all still have to be the ones the operator started with.
	_, err = state.UpdateQuery(ctx, deviceGroupOperation(), group.ID, true, "(")
	assert.ErrorIs(t, err, devicegroup.ErrInvalidQuery)
	_, err = state.UpdateQuery(ctx, deviceGroupOperation(), group.ID, true, "")
	assert.ErrorIs(t, err, devicegroup.ErrInvalidQuery)
	unchanged, err := st.GetDeviceGroup(ctx, group.ID)
	require.NoError(t, err)
	assert.False(t, unchanged.IsDynamic, "a rejected query cannot convert the group")
	assert.Equal(t, int64(2), unchanged.LiveMemberCount, "a rejected query cannot drop members")

	convertOp := deviceGroupOperation()
	converted, err := state.UpdateQuery(ctx, convertOp, group.ID, true, `device.labels.env equals prod`)
	require.NoError(t, err, "a curated group must be convertible to a rule")
	assert.True(t, converted.IsDynamic)
	require.NotNil(t, converted.DynamicQuery)
	assert.Equal(t, `device.labels.env equals prod`, *converted.DynamicQuery)
	assert.Equal(t, int64(0), converted.LiveMemberCount, "the curated membership does not survive the rule")

	members, err := st.ListDeviceGroupMembers(ctx, group.ID)
	require.NoError(t, err)
	assert.Empty(t, members, "membership has exactly one source once the group is a rule")

	// The mode change, the query and the member clearing are one audited operation.
	recorded, err := st.GetAuditOperation(ctx, convertOp.OperationID)
	require.NoError(t, err)
	effects, err := st.ListAuditEffects(ctx, recorded.OperationID)
	require.NoError(t, err)
	assert.NotEmpty(t, effects)
	var changedFields []string
	for _, effect := range effects {
		if effect.ResourceType == "device_group" && effect.Action == "UPDATE" {
			changedFields = effect.ChangedFields
			break
		}
	}
	assert.Contains(t, changedFields, "members", "the conversion audit must record the membership deletion")

	// Manual membership is closed while the rule owns it…
	_, err = state.AddDevices(ctx, deviceGroupOperation(), group.ID, []string{deviceIDs[0]})
	assert.ErrorIs(t, err, devicegroup.ErrDynamicGroup)

	// …and the reverse direction still works, so the mode is genuinely a property
	// the owner controls rather than a one-way door.
	materialized, err := state.UpdateQuery(ctx, deviceGroupOperation(), group.ID, false, "")
	require.NoError(t, err)
	assert.False(t, materialized.IsDynamic)
}
