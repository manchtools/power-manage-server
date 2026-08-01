package device

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

func requireOne(operation string, rows int64, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	if rows != 1 {
		return fmt.Errorf("%s: affected %d rows", operation, rows)
	}
	return nil
}

func deviceEffect(deviceID, action string, fields ...string) store.AuditEffect {
	return store.AuditEffect{
		ResourceType: "device", ResourceID: deviceID, Action: action,
		Outcome: store.EffectApplied, ChangedFields: fields,
	}
}

// CancelExecution atomically cancels an execution that has not begun. Later
// states are an audited idempotent no-op.
func (h *Handlers) CancelExecution(ctx context.Context, req *connect.Request[pmv1.CancelExecutionRequest]) (*connect.Response[pmv1.CancelExecutionResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	execution, err := h.store.GetExecution(ctx, req.Msg.ExecutionId)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, errExecutionNotFound, "execution not found")
		}
		return nil, h.internal(ctx, "read cancel target", err)
	}
	if _, err := h.mutationDevice(ctx, "CancelExecution", execution.DeviceID); err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			return nil, notFound(ctx, errExecutionNotFound, "execution not found")
		}
		return nil, err
	}

	completedAt := h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceCancelExecutionProcedure, "CancelExecution"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			n, err := tx.CancelPendingExecution(ctx, db.CancelPendingExecutionParams{
				ID: req.Msg.ExecutionId, CompletedAt: &completedAt,
			})
			if err != nil {
				return fmt.Errorf("cancel execution: %w", err)
			}
			if n == 1 {
				rec.Effect(store.AuditEffect{
					ResourceType: "execution", ResourceID: req.Msg.ExecutionId,
					Action: "CANCEL", Outcome: store.EffectApplied,
					ChangedFields: []string{"completed_at", "status"},
				})
			}
			return nil
		})
	if err != nil {
		return nil, h.internal(ctx, "cancel execution", err)
	}
	updated, err := h.store.GetExecution(ctx, req.Msg.ExecutionId)
	if err != nil {
		return nil, h.internal(ctx, "read cancelled execution", err)
	}
	message, err := executionToProto(updated)
	if err != nil {
		return nil, h.internal(ctx, "decode cancelled execution", err)
	}
	return connect.NewResponse(&pmv1.CancelExecutionResponse{Execution: message}), nil
}

// SetDeviceLabel upserts one label in the same transaction as its audit effect.
func (h *Handlers) SetDeviceLabel(ctx context.Context, req *connect.Request[pmv1.SetDeviceLabelRequest]) (*connect.Response[pmv1.UpdateDeviceResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "SetDeviceLabel", req.Msg.Id); err != nil {
		return nil, err
	}
	if _, err := h.store.GetDevice(ctx, req.Msg.Id); err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, errDeviceNotFound, "device not found")
		}
		return nil, h.internal(ctx, "read label target", err)
	}
	_, err = h.store.WithAudit(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceSetDeviceLabelProcedure, "SetDeviceLabel"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			n, err := tx.SetDeviceLabel(ctx, db.SetDeviceLabelParams{
				DeviceID: req.Msg.Id, Key: req.Msg.Key, Value: req.Msg.Value,
			})
			if err := requireOne("set device label", n, err); err != nil {
				return err
			}
			rec.Effect(deviceEffect(req.Msg.Id, "UPDATE", "labels"))
			return nil
		})
	if err != nil {
		return nil, h.internal(ctx, "set device label", err)
	}
	return h.updatedDevice(ctx, req.Msg.Id)
}

// RemoveDeviceLabel removes one label. Missing labels are an idempotent success.
func (h *Handlers) RemoveDeviceLabel(ctx context.Context, req *connect.Request[pmv1.RemoveDeviceLabelRequest]) (*connect.Response[pmv1.UpdateDeviceResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "RemoveDeviceLabel", req.Msg.Id); err != nil {
		return nil, err
	}
	if _, err := h.store.GetDevice(ctx, req.Msg.Id); err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, errDeviceNotFound, "device not found")
		}
		return nil, h.internal(ctx, "read label target", err)
	}
	_, err = h.store.WithAudit(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceRemoveDeviceLabelProcedure, "RemoveDeviceLabel"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			n, err := tx.RemoveDeviceLabel(ctx, db.RemoveDeviceLabelParams{DeviceID: req.Msg.Id, Key: req.Msg.Key})
			if err != nil {
				return fmt.Errorf("remove device label: %w", err)
			}
			if n == 1 {
				rec.Effect(deviceEffect(req.Msg.Id, "UPDATE", "labels"))
			}
			return nil
		})
	if err != nil {
		return nil, h.internal(ctx, "remove device label", err)
	}
	return h.updatedDevice(ctx, req.Msg.Id)
}

// AssignDevice assigns distinct users and groups with one audited transaction.
func (h *Handlers) AssignDevice(ctx context.Context, req *connect.Request[pmv1.AssignDeviceRequest]) (*connect.Response[pmv1.AssignDeviceResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	userIDs := distinct(req.Msg.UserIds, req.Msg.UserId)
	groupIDs := distinct(req.Msg.GroupIds, req.Msg.GroupId)
	if len(userIDs) == 0 && len(groupIDs) == 0 {
		return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "at least one user or group is required")
	}
	if len(userIDs) > 256 || len(groupIDs) > 256 {
		return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "too many users or groups")
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "AssignDevice", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	view, err := h.store.GetDeviceView(ctx, req.Msg.DeviceId)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, errDeviceNotFound, "device not found")
		}
		return nil, h.internal(ctx, "read assignment target", err)
	}
	for _, id := range userIDs {
		if _, err := h.store.GetUser(ctx, id); err != nil {
			if store.IsNotFound(err) {
				return nil, notFound(ctx, errUserNotFound, "user not found")
			}
			return nil, h.internal(ctx, "read assignment user", err)
		}
	}
	for _, id := range groupIDs {
		if _, err := h.store.GetUserGroup(ctx, id); err != nil {
			if store.IsNotFound(err) {
				return nil, notFound(ctx, errUserGroupMissing, "user group not found")
			}
			return nil, h.internal(ctx, "read assignment group", err)
		}
	}
	existingUsers := set(view.AssignedUserIDs)
	existingGroups := set(view.AssignedGroupIDs)
	_, err = h.store.WithAudit(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceAssignDeviceProcedure, "AssignDevice"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			for _, id := range userIDs {
				if existingUsers[id] {
					continue
				}
				n, err := tx.AssignDeviceUser(ctx, db.AssignDeviceUserParams{
					DeviceID: req.Msg.DeviceId, UserID: id, AssignedAt: h.now().UTC(), AssignedBy: actor.ID,
				})
				if err := requireOne("assign device user", n, err); err != nil {
					return err
				}
				effect := deviceEffect(req.Msg.DeviceId, "ASSIGN", "assigned_user_ids")
				effect.AfterRef = &id
				rec.Effect(effect)
			}
			for _, id := range groupIDs {
				if existingGroups[id] {
					continue
				}
				n, err := tx.AssignDeviceGroup(ctx, db.AssignDeviceGroupParams{
					DeviceID: req.Msg.DeviceId, GroupID: id, AssignedAt: h.now().UTC(), AssignedBy: actor.ID,
				})
				if err := requireOne("assign device group", n, err); err != nil {
					return err
				}
				effect := deviceEffect(req.Msg.DeviceId, "ASSIGN", "assigned_group_ids")
				effect.AfterRef = &id
				rec.Effect(effect)
			}
			return nil
		})
	if err != nil {
		return nil, h.internal(ctx, "assign device", err)
	}
	updated, err := h.store.GetDeviceView(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, h.internal(ctx, "read assigned device", err)
	}
	return connect.NewResponse(&pmv1.AssignDeviceResponse{Device: h.toProto(updated)}), nil
}

// UnassignDevice removes exactly one user or group assignment.
func (h *Handlers) UnassignDevice(ctx context.Context, req *connect.Request[pmv1.UnassignDeviceRequest]) (*connect.Response[pmv1.UnassignDeviceResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if (req.Msg.UserId == "") == (req.Msg.GroupId == "") {
		return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "exactly one user or group is required")
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, "UnassignDevice", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	if _, err := h.store.GetDevice(ctx, req.Msg.DeviceId); err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, errDeviceNotFound, "device not found")
		}
		return nil, h.internal(ctx, "read unassignment target", err)
	}
	_, err = h.store.WithAudit(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceUnassignDeviceProcedure, "UnassignDevice"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			var n int64
			var err error
			var field, ref string
			if req.Msg.UserId != "" {
				ref, field = req.Msg.UserId, "assigned_user_ids"
				n, err = tx.UnassignDeviceUser(ctx, db.UnassignDeviceUserParams{DeviceID: req.Msg.DeviceId, UserID: ref})
			} else {
				ref, field = req.Msg.GroupId, "assigned_group_ids"
				n, err = tx.UnassignDeviceGroup(ctx, db.UnassignDeviceGroupParams{DeviceID: req.Msg.DeviceId, GroupID: ref})
			}
			if err != nil {
				return fmt.Errorf("unassign device: %w", err)
			}
			if n == 1 {
				effect := deviceEffect(req.Msg.DeviceId, "UNASSIGN", field)
				effect.BeforeRef = &ref
				rec.Effect(effect)
			}
			return nil
		})
	if err != nil {
		return nil, h.internal(ctx, "unassign device", err)
	}
	view, err := h.store.GetDeviceView(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, h.internal(ctx, "read unassigned device", err)
	}
	return connect.NewResponse(&pmv1.UnassignDeviceResponse{Device: h.toProto(view)}), nil
}

// SetDeviceSyncInterval writes the device-level sync override directly.
func (h *Handlers) SetDeviceSyncInterval(ctx context.Context, req *connect.Request[pmv1.SetDeviceSyncIntervalRequest]) (*connect.Response[pmv1.UpdateDeviceResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := h.mutationDevice(ctx, "SetDeviceSyncInterval", req.Msg.Id); err != nil {
		return nil, err
	}
	_, err = h.store.WithAudit(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceSetDeviceSyncIntervalProcedure, "SetDeviceSyncInterval"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			n, err := tx.SetDeviceSyncInterval(ctx, db.SetDeviceSyncIntervalParams{ID: req.Msg.Id, Minutes: req.Msg.SyncIntervalMinutes})
			if err := requireOne("set device sync interval", n, err); err != nil {
				return err
			}
			rec.Effect(deviceEffect(req.Msg.Id, "UPDATE", "sync_interval_minutes"))
			return nil
		})
	if err != nil {
		return nil, h.internal(ctx, "set device sync interval", err)
	}
	return h.updatedDevice(ctx, req.Msg.Id)
}

// SetDeviceInventoryInterval writes the device-level inventory override.
func (h *Handlers) SetDeviceInventoryInterval(ctx context.Context, req *connect.Request[pmv1.SetDeviceInventoryIntervalRequest]) (*connect.Response[pmv1.UpdateDeviceResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if minutes := req.Msg.InventoryIntervalMinutes; minutes != 0 && (minutes < 120 || minutes > 10080) {
		return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "inventory interval is out of range")
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := h.mutationDevice(ctx, "SetDeviceInventoryInterval", req.Msg.Id); err != nil {
		return nil, err
	}
	_, err = h.store.WithAudit(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceSetDeviceInventoryIntervalProcedure, "SetDeviceInventoryInterval"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			n, err := tx.SetDeviceInventoryInterval(ctx, db.SetDeviceInventoryIntervalParams{ID: req.Msg.Id, Minutes: req.Msg.InventoryIntervalMinutes})
			if err := requireOne("set device inventory interval", n, err); err != nil {
				return err
			}
			rec.Effect(deviceEffect(req.Msg.Id, "UPDATE", "inventory_interval_minutes"))
			return nil
		})
	if err != nil {
		return nil, h.internal(ctx, "set device inventory interval", err)
	}
	return h.updatedDevice(ctx, req.Msg.Id)
}

// DeleteDevice atomically soft-deletes the device, revokes its current
// certificate, and records the audit effect. The active stream closes only
// after that transaction commits.
func (h *Handlers) DeleteDevice(ctx context.Context, req *connect.Request[pmv1.DeleteDeviceRequest]) (*connect.Response[pmv1.DeleteDeviceResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	view, err := h.mutationDevice(ctx, "DeleteDevice", req.Msg.Id)
	if err != nil {
		return nil, err
	}
	if view.CertFingerprint != nil && view.CertNotAfter == nil {
		return nil, h.internal(ctx, "delete device", fmt.Errorf("certificate expiry is missing"))
	}
	_, err = h.store.WithAudit(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceDeleteDeviceProcedure, "DeleteDevice"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			n, err := tx.SoftDeleteDevice(ctx, req.Msg.Id)
			if err := requireOne("delete device", n, err); err != nil {
				return err
			}
			if view.CertFingerprint != nil {
				if err := store.RevokeInTx(ctx, tx, *view.CertFingerprint, *view.CertNotAfter, "device_deleted"); err != nil {
					return err
				}
			}
			effect := deviceEffect(req.Msg.Id, "DELETE", "is_deleted")
			before, after := false, true
			effect.BeforeFlag, effect.AfterFlag = &before, &after
			if view.CertFingerprint != nil {
				effect.EvidenceKind = "certificate_fingerprint"
				effect.EvidenceFingerprint = auth.Fingerprint(*view.CertFingerprint)
			}
			rec.Effect(effect)
			return nil
		})
	if err != nil {
		return nil, h.internal(ctx, "delete device", err)
	}
	h.closeStream(req.Msg.Id)
	return connect.NewResponse(&pmv1.DeleteDeviceResponse{}), nil
}

func (h *Handlers) updatedDevice(ctx context.Context, deviceID string) (*connect.Response[pmv1.UpdateDeviceResponse], error) {
	view, err := h.store.GetDeviceView(ctx, deviceID)
	if err != nil {
		return nil, h.internal(ctx, "read updated device", err)
	}
	return connect.NewResponse(&pmv1.UpdateDeviceResponse{Device: h.toProto(view)}), nil
}

func distinct(ids []string, extra string) []string {
	seen := make(map[string]bool, len(ids)+1)
	out := make([]string, 0, len(ids)+1)
	for _, id := range append(append([]string(nil), ids...), extra) {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func set(ids []string) map[string]bool {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}
