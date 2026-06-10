package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// DeviceListener returns a store.EventListener that applies every
// device stream event the deleted PL/pgSQL project_device_event
// handled. Thirteen event types: DeviceRegistered, DeviceSeen,
// DeviceHeartbeat, DeviceCertRenewed, DeviceLabelsUpdated,
// DeviceLabelSet, DeviceLabelRemoved, DeviceDeleted, DeviceAssigned,
// DeviceUnassigned, DeviceGroupAssigned, DeviceGroupUnassigned,
// DeviceSyncIntervalSet.
//
// Event-type families:
//   - Single-statement events (Seen, Heartbeat, CertRenewed,
//     LabelsUpdated, LabelSet, LabelRemoved, Assigned, Unassigned,
//     GroupAssigned, GroupUnassigned, SyncIntervalSet) run on the
//     autocommit pool — one guarded UPDATE/INSERT/DELETE each.
//   - Multi-write events (DeviceRegistered when assigned_user_id is
//     present; DeviceDeleted with its assigned-user + assigned-group
//     wipes) wrap the cascade in store.WithTx so the writes are
//     atomic with each other (not with the event commit, which
//     already happened — fireListeners is post-commit).
//
// Asymmetric-guard discipline (per the role + identity_provider +
// action_set + assignment + user_group + device_group +
// compliance_policy + compliance + action+definition + execution
// ports): every UPDATE on devices_projection carries a
// `WHERE projection_version < $N` guard via :execrows, and the
// listener short-circuits cascades when n == 0. The DELETEs on
// device_assigned_users_projection and device_assigned_groups_projection
// carry a `WHERE projection_version <= $N` guard so a stale Unassigned
// replayed after a re-Assign cannot wipe the live row (CR catch on
// PR #179, applied here to the assignment-table junction tables).
//
// Wired in projectors.WireAll. Refs #136 (Phase 2 of tracker #107).
func DeviceListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "device" {
			return
		}
		// Multi-write events route through ApplyDevice via WithTx so
		// the cascade stays atomic; single-statement events go on the
		// autocommit pool. ApplyDevice handles all event types when
		// called with tx-bound queries (the rebuild path).
		switch e.EventType {
		case string(eventtypes.DeviceRegistered), string(eventtypes.DeviceDeleted):
			if err := st.WithTx(ctx, func(q *store.Queries) error {
				return ApplyDevice(ctx, q, e)
			}); err != nil {
				logger.Warn("device projector: failed to apply event",
					"event_id", e.ID, "event_type", e.EventType, "device_id", e.StreamID, "error", err)
			}
			return
		}
		if err := ApplyDevice(ctx, st.Queries(), e); err != nil {
			logger.Warn("device projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "device_id", e.StreamID, "error", err)
		}
	}
}

// ApplyDevice is the transactional core of the device projector.
// The listener wraps it for live-event dispatch (using WithTx for
// the multi-write event types); the rebuild path
// (manchtools/power-manage-server#125) registers it via
// RegisterRebuildApply so RebuildAll re-derives the projection from
// the event store instead of dispatching to the no-op PL/pgSQL stub.
//
// Asymmetric-guard discipline is preserved across every multi-write
// event: when the version-guarded write on the parent row affects
// zero rows, every cascading INSERT/DELETE downstream is skipped —
// otherwise a stale event re-applied later would leak orphan
// junction rows or wipe a freshly-restored device's assignments.
func ApplyDevice(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "device" {
		return nil
	}
	switch e.EventType {
	case string(eventtypes.DeviceRegistered):
		return applyDeviceRegistered(ctx, q, e)
	case string(eventtypes.DeviceSeen):
		return applyDeviceSeen(ctx, q, e)
	case string(eventtypes.DeviceHeartbeat):
		return applyDeviceHeartbeat(ctx, q, e)
	case string(eventtypes.DeviceCertRenewed):
		return applyDeviceCertRenewed(ctx, q, e)
	case string(eventtypes.DeviceLabelsUpdated):
		return applyDeviceLabelsUpdated(ctx, q, e)
	case string(eventtypes.DeviceLabelSet):
		return applyDeviceLabelSet(ctx, q, e)
	case string(eventtypes.DeviceLabelRemoved):
		return applyDeviceLabelRemoved(ctx, q, e)
	case string(eventtypes.DeviceDeleted):
		return applyDeviceDeleted(ctx, q, e)
	case string(eventtypes.DeviceAssigned):
		return applyDeviceAssigned(ctx, q, e)
	case string(eventtypes.DeviceUnassigned):
		return applyDeviceUnassigned(ctx, q, e)
	case string(eventtypes.DeviceGroupAssigned):
		return applyDeviceGroupAssigned(ctx, q, e)
	case string(eventtypes.DeviceGroupUnassigned):
		return applyDeviceGroupUnassigned(ctx, q, e)
	case string(eventtypes.DeviceSyncIntervalSet):
		return applyDeviceSyncIntervalSet(ctx, q, e)
	}
	return nil
}

func applyDeviceRegistered(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceRegisteredFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	occurredAt := e.OccurredAt
	if err := q.UpsertDeviceProjection(ctx, db.UpsertDeviceProjectionParams{
		ID:                  payload.ID,
		Hostname:            payload.Hostname,
		CertFingerprint:     payload.CertFingerprint,
		CertNotAfter:        payload.CertNotAfter,
		RegisteredAt:        &occurredAt,
		RegistrationTokenID: payload.RegistrationTokenID,
		ProjectionVersion:   e.SequenceNum,
	}); err != nil {
		return err
	}
	// Initial label rows for a freshly-registered device. ON CONFLICT
	// inside SetDeviceLabel makes the re-register revival path safe —
	// we keep whatever labels were already on the row (PL/pgSQL
	// behaviour: ON CONFLICT DO UPDATE kept the EXCLUDED labels, so
	// the new payload's labels are now applied per-key instead).
	for k, v := range payload.Labels {
		if err := q.SetDeviceLabel(ctx, db.SetDeviceLabelParams{
			DeviceID: payload.ID,
			Key:      k,
			Value:    v,
		}); err != nil {
			return err
		}
	}
	// Re-evaluation enqueue: freshly-registered devices with seed
	// labels (or no labels — equally relevant) must be considered by
	// every dynamic device group. Wave F replacement for the PL/pgSQL
	// device_labels_change_trigger fan-out.
	if err := enqueueDynamicDeviceGroupsForDevice(ctx, q, payload.ID); err != nil {
		return err
	}
	if payload.AssignedUserID == nil || *payload.AssignedUserID == "" {
		return nil
	}
	// Auto-assign cascade — token owner gets the device assignment.
	// Wrapped in the same WithTx as the upsert (the listener routes
	// DeviceRegistered through WithTx unconditionally) so the two
	// writes commit together.
	return q.InsertDeviceAssignedUserOnRegister(ctx, db.InsertDeviceAssignedUserOnRegisterParams{
		DeviceID:          payload.ID,
		UserID:            *payload.AssignedUserID,
		AssignedAt:        occurredAt,
		AssignedBy:        e.ActorID,
		ProjectionVersion: e.SequenceNum,
	})
}

func applyDeviceSeen(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceSeenFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	occurredAt := e.OccurredAt
	if _, err := q.UpdateDeviceSeenProjection(ctx, db.UpdateDeviceSeenProjectionParams{
		ID:                payload.ID,
		LastSeenAt:        &occurredAt,
		AgentVersion:      payload.AgentVersion,
		Hostname:          payload.Hostname,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		return err
	}
	return nil
}

func applyDeviceHeartbeat(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceHeartbeatFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	occurredAt := e.OccurredAt
	if _, err := q.UpdateDeviceHeartbeatProjection(ctx, db.UpdateDeviceHeartbeatProjectionParams{
		ID:                payload.ID,
		LastSeenAt:        &occurredAt,
		AgentVersion:      payload.AgentVersion,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		return err
	}
	return nil
}

func applyDeviceCertRenewed(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceCertRenewedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	certFingerprint := payload.CertFingerprint
	if _, err := q.UpdateDeviceCertRenewedProjection(ctx, db.UpdateDeviceCertRenewedProjectionParams{
		ID:                payload.ID,
		CertFingerprint:   &certFingerprint,
		CertNotAfter:      payload.CertNotAfter,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		return err
	}
	return nil
}

func applyDeviceLabelsUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceLabelsUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	if !payload.HasLabels {
		// "labels" key absent on the wire — preserve existing rows.
		return nil
	}
	advanced, err := advanceDeviceVersion(ctx, q, payload.ID, e.SequenceNum)
	if err != nil || !advanced {
		return err
	}
	if err := q.ClearDeviceLabels(ctx, payload.ID); err != nil {
		return err
	}
	for k, v := range payload.Labels {
		if err := q.SetDeviceLabel(ctx, db.SetDeviceLabelParams{
			DeviceID: payload.ID,
			Key:      k,
			Value:    v,
		}); err != nil {
			return err
		}
	}
	return enqueueDynamicDeviceGroupsForDevice(ctx, q, payload.ID)
}

func applyDeviceLabelSet(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceLabelSetFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	advanced, err := advanceDeviceVersion(ctx, q, payload.ID, e.SequenceNum)
	if err != nil || !advanced {
		return err
	}
	if err := q.SetDeviceLabel(ctx, db.SetDeviceLabelParams{
		DeviceID: payload.ID,
		Key:      payload.Key,
		Value:    payload.Value,
	}); err != nil {
		return err
	}
	return enqueueDynamicDeviceGroupsForDevice(ctx, q, payload.ID)
}

func applyDeviceLabelRemoved(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceLabelRemovedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	advanced, err := advanceDeviceVersion(ctx, q, payload.ID, e.SequenceNum)
	if err != nil || !advanced {
		return err
	}
	if err := q.RemoveDeviceLabel(ctx, db.RemoveDeviceLabelParams{
		DeviceID: payload.ID,
		Key:      payload.Key,
	}); err != nil {
		return err
	}
	return enqueueDynamicDeviceGroupsForDevice(ctx, q, payload.ID)
}

// advanceDeviceVersion bumps devices_projection.projection_version to
// sequenceNum if it was lower. Returns (true, nil) when the bump
// succeeded — meaning the event is newer than the row's last-applied
// state, so the caller should proceed with the child-table change.
// Returns (false, nil) when the event is stale and must be skipped
// (the corresponding label row would otherwise be overwritten by an
// out-of-order replay).
func advanceDeviceVersion(ctx context.Context, q *store.Queries, deviceID string, sequenceNum int64) (bool, error) {
	n, err := q.AdvanceDeviceProjectionVersion(ctx, db.AdvanceDeviceProjectionVersionParams{
		ID:                deviceID,
		ProjectionVersion: sequenceNum,
	})
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// enqueueDynamicDeviceGroupsForDevice queues every active dynamic
// device group for re-evaluation, tagging the queue entry with a
// human-readable reason ("device_<id>_changed"). Replaces the
// PL/pgSQL trigger_device_label_change / trigger_inventory_change /
// queue_dynamic_groups_for_device chain (Wave F, tracker #242).
func enqueueDynamicDeviceGroupsForDevice(ctx context.Context, q *store.Queries, deviceID string) error {
	return q.EnqueueAllDynamicDeviceGroups(ctx, "device_"+deviceID+"_changed")
}

func applyDeviceDeleted(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	n, err := q.SoftDeleteDeviceProjection(ctx, db.SoftDeleteDeviceProjectionParams{
		ID:                e.StreamID,
		ProjectionVersion: e.SequenceNum,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		// Stale DeviceDeleted replay against a row whose
		// projection_version has moved past this event. Skipping the
		// cascade (assigned-user wipe + assigned-group wipe) is
		// mandatory: otherwise an old delete re-applied by the
		// reconciler against a freshly-restored device would silently
		// nuke its assignments.
		return nil
	}
	if err := q.DeleteDeviceAssignedUsersByDevice(ctx, e.StreamID); err != nil {
		return err
	}
	if err := q.DeleteDeviceAssignedGroupsByDevice(ctx, e.StreamID); err != nil {
		return err
	}
	// Cascade out of every dynamic group membership the device
	// participated in. Replaces the PL/pgSQL device_deleted_trigger
	// (Wave F, tracker #242): scope the recount to just the affected
	// groups instead of the trigger's full-table sweep.
	affectedGroups, err := q.ListDeviceGroupMembershipsByDevice(ctx, e.StreamID)
	if err != nil {
		return err
	}
	if err := q.DeleteDeviceGroupMembershipsForDevice(ctx, e.StreamID); err != nil {
		return err
	}
	for _, groupID := range affectedGroups {
		if err := q.RecountDeviceGroupMembers(ctx, groupID); err != nil {
			return err
		}
	}
	return nil
}

func applyDeviceAssigned(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceAssignedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	return q.InsertDeviceAssignedUser(ctx, db.InsertDeviceAssignedUserParams{
		DeviceID:          payload.DeviceID,
		UserID:            payload.UserID,
		AssignedAt:        e.OccurredAt,
		AssignedBy:        e.ActorID,
		ProjectionVersion: e.SequenceNum,
	})
}

func applyDeviceUnassigned(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceUnassignedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	// Stale-replay DELETE protection: the SQL guard
	// `WHERE projection_version <= $N` rejects a stale Unassigned
	// replayed after a re-Assign — the live row's projection_version
	// was bumped by the re-Assign INSERT, so the stale Unassigned's
	// older sequence_num fails the guard. n == 0 here is silent (no
	// cascade to short-circuit), but the :execrows shape gives us
	// a hook to grow observability later if needed.
	if _, err := q.DeleteDeviceAssignedUser(ctx, db.DeleteDeviceAssignedUserParams{
		DeviceID:          payload.DeviceID,
		UserID:            payload.UserID,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		return err
	}
	return nil
}

func applyDeviceGroupAssigned(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceGroupAssignedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	return q.InsertDeviceAssignedGroup(ctx, db.InsertDeviceAssignedGroupParams{
		DeviceID:          payload.DeviceID,
		GroupID:           payload.GroupID,
		AssignedAt:        e.OccurredAt,
		AssignedBy:        e.ActorID,
		ProjectionVersion: e.SequenceNum,
	})
}

func applyDeviceGroupUnassigned(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceGroupUnassignedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	// Same stale-replay guard as DeviceUnassigned (assignment-table
	// DELETE protection from PR #179 CR catch).
	if _, err := q.DeleteDeviceAssignedGroup(ctx, db.DeleteDeviceAssignedGroupParams{
		DeviceID:          payload.DeviceID,
		GroupID:           payload.GroupID,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		return err
	}
	return nil
}

func applyDeviceSyncIntervalSet(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := DeviceSyncIntervalSetFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	if _, err := q.UpdateDeviceSyncIntervalProjection(ctx, db.UpdateDeviceSyncIntervalProjectionParams{
		ID:                  payload.ID,
		SyncIntervalMinutes: payload.SyncIntervalMinutes,
		ProjectionVersion:   e.SequenceNum,
	}); err != nil {
		return err
	}
	return nil
}
