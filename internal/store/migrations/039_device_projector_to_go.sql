-- Replace project_device_event() with a no-op stub. The actual
-- projection logic now lives in projectors.DeviceListener (Go,
-- post-commit). The shared project_event() dispatcher trigger still
-- PERFORMs project_device_event(NEW) for every device-stream event;
-- the no-op stub keeps that dispatch quiet (no
-- plpgsql_projection_errors entries) until the Phase 2 cleanup
-- migration drops every still-PL/pgSQL WHEN clause from the
-- dispatcher.
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. The thirteen event types (Registered, Seen,
--     Heartbeat, CertRenewed, LabelsUpdated, LabelSet, LabelRemoved,
--     Deleted, Assigned, Unassigned, GroupAssigned, GroupUnassigned,
--     SyncIntervalSet) and their cascades (Registered's auto-assign,
--     Deleted's assignment-table wipe) were atomic with the event
--     commit.
--   - After: Go listener fires post-commit. Every multi-write event
--     (DeviceRegistered when assigned_user_id is present;
--     DeviceDeleted with its two assignment-table wipes) wraps its
--     writes in store.WithTx so the cascade stays atomic with itself,
--     but not with the event commit. The handler's read-after-write
--     paths (RegisterDevice / DeleteDevice / etc. reading back from
--     devices_projection) still see the projection because
--     fireListeners is synchronous — the listener has already run by
--     the time AppendEvent returns.
--
-- Tightening: every UPDATE on devices_projection (Seen, Heartbeat,
-- CertRenewed, LabelsUpdated, LabelSet, LabelRemoved,
-- SyncIntervalSet, soft-delete) now carries an explicit
-- `WHERE projection_version < $N` guard, rejecting stale reconciler
-- replays. The PL/pgSQL projector stamped projection_version without
-- a guard.
--
-- Asymmetric-guard discipline (per the role + identity_provider +
-- action_set + assignment + user_group + device_group +
-- compliance_policy + compliance + action+definition + execution
-- ports): the guarded SoftDelete uses :execrows, and the listener
-- short-circuits the cascade (assigned-user wipe + assigned-group
-- wipe) when n == 0 — otherwise a stale DeviceDeleted re-applied
-- later would silently nuke a freshly-restored device's assignments.
--
-- Stale-replay DELETE protection on the assignment junction tables:
-- DeviceUnassigned and DeviceGroupUnassigned both carry a
-- `WHERE projection_version <= $N` guard via :execrows so a stale
-- Unassigned replayed after a re-Assign cannot wipe the live row.
-- The live row's projection_version was bumped by the re-Assign
-- INSERT, so the stale Unassigned's older sequence_num fails the
-- guard. CR catch on PR #179 pattern, applied here to the
-- device_assigned_users / device_assigned_groups projections.
--
-- DeviceRegistered's UPSERT preserves the PL/pgSQL projector's
-- soft-delete revival semantic: ON CONFLICT (id) DO UPDATE flips
-- is_deleted=FALSE so an operator re-enrolling a previously-deleted
-- device id gets the row back, with the event-sourced timeline
-- preserved.
--
-- See manchtools/power-manage-server#136. Ninth port under Phase 2
-- of tracker #107's projector-migration pattern.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_device_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.DeviceListener. See migration
    -- comment + the listener wiring in cmd/control/main.go via
    -- projectors.WireAll.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the PL/pgSQL projector verbatim from migration 002 (the
-- last definition before this port — multi-user assignment support
-- with junction tables, the body that was in place when this port
-- ran).

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_device_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'DeviceRegistered' THEN
            INSERT INTO devices_projection (
                id, hostname, cert_fingerprint, cert_not_after,
                registered_at, last_seen_at, registration_token_id,
                labels, projection_version
            ) VALUES (
                event.stream_id,
                COALESCE(event.data->>'hostname', ''),
                event.data->>'cert_fingerprint',
                CASE WHEN event.data->>'cert_not_after' IS NOT NULL
                     THEN (event.data->>'cert_not_after')::TIMESTAMPTZ
                     ELSE NULL END,
                event.occurred_at,
                event.occurred_at,
                event.data->>'registration_token_id',
                COALESCE(event.data->'labels', '{}'),
                event.sequence_num
            )
            ON CONFLICT (id) DO UPDATE SET
                hostname = EXCLUDED.hostname,
                cert_fingerprint = EXCLUDED.cert_fingerprint,
                cert_not_after = EXCLUDED.cert_not_after,
                registered_at = EXCLUDED.registered_at,
                last_seen_at = EXCLUDED.last_seen_at,
                registration_token_id = EXCLUDED.registration_token_id,
                labels = EXCLUDED.labels,
                projection_version = EXCLUDED.projection_version,
                is_deleted = FALSE;

            -- Auto-assign device to token owner if present
            IF event.data->>'assigned_user_id' IS NOT NULL THEN
                INSERT INTO device_assigned_users_projection (device_id, user_id, assigned_at, assigned_by, projection_version)
                VALUES (event.stream_id, event.data->>'assigned_user_id', event.occurred_at, event.actor_id, event.sequence_num)
                ON CONFLICT (device_id, user_id) DO NOTHING;
            END IF;

        WHEN 'DeviceSeen' THEN
            UPDATE devices_projection
            SET last_seen_at = event.occurred_at,
                agent_version = COALESCE(event.data->>'agent_version', agent_version),
                hostname = COALESCE(NULLIF(event.data->>'hostname', ''), hostname),
                projection_version = event.sequence_num,
                is_deleted = FALSE
            WHERE id = event.stream_id;

        WHEN 'DeviceHeartbeat' THEN
            UPDATE devices_projection
            SET last_seen_at = event.occurred_at,
                agent_version = COALESCE(event.data->>'agent_version', agent_version),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceCertRenewed' THEN
            UPDATE devices_projection
            SET cert_fingerprint = event.data->>'cert_fingerprint',
                cert_not_after = CASE WHEN event.data->>'cert_not_after' IS NOT NULL
                                      THEN (event.data->>'cert_not_after')::TIMESTAMPTZ
                                      ELSE cert_not_after END,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceLabelsUpdated' THEN
            UPDATE devices_projection
            SET labels = COALESCE(event.data->'labels', labels),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceLabelSet' THEN
            UPDATE devices_projection
            SET labels = COALESCE(labels, '{}'::jsonb) || jsonb_build_object(event.data->>'key', event.data->>'value'),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceLabelRemoved' THEN
            UPDATE devices_projection
            SET labels = labels - (event.data->>'key'),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceDeleted' THEN
            UPDATE devices_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Clean up assignments when device is deleted
            DELETE FROM device_assigned_users_projection WHERE device_id = event.stream_id;
            DELETE FROM device_assigned_groups_projection WHERE device_id = event.stream_id;

        WHEN 'DeviceAssigned' THEN
            INSERT INTO device_assigned_users_projection (device_id, user_id, assigned_at, assigned_by, projection_version)
            VALUES (event.stream_id, event.data->>'user_id', event.occurred_at, event.actor_id, event.sequence_num)
            ON CONFLICT (device_id, user_id) DO NOTHING;

        WHEN 'DeviceUnassigned' THEN
            DELETE FROM device_assigned_users_projection
            WHERE device_id = event.stream_id AND user_id = event.data->>'user_id';

        WHEN 'DeviceGroupAssigned' THEN
            INSERT INTO device_assigned_groups_projection (device_id, group_id, assigned_at, assigned_by, projection_version)
            VALUES (event.stream_id, event.data->>'group_id', event.occurred_at, event.actor_id, event.sequence_num)
            ON CONFLICT (device_id, group_id) DO NOTHING;

        WHEN 'DeviceGroupUnassigned' THEN
            DELETE FROM device_assigned_groups_projection
            WHERE device_id = event.stream_id AND group_id = event.data->>'group_id';

        WHEN 'DeviceSyncIntervalSet' THEN
            UPDATE devices_projection
            SET sync_interval_minutes = COALESCE((event.data->>'sync_interval_minutes')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
