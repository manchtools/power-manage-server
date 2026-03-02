-- +goose Up

-- Junction table: devices ↔ users (many-to-many)
CREATE TABLE device_assigned_users_projection (
    device_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by TEXT NOT NULL DEFAULT '',
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, user_id)
);

CREATE INDEX idx_device_assigned_users_user ON device_assigned_users_projection(user_id);

-- Junction table: devices ↔ user groups (many-to-many)
CREATE TABLE device_assigned_groups_projection (
    device_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by TEXT NOT NULL DEFAULT '',
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, group_id)
);

CREATE INDEX idx_device_assigned_groups_group ON device_assigned_groups_projection(group_id);

-- Migrate existing assigned_user_id data into the new junction table
INSERT INTO device_assigned_users_projection (device_id, user_id, assigned_at, assigned_by, projection_version)
SELECT id, assigned_user_id, registered_at, '', projection_version
FROM devices_projection
WHERE assigned_user_id IS NOT NULL AND is_deleted = FALSE;

-- Drop the old column and index
DROP INDEX IF EXISTS idx_devices_assigned_user;
ALTER TABLE devices_projection DROP COLUMN assigned_user_id;

-- Replace device event projector with multi-user assignment support
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

-- +goose Down

-- Re-add the assigned_user_id column
ALTER TABLE devices_projection ADD COLUMN assigned_user_id TEXT;
CREATE INDEX idx_devices_assigned_user ON devices_projection (assigned_user_id);

-- Migrate first assigned user back (pick one arbitrarily)
-- +goose StatementBegin
DO $$
BEGIN
    UPDATE devices_projection d
    SET assigned_user_id = (
        SELECT user_id FROM device_assigned_users_projection
        WHERE device_id = d.id
        ORDER BY assigned_at ASC
        LIMIT 1
    );
END
$$;
-- +goose StatementEnd

-- Drop junction tables
DROP TABLE IF EXISTS device_assigned_groups_projection;
DROP TABLE IF EXISTS device_assigned_users_projection;

-- Restore original device event projector (from migration 001)
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

        WHEN 'DeviceAssigned' THEN
            UPDATE devices_projection
            SET assigned_user_id = event.data->>'user_id',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceUnassigned' THEN
            UPDATE devices_projection
            SET assigned_user_id = NULL,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

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
