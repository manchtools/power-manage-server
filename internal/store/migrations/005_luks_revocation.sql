-- +goose Up

-- Track LUKS device-bound key revocation status on existing keys.
ALTER TABLE luks_keys_projection
    ADD COLUMN revocation_status TEXT,
    ADD COLUMN revocation_error TEXT,
    ADD COLUMN revocation_at TIMESTAMPTZ;

-- +goose StatementBegin
-- Update projector to handle revocation events.
CREATE OR REPLACE FUNCTION project_luks_key_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'LuksKeyRotated' THEN
            -- Mark previous keys as not current for this device+action+device_path
            UPDATE luks_keys_projection
            SET is_current = FALSE
            WHERE device_id = event.data->>'device_id'
              AND action_id = event.data->>'action_id'
              AND device_path = event.data->>'device_path';

            -- Insert new key (revocation resets on rotation)
            INSERT INTO luks_keys_projection
                (device_id, action_id, device_path, passphrase, rotated_at, rotation_reason)
            VALUES (
                event.data->>'device_id',
                event.data->>'action_id',
                event.data->>'device_path',
                event.data->>'passphrase',
                (event.data->>'rotated_at')::TIMESTAMPTZ,
                COALESCE(event.data->>'rotation_reason', 'scheduled')
            );

            -- Keep only last 3 keys per device+action+device_path
            DELETE FROM luks_keys_projection
            WHERE id NOT IN (
                SELECT id FROM luks_keys_projection
                WHERE device_id = event.data->>'device_id'
                  AND action_id = event.data->>'action_id'
                  AND device_path = event.data->>'device_path'
                ORDER BY rotated_at DESC LIMIT 3
            )
            AND device_id = event.data->>'device_id'
            AND action_id = event.data->>'action_id'
            AND device_path = event.data->>'device_path';

        WHEN 'LuksDeviceKeyRevocationDispatched' THEN
            UPDATE luks_keys_projection
            SET revocation_status = 'dispatched',
                revocation_error = NULL,
                revocation_at = (event.data->>'dispatched_at')::TIMESTAMPTZ
            WHERE device_id = event.data->>'device_id'
              AND action_id = event.data->>'action_id'
              AND is_current = TRUE;

        WHEN 'LuksDeviceKeyRevoked' THEN
            UPDATE luks_keys_projection
            SET revocation_status = 'success',
                revocation_error = NULL,
                revocation_at = (event.data->>'revoked_at')::TIMESTAMPTZ
            WHERE device_id = event.data->>'device_id'
              AND action_id = event.data->>'action_id'
              AND is_current = TRUE;

        WHEN 'LuksDeviceKeyRevocationFailed' THEN
            UPDATE luks_keys_projection
            SET revocation_status = 'failed',
                revocation_error = event.data->>'error',
                revocation_at = (event.data->>'failed_at')::TIMESTAMPTZ
            WHERE device_id = event.data->>'device_id'
              AND action_id = event.data->>'action_id'
              AND is_current = TRUE;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Restore original projector without revocation events.
CREATE OR REPLACE FUNCTION project_luks_key_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'LuksKeyRotated' THEN
            UPDATE luks_keys_projection
            SET is_current = FALSE
            WHERE device_id = event.data->>'device_id'
              AND action_id = event.data->>'action_id'
              AND device_path = event.data->>'device_path';

            INSERT INTO luks_keys_projection
                (device_id, action_id, device_path, passphrase, rotated_at, rotation_reason)
            VALUES (
                event.data->>'device_id',
                event.data->>'action_id',
                event.data->>'device_path',
                event.data->>'passphrase',
                (event.data->>'rotated_at')::TIMESTAMPTZ,
                COALESCE(event.data->>'rotation_reason', 'scheduled')
            );

            DELETE FROM luks_keys_projection
            WHERE id NOT IN (
                SELECT id FROM luks_keys_projection
                WHERE device_id = event.data->>'device_id'
                  AND action_id = event.data->>'action_id'
                  AND device_path = event.data->>'device_path'
                ORDER BY rotated_at DESC LIMIT 3
            )
            AND device_id = event.data->>'device_id'
            AND action_id = event.data->>'action_id'
            AND device_path = event.data->>'device_path';
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

ALTER TABLE luks_keys_projection
    DROP COLUMN revocation_status,
    DROP COLUMN revocation_error,
    DROP COLUMN revocation_at;
