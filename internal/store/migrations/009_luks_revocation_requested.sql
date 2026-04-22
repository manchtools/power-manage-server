-- Add LuksDeviceKeyRevocationRequested event to the luks_key projector.
--
-- Rationale: previously the revocation flow enqueued the Asynq task first
-- and only appended a LuksDeviceKeyRevocationDispatched event afterwards.
-- If the enqueue succeeded but the follow-up event append failed, the
-- agent would revoke the key while the audit stream had no record of the
-- operator ever asking for it — awkward for compliance, worse for incident
-- response.
--
-- The revised flow in RevokeLuksDeviceKey emits this Requested event
-- BEFORE attempting the enqueue, so operator intent is captured durably
-- regardless of enqueue outcome. On enqueue success the handler follows
-- up with the existing Dispatched event; on failure it emits the existing
-- Failed event.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_luks_key_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'LuksKeyRotated' THEN
            -- Mark all prior keys for this (device, device_path) as non-current.
            UPDATE luks_keys_projection
            SET is_current = FALSE
            WHERE device_id = event.data->>'device_id'
              AND device_path = event.data->>'device_path'
              AND is_current = TRUE;

            INSERT INTO luks_keys_projection (
                id, device_id, action_id, device_path, passphrase_encrypted,
                rotated_at, rotation_reason, is_current
            ) VALUES (
                event.stream_id,
                event.data->>'device_id',
                event.data->>'action_id',
                event.data->>'device_path',
                (event.data->>'passphrase')::BYTEA,
                COALESCE((event.data->>'rotated_at')::TIMESTAMPTZ, event.occurred_at),
                event.data->>'rotation_reason',
                TRUE
            );

        WHEN 'LuksDeviceKeyRevocationRequested' THEN
            -- Durable operator-intent record emitted BEFORE the Asynq
            -- enqueue. Sets revocation_status = 'requested'; the follow-up
            -- Dispatched / Failed event overwrites to 'dispatched' or
            -- 'failed'. If the follow-up append itself fails, the
            -- projection lingers at 'requested' — still a meaningful
            -- audit state, not a silent no-op.
            UPDATE luks_keys_projection
            SET revocation_status = 'requested',
                revocation_error = NULL,
                revocation_at = (event.data->>'requested_at')::TIMESTAMPTZ
            WHERE device_id = event.data->>'device_id'
              AND action_id = event.data->>'action_id'
              AND is_current = TRUE;

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
-- Revert to the pre-requested projector (no 'requested' case).
CREATE OR REPLACE FUNCTION project_luks_key_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'LuksKeyRotated' THEN
            UPDATE luks_keys_projection
            SET is_current = FALSE
            WHERE device_id = event.data->>'device_id'
              AND device_path = event.data->>'device_path'
              AND is_current = TRUE;

            INSERT INTO luks_keys_projection (
                id, device_id, action_id, device_path, passphrase_encrypted,
                rotated_at, rotation_reason, is_current
            ) VALUES (
                event.stream_id,
                event.data->>'device_id',
                event.data->>'action_id',
                event.data->>'device_path',
                (event.data->>'passphrase')::BYTEA,
                COALESCE((event.data->>'rotated_at')::TIMESTAMPTZ, event.occurred_at),
                event.data->>'rotation_reason',
                TRUE
            );

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
