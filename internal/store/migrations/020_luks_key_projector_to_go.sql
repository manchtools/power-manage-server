-- Replace project_luks_key_event() with a no-op stub. The actual
-- projection logic now lives in projectors.LuksKeyListener (Go,
-- post-commit). The shared project_event() dispatcher trigger still
-- PERFORMs project_luks_key_event(NEW) for every luks_key-stream
-- event; the no-op stub keeps that dispatch quiet (no
-- projection_errors entries) until the dispatcher itself is rewritten
-- to skip stream types with Go projectors.
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. The four event types (Rotated + three revocation
--     variants) and the event commit were atomic.
--   - After: Go listener fires post-commit. LuksKeyRotated's three
--     writes (mark previous not-current, insert new, trim history to
--     3) remain atomic with each other (store.WithTx) but not with
--     the event commit. Revocation events are single UPDATEs and
--     don't need a tx wrap. LUKS reads are operator-driven (recover
--     a passphrase, audit revocation status) — not hot-path RPCs —
--     so the post-commit gap closes before any human-driven query.
--
-- LuksDeviceKeyRevocationRequested stays a no-op in the Go listener
-- (the deleted PL/pgSQL function also lacked a case for it). The
-- Requested event is a marker the dispatcher handler appends before
-- enqueueing; revocation_status only changes once Dispatched /
-- Revoked / Failed lands.
--
-- See manchtools/power-manage-server#99. Fourth port under the
-- projector-migration pattern (#96 canary, #97 totp, #98 lps_password,
-- #99 luks_key).
--
-- Refs tracker #107.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_luks_key_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.LuksKeyListener. See migration
    -- comment + the listener wiring in cmd/control/main.go via
    -- projectors.WireAll.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the original PL/pgSQL projector verbatim from migration 003.

-- +goose StatementBegin
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
