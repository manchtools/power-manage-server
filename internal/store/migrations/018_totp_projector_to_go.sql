-- Replace project_totp_event() with a no-op stub. The actual
-- projection logic now lives in projectors.TotpListener (Go,
-- post-commit). The shared project_event() dispatcher trigger
-- still PERFORMs project_totp_event(NEW) for every totp-stream
-- event; the no-op stub keeps that dispatch quiet (no
-- projection_errors entries) until the dispatcher itself is
-- rewritten to skip stream types with Go projectors.
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. totp_projection AND users_projection.totp_enabled
--     updated atomically with the event commit.
--   - After: Go listener fires post-commit. Both writes happen
--     async (~ms after the event lands). users_projection.totp_enabled
--     is read on the auth/login path (NOT on every API call), so
--     the post-commit gap closes well before the next read in
--     practice. The login flow's own logout/login cycle dwarfs
--     the listener latency.
--
-- See manchtools/power-manage-server#97. Second port under the
-- projector-migration pattern (#96 was the canary).

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_totp_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.TotpListener. See migration
    -- comment + the listener wiring in cmd/control/main.go.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the original PL/pgSQL projector verbatim from migration 003.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_totp_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'TOTPSetupInitiated' THEN
            INSERT INTO totp_projection (
                user_id, secret_encrypted, verified, enabled,
                backup_codes_hash, backup_codes_used,
                created_at, updated_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'secret_encrypted',
                FALSE,
                FALSE,
                ARRAY(SELECT jsonb_array_elements_text(event.data->'backup_codes_hash')),
                ARRAY(SELECT FALSE FROM jsonb_array_elements_text(event.data->'backup_codes_hash')),
                event.occurred_at,
                event.occurred_at,
                event.sequence_num
            )
            ON CONFLICT (user_id) DO UPDATE SET
                secret_encrypted = EXCLUDED.secret_encrypted,
                verified = FALSE,
                enabled = FALSE,
                backup_codes_hash = EXCLUDED.backup_codes_hash,
                backup_codes_used = EXCLUDED.backup_codes_used,
                updated_at = EXCLUDED.updated_at,
                projection_version = EXCLUDED.projection_version;

        WHEN 'TOTPVerified' THEN
            UPDATE totp_projection
            SET verified = TRUE,
                enabled = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE user_id = event.stream_id;

            UPDATE users_projection
            SET totp_enabled = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'TOTPDisabled' THEN
            DELETE FROM totp_projection WHERE user_id = event.stream_id;

            UPDATE users_projection
            SET totp_enabled = FALSE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'TOTPBackupCodeUsed' THEN
            UPDATE totp_projection
            SET backup_codes_used[(event.data->>'index')::int + 1] = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE user_id = event.stream_id;

        WHEN 'TOTPBackupCodesRegenerated' THEN
            UPDATE totp_projection
            SET backup_codes_hash = ARRAY(SELECT jsonb_array_elements_text(event.data->'backup_codes_hash')),
                backup_codes_used = ARRAY(SELECT FALSE FROM jsonb_array_elements_text(event.data->'backup_codes_hash')),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE user_id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
