-- Replace project_scim_group_mapping_event() with a no-op stub.
-- The actual projection logic now lives in
-- projectors.SCIMGroupMappingListener (Go, post-commit).
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. All three event types (Mapped, Unmapped,
--     MappingUpdated) atomic with the event commit.
--   - After: Go listener fires post-commit. Each event type is a
--     single statement (UPSERT, DELETE, UPDATE) so no tx wrap is
--     needed.
--
-- Tightening: SCIMGroupMappingUpdated now has a
-- `WHERE projection_version < $N` guard rejecting stale reconciler
-- replays. The PL/pgSQL projector lacked it.
--
-- See manchtools/power-manage-server#105. Tenth port under the
-- projector-migration pattern.
--
-- Refs tracker #107.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_scim_group_mapping_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.SCIMGroupMappingListener.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the original PL/pgSQL projector verbatim from migration 003.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_scim_group_mapping_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'SCIMGroupMapped' THEN
            INSERT INTO scim_group_mapping_projection (
                id, provider_id, scim_group_id, scim_display_name,
                user_group_id, created_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'provider_id',
                event.data->>'scim_group_id',
                COALESCE(event.data->>'scim_display_name', ''),
                event.data->>'user_group_id',
                event.occurred_at,
                event.sequence_num
            )
            ON CONFLICT (provider_id, scim_group_id) DO UPDATE SET
                scim_display_name = EXCLUDED.scim_display_name,
                user_group_id = EXCLUDED.user_group_id,
                projection_version = EXCLUDED.projection_version;

        WHEN 'SCIMGroupUnmapped' THEN
            DELETE FROM scim_group_mapping_projection
            WHERE provider_id = event.data->>'provider_id'
              AND scim_group_id = event.data->>'scim_group_id';

        WHEN 'SCIMGroupMappingUpdated' THEN
            UPDATE scim_group_mapping_projection
            SET scim_display_name = COALESCE(event.data->>'scim_display_name', scim_display_name),
                projection_version = event.sequence_num
            WHERE provider_id = event.data->>'provider_id'
              AND scim_group_id = event.data->>'scim_group_id';

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
