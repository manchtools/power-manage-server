-- Replace project_user_selection_event() with a no-op stub. The
-- actual projection logic now lives in
-- projectors.UserSelectionListener (Go, post-commit).
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. The single event type (UserSelectionChanged) +
--     UPSERT atomic with the event commit.
--   - After: Go listener fires post-commit. Single UPSERT statement
--     so no tx wrap needed.
--
-- Tightening: the UPSERT's conflict-update path now has a
-- `WHERE user_selections_projection.projection_version <
-- EXCLUDED.projection_version` guard rejecting stale reconciler
-- replays. The PL/pgSQL projector lacked it.
--
-- ⚠️ Known issue (#125): the `user_selections` entry in
-- AllRebuildTargets will dispatch to the no-op stub after this PR
-- merges, breaking emergency rebuild via RebuildAll(ctx,
-- "user_selections"). Same pattern affects `roles` and `tokens`
-- since their respective ports merged. Tracked separately at #125.
--
-- See manchtools/power-manage-server#106. Eleventh and final port
-- under tracker #107's projector-migration pattern.
--
-- Refs tracker #107.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_selection_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.UserSelectionListener.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the original PL/pgSQL projector verbatim from migration 002.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_selection_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'UserSelectionChanged' THEN
            INSERT INTO user_selections_projection (
                id, device_id, source_type, source_id, selected,
                updated_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'device_id',
                event.data->>'source_type',
                event.data->>'source_id',
                COALESCE((event.data->>'selected')::BOOLEAN, FALSE),
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            ) ON CONFLICT (device_id, source_type, source_id) DO UPDATE
            SET selected = COALESCE((event.data->>'selected')::BOOLEAN, FALSE),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
