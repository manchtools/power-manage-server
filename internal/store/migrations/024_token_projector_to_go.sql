-- Replace project_token_event() with a no-op stub. The actual
-- projection logic now lives in projectors.TokenListener (Go,
-- post-commit). The shared project_event() dispatcher trigger
-- still PERFORMs project_token_event(NEW) for every token-stream
-- event; the no-op stub keeps that dispatch quiet (no
-- projection_errors entries) until the dispatcher itself is
-- rewritten to skip stream types with Go projectors.
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. All six event types (Created, Renamed, Used,
--     Disabled, Enabled, Deleted) atomic with the event commit.
--   - After: Go listener fires post-commit. Each event type
--     produces a single statement, so no tx wrap is needed. The
--     handler's read-after-write paths
--     (token_handler.{Create,Rename,SetDisabled,Delete}Token reading
--     back from tokens_projection) still see the projection because
--     fireListeners is synchronous.
--
-- Tightening: every UPDATE now has a `WHERE projection_version < $N`
-- guard, rejecting stale reconciler replays. This is load-bearing
-- for TokenUsed in particular — without the guard, a duplicate
-- replay would erroneously bump current_uses twice.
--
-- See manchtools/power-manage-server#103. Eighth port under the
-- projector-migration pattern.
--
-- Refs tracker #107.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_token_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.TokenListener. See migration
    -- comment + the listener wiring in cmd/control/main.go via
    -- projectors.WireAll.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the original PL/pgSQL projector verbatim from migration 011.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_token_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'TokenCreated' THEN
            INSERT INTO tokens_projection (
                id, value_hash, name, one_time, max_uses, expires_at,
                created_at, created_by, owner_id, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'value_hash',
                COALESCE(event.data->>'name', ''),
                COALESCE((event.data->>'one_time')::BOOLEAN, FALSE),
                COALESCE((event.data->>'max_uses')::INTEGER, 0),
                CASE WHEN event.data->>'expires_at' IS NOT NULL
                     THEN (event.data->>'expires_at')::TIMESTAMPTZ
                     ELSE NULL END,
                event.occurred_at,
                event.actor_id,
                event.data->>'owner_id',
                event.sequence_num
            );

        WHEN 'TokenRenamed' THEN
            UPDATE tokens_projection
            SET name = event.data->>'name',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'TokenUsed' THEN
            UPDATE tokens_projection
            SET current_uses = current_uses + 1,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'TokenDisabled' THEN
            UPDATE tokens_projection
            SET disabled = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'TokenEnabled' THEN
            UPDATE tokens_projection
            SET disabled = FALSE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'TokenDeleted' THEN
            UPDATE tokens_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
