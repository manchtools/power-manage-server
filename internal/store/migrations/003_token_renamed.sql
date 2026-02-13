-- +goose Up

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
                COALESCE(event.data->>'owner_id', event.actor_id),
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

-- +goose Down

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
                COALESCE(event.data->>'owner_id', event.actor_id),
                event.sequence_num
            );

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
