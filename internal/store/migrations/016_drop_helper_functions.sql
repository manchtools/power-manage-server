-- Drop two PL/pgSQL helper functions that no longer need to live in
-- the database:
--
--   - get_stream_at()              — point-in-time stream replay
--                                    helper. Zero callers in code or
--                                    tests; only referenced in
--                                    cmd/control/README.md as a
--                                    "you can run this in psql"
--                                    suggestion. Operators that need
--                                    point-in-time replay can write
--                                    the inline SELECT directly or
--                                    add a sqlc query later if it
--                                    becomes a hot operation.
--
--   - get_device_sync_interval()   — moved into a sqlc query in
--                                    queries/devices.sql with the
--                                    same resolution semantics
--                                    (device override > group MIN >
--                                    0). The Go-side query is now
--                                    the single source of truth and
--                                    is easier to read, debug, and
--                                    extend than the PL/pgSQL
--                                    function it replaces.
--
-- Two helpers explicitly NOT dropped in this migration:
--
--   - generate_ulid()             — still called by
--                                    evaluate_dynamic_group() in
--                                    migration 004 to synthesise
--                                    group_id values during dynamic
--                                    group rebuilds. Will be removed
--                                    when the dynamic-query
--                                    interpreter is ported to Go
--                                    (Group 2, planned for
--                                    2026.07).
--
--   - resolve_inventory_field()    — still called by
--                                    evaluate_condition_v2() and
--                                    evaluate_user_condition() in
--                                    migrations 004/006. Same
--                                    deferral as generate_ulid().
--
-- See manchtools/power-manage-server#95, tracker #107.

-- +goose Up

DROP FUNCTION IF EXISTS get_stream_at(TEXT, TEXT, TIMESTAMPTZ);
DROP FUNCTION IF EXISTS get_device_sync_interval(TEXT);


-- +goose Down

-- Restore get_stream_at verbatim from migration 004 so a Down + Up
-- cycle leaves the database in pre-#95 state.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION get_stream_at(
    p_stream_type TEXT,
    p_stream_id TEXT,
    p_at TIMESTAMPTZ
) RETURNS SETOF events AS $$
BEGIN
    RETURN QUERY
    SELECT * FROM events
    WHERE stream_type = p_stream_type
      AND stream_id = p_stream_id
      AND occurred_at <= p_at
    ORDER BY stream_version;
END;
$$ LANGUAGE plpgsql STABLE;
-- +goose StatementEnd

-- Restore get_device_sync_interval verbatim from migration 004.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION get_device_sync_interval(p_device_id TEXT) RETURNS INTEGER AS $$
DECLARE
    device_interval INTEGER;
    group_interval INTEGER;
BEGIN
    SELECT sync_interval_minutes INTO device_interval
    FROM devices_projection
    WHERE id = p_device_id AND is_deleted = FALSE;

    IF device_interval IS NOT NULL AND device_interval > 0 THEN
        RETURN device_interval;
    END IF;

    SELECT MIN(dg.sync_interval_minutes) INTO group_interval
    FROM device_groups_projection dg
    JOIN device_group_members_projection dgm ON dgm.group_id = dg.id
    WHERE dgm.device_id = p_device_id
      AND dg.is_deleted = FALSE
      AND dg.sync_interval_minutes > 0;

    IF group_interval IS NOT NULL AND group_interval > 0 THEN
        RETURN group_interval;
    END IF;

    RETURN 0;
END;
$$ LANGUAGE plpgsql STABLE;
-- +goose StatementEnd
