-- evaluate_queued_dynamic_groups + evaluate_queued_dynamic_user_groups
-- now return (evaluated_count INT, more BOOLEAN) so the caller can
-- terminate the drain loop explicitly instead of inferring queue-
-- empty from "count < batch_limit". Closes audit F035 /
-- manchtools/power-manage-server#168.
--
-- Edge case the inference shape gets wrong: a batch that processes
-- EXACTLY the limit triggers one extra round-trip that observes the
-- now-empty queue and returns 0 — wasteful but not incorrect. The
-- explicit `more` flag is a single `SELECT EXISTS(...)` probe after
-- the batch UPDATE, paid once per batch instead of per-call.
--
-- Function signature change: PostgreSQL can't CREATE OR REPLACE a
-- function with a different return type, so we DROP first. The two
-- callers (sqlc-generated EvaluateQueuedDynamicGroups* and the
-- evaluate_dynamic_groups_on_label_change() trigger that PERFORMs
-- this function) all tolerate the new shape: the sqlc wrapper is
-- updated alongside this migration, and the trigger ignores the
-- return value.
-- +goose Up

DROP FUNCTION IF EXISTS evaluate_queued_dynamic_groups();
DROP FUNCTION IF EXISTS evaluate_queued_dynamic_user_groups();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION evaluate_queued_dynamic_groups(OUT evaluated_count INTEGER, OUT more BOOLEAN) AS $$
DECLARE
    queue_record RECORD;
    batch_limit  CONSTANT INTEGER := 1000;
BEGIN
    evaluated_count := 0;
    FOR queue_record IN
        SELECT group_id FROM dynamic_group_evaluation_queue
        ORDER BY queued_at LIMIT batch_limit
    LOOP
        PERFORM evaluate_dynamic_group(queue_record.group_id);
        evaluated_count := evaluated_count + 1;
    END LOOP;

    -- more = true only if the queue still has rows AFTER the batch.
    -- The EXISTS probe is cheap (LIMIT 1) and avoids the inference
    -- shape's spurious tail iteration on a count == batch_limit
    -- boundary hit.
    SELECT EXISTS (
        SELECT 1 FROM dynamic_group_evaluation_queue LIMIT 1
    ) INTO more;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION evaluate_queued_dynamic_user_groups(OUT evaluated_count INTEGER, OUT more BOOLEAN) AS $$
DECLARE
    queue_record RECORD;
    batch_limit  CONSTANT INTEGER := 100;
BEGIN
    evaluated_count := 0;
    FOR queue_record IN
        SELECT group_id FROM dynamic_user_group_evaluation_queue
        ORDER BY queued_at LIMIT batch_limit
    LOOP
        PERFORM evaluate_dynamic_user_group(queue_record.group_id);
        evaluated_count := evaluated_count + 1;
    END LOOP;

    SELECT EXISTS (
        SELECT 1 FROM dynamic_user_group_evaluation_queue LIMIT 1
    ) INTO more;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down

DROP FUNCTION IF EXISTS evaluate_queued_dynamic_groups();
DROP FUNCTION IF EXISTS evaluate_queued_dynamic_user_groups();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION evaluate_queued_dynamic_groups() RETURNS INTEGER AS $$
DECLARE
    evaluated_count INTEGER := 0;
    queue_record RECORD;
BEGIN
    FOR queue_record IN
        SELECT group_id FROM dynamic_group_evaluation_queue
        ORDER BY queued_at LIMIT 1000
    LOOP
        PERFORM evaluate_dynamic_group(queue_record.group_id);
        evaluated_count := evaluated_count + 1;
    END LOOP;
    RETURN evaluated_count;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION evaluate_queued_dynamic_user_groups() RETURNS INTEGER AS $$
DECLARE
    evaluated_count INTEGER := 0;
    queue_record RECORD;
BEGIN
    FOR queue_record IN
        SELECT group_id FROM dynamic_user_group_evaluation_queue
        ORDER BY queued_at LIMIT 100
    LOOP
        PERFORM evaluate_dynamic_user_group(queue_record.group_id);
        evaluated_count := evaluated_count + 1;
    END LOOP;
    RETURN evaluated_count;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
