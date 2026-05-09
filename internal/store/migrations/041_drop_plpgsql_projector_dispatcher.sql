-- Final cleanup of the PL/pgSQL projector dispatcher.
--
-- Tracker #136 ported the eleven domain projectors (action_set,
-- assignment, user_group, device_group, compliance_policy,
-- compliance, action+definition, execution, device, user) to Go
-- listeners under projectors.WireAll. Each port left the PL/pgSQL
-- function body as a no-op stub so the shared project_event()
-- dispatcher trigger could keep PERFORMing it without raising
-- plpgsql_projection_errors during the rolling rollout.
--
-- After PR #183 (the user port) merged, every event INSERT'd into
-- the events table fired the dispatcher trigger → CASE → PERFORM
-- of a no-op stub function. Pure overhead. This migration:
--
--   1. Drops the event_projector trigger so AppendEvent commits
--      stop paying the per-event PL/pgSQL function-call cost.
--   2. Drops the project_event() dispatcher function itself.
--   3. Drops the eleven no-op projector stubs left behind by
--      migrations 030/032/033/034/035/036/037 (action+definition)
--      /038/039/040.
--
-- Functional impact: zero. Go listeners registered via
-- projectors.WireAll do all the projection work post-commit
-- (synchronous fireListeners inside Store.AppendEvent). The
-- rebuild path (Store.RebuildAll) routes through Go appliers
-- via RegisterRebuildApply — nothing in production code calls
-- the dropped functions or relies on the trigger.
--
-- The plpgsql_projection_errors table is intentionally KEPT:
--   - It still holds historical rows from when PL/pgSQL projectors
--     could fail. Operators investigating old incidents need
--     the audit trail.
--   - The COMMENT from migration 029 already pins its narrowed
--     scope ("captures errors raised inside PL/pgSQL projector
--     functions"). After this migration no new rows can be
--     written, but that's invisible to readers — they see the
--     historical record, not a "live" surface.
--   - A future migration may TRUNCATE/DROP it once the historical
--     window stops being interesting. Out of scope for this
--     cleanup.
--
-- Down migration restores the dispatcher trigger pointing at the
-- eleven no-op stubs (re-created here as IMMUTABLE no-op bodies)
-- so a rollback of THIS migration alone leaves the schema in the
-- state migration 040 left it in. A clean rollback to pre-#136
-- requires running 040..030 downs in reverse to restore the
-- actual PL/pgSQL projector bodies.
--
-- See manchtools/power-manage-server#136.

-- +goose Up

DROP TRIGGER IF EXISTS event_projector ON events;
DROP FUNCTION IF EXISTS project_event();

DROP FUNCTION IF EXISTS project_action_set_event(events);
DROP FUNCTION IF EXISTS project_assignment_event(events);
DROP FUNCTION IF EXISTS project_user_group_event(events);
DROP FUNCTION IF EXISTS project_device_group_event(events);
DROP FUNCTION IF EXISTS project_compliance_policy_event(events);
DROP FUNCTION IF EXISTS project_compliance_event(events);
DROP FUNCTION IF EXISTS project_action_event(events);
DROP FUNCTION IF EXISTS project_definition_event(events);
DROP FUNCTION IF EXISTS project_execution_event(events);
DROP FUNCTION IF EXISTS project_device_event(events);
DROP FUNCTION IF EXISTS project_user_event(events);

-- +goose Down

-- Re-create the eleven no-op stubs that migration 040 left in
-- place. Each takes an `events` row, returns void, does nothing.
-- This restores the pg_proc state migration 040 ended at; a
-- deeper rollback to actual PL/pgSQL projector bodies requires
-- running 040..030 downs in reverse separately.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_action_set_event(event events) RETURNS void AS $$
BEGIN
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_assignment_event(event events) RETURNS void AS $$
BEGIN
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_group_event(event events) RETURNS void AS $$
BEGIN
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_device_group_event(event events) RETURNS void AS $$
BEGIN
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_compliance_policy_event(event events) RETURNS void AS $$
BEGIN
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_compliance_event(event events) RETURNS void AS $$
BEGIN
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_action_event(event events) RETURNS void AS $$
BEGIN
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_definition_event(event events) RETURNS void AS $$
BEGIN
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_execution_event(event events) RETURNS void AS $$
BEGIN
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_device_event(event events) RETURNS void AS $$
BEGIN
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_event(event events) RETURNS void AS $$
BEGIN
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Re-create the dispatcher with the post-040 shape: routes every
-- ported stream type to its no-op stub (which is the same body
-- migrations 030..040 left). The trigger fires post-INSERT on
-- events.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_event() RETURNS trigger AS $$
BEGIN
    CASE NEW.stream_type
        WHEN 'user' THEN
            BEGIN
                PERFORM project_user_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO plpgsql_projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;
        WHEN 'device' THEN
            BEGIN
                PERFORM project_device_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO plpgsql_projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;
        WHEN 'action' THEN
            BEGIN
                PERFORM project_action_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO plpgsql_projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;
        WHEN 'definition' THEN
            BEGIN
                PERFORM project_action_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO plpgsql_projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, 'definition->action', SQLERRM);
            END;
            BEGIN
                PERFORM project_definition_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO plpgsql_projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, 'definition->definition', SQLERRM);
            END;
        WHEN 'action_set' THEN
            BEGIN
                PERFORM project_action_set_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO plpgsql_projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;
        WHEN 'device_group' THEN
            BEGIN
                PERFORM project_device_group_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO plpgsql_projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;
        WHEN 'assignment' THEN
            BEGIN
                PERFORM project_assignment_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO plpgsql_projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;
        WHEN 'execution' THEN
            BEGIN
                PERFORM project_execution_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO plpgsql_projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;
        WHEN 'user_group' THEN
            BEGIN
                PERFORM project_user_group_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO plpgsql_projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;
        WHEN 'compliance' THEN
            BEGIN
                PERFORM project_compliance_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO plpgsql_projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;
        WHEN 'compliance_policy' THEN
            BEGIN
                PERFORM project_compliance_policy_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO plpgsql_projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;
        ELSE
            NULL;
    END CASE;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER event_projector
    AFTER INSERT ON events
    FOR EACH ROW
    EXECUTE FUNCTION project_event();
