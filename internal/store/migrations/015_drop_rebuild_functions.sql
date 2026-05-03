-- Drop the 13 PL/pgSQL rebuild functions (12 per-target + 1 umbrella).
-- They are replaced by a single Go entry point Store.RebuildAll() in
-- internal/store/rebuild.go that walks the event store with the same
-- per-stream-type semantics. The PL/pgSQL projector functions
-- project_<X>_event() stay in place — RebuildAll continues to call
-- them via SELECT project_<X>_event(events.*) until each is ported
-- to a Go projector under #96–#106.
--
-- Operators previously ran these functions via psql for emergency
-- rebuild from the event store. They are not invoked by any runtime
-- path. Documentation update in cmd/control/README.md points at the
-- new Go entry point.
--
-- See manchtools/power-manage-server#94 (and tracker #107).

-- +goose Up

DROP FUNCTION IF EXISTS rebuild_users_projection();
DROP FUNCTION IF EXISTS rebuild_tokens_projection();
DROP FUNCTION IF EXISTS rebuild_devices_projection();
DROP FUNCTION IF EXISTS rebuild_actions_projection();
DROP FUNCTION IF EXISTS rebuild_executions_projection();
DROP FUNCTION IF EXISTS rebuild_action_sets_projection();
DROP FUNCTION IF EXISTS rebuild_definitions_projection();
DROP FUNCTION IF EXISTS rebuild_device_groups_projection();
DROP FUNCTION IF EXISTS rebuild_assignments_projection();
DROP FUNCTION IF EXISTS rebuild_user_selections_projection();
DROP FUNCTION IF EXISTS rebuild_roles_projection();
DROP FUNCTION IF EXISTS rebuild_user_groups_projection();
DROP FUNCTION IF EXISTS rebuild_all_projections();


-- +goose Down

-- Restore the 13 functions with their original bodies. Bodies are
-- copied verbatim from migration 004_dynamic_groups.sql / earlier so
-- a Down + Up cycle leaves the database in the pre-#94 state.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_users_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE users_projection CASCADE;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'user' ORDER BY sequence_num LOOP
        PERFORM project_user_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_tokens_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE tokens_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'token' ORDER BY sequence_num LOOP
        PERFORM project_token_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_devices_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE devices_projection CASCADE;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'device' ORDER BY sequence_num LOOP
        PERFORM project_device_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_actions_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE actions_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type IN ('action', 'definition') ORDER BY sequence_num LOOP
        PERFORM project_action_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_executions_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE executions_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'execution' ORDER BY sequence_num LOOP
        PERFORM project_execution_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_action_sets_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE action_sets_projection CASCADE;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'action_set' ORDER BY sequence_num LOOP
        PERFORM project_action_set_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_definitions_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE definitions_projection CASCADE;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'definition' ORDER BY sequence_num LOOP
        PERFORM project_definition_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_device_groups_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE device_groups_projection CASCADE;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'device_group' ORDER BY sequence_num LOOP
        PERFORM project_device_group_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_assignments_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE assignments_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'assignment' ORDER BY sequence_num LOOP
        PERFORM project_assignment_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_user_selections_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE user_selections_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'user_selection' ORDER BY sequence_num LOOP
        PERFORM project_user_selection_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_roles_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE roles_projection CASCADE;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'role' ORDER BY sequence_num LOOP
        PERFORM project_role_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_user_groups_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE user_groups_projection CASCADE;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'user_group' ORDER BY sequence_num LOOP
        PERFORM project_user_group_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_all_projections() RETURNS void AS $$
BEGIN
    PERFORM rebuild_users_projection();
    PERFORM rebuild_tokens_projection();
    PERFORM rebuild_devices_projection();
    PERFORM rebuild_actions_projection();
    PERFORM rebuild_executions_projection();
    PERFORM rebuild_action_sets_projection();
    PERFORM rebuild_definitions_projection();
    PERFORM rebuild_device_groups_projection();
    PERFORM rebuild_assignments_projection();
    PERFORM rebuild_user_selections_projection();
    PERFORM rebuild_roles_projection();
    PERFORM rebuild_user_groups_projection();
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
