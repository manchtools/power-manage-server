-- +goose Up

-- Schema changes
ALTER TABLE user_groups_projection ADD COLUMN is_dynamic BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE user_groups_projection ADD COLUMN dynamic_query TEXT;

CREATE TABLE dynamic_user_group_evaluation_queue (
    group_id TEXT PRIMARY KEY REFERENCES user_groups_projection(id),
    queued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason TEXT
);

-- Evaluate a single user attribute condition.
-- Unlike device groups (JSONB labels), user groups evaluate against typed parameters.
-- Queryable: user.email (text), user.disabled (bool), user.totp_enabled (bool), user.has_password (bool)
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION evaluate_user_condition(
    user_email TEXT,
    user_disabled BOOLEAN,
    user_totp_enabled BOOLEAN,
    user_has_password BOOLEAN,
    condition TEXT
) RETURNS BOOLEAN AS $$
DECLARE
    parts TEXT[];
    field_expr TEXT;
    operator TEXT;
    value TEXT;
    field_value TEXT;
    values_arr TEXT[];
    i INTEGER;
BEGIN
    condition := trim(condition);
    IF condition = '' OR condition IS NULL THEN
        RETURN TRUE;
    END IF;

    -- Unary: exists
    IF condition ~* '^\s*(\S+)\s+exists\s*$' THEN
        parts := regexp_matches(condition, '^\s*(\S+)\s+exists\s*$', 'i');
        field_expr := lower(parts[1]);
        CASE field_expr
            WHEN 'user.email' THEN RETURN user_email IS NOT NULL AND user_email != '';
            WHEN 'user.disabled' THEN RETURN TRUE;
            WHEN 'user.totp_enabled' THEN RETURN TRUE;
            WHEN 'user.has_password' THEN RETURN TRUE;
            ELSE RETURN FALSE;
        END CASE;
    END IF;

    -- Unary: notExists
    IF condition ~* '^\s*(\S+)\s+notExists\s*$' THEN
        parts := regexp_matches(condition, '^\s*(\S+)\s+notExists\s*$', 'i');
        field_expr := lower(parts[1]);
        CASE field_expr
            WHEN 'user.email' THEN RETURN user_email IS NULL OR user_email = '';
            ELSE RETURN FALSE;
        END CASE;
    END IF;

    -- Binary operators
    IF condition ~* '^\s*(\S+)\s+(equals|notEquals|contains|notContains|startsWith|endsWith|in|notIn)\s+' THEN
        parts := regexp_matches(condition,
            '^\s*(\S+)\s+(equals|notEquals|contains|notContains|startsWith|endsWith|in|notIn)\s+[\"'']?(.+?)[\"'']?\s*$', 'i');
        IF parts IS NULL THEN
            RETURN FALSE;
        END IF;
        field_expr := lower(parts[1]);
        operator := lower(parts[2]);
        value := parts[3];
    ELSE
        RETURN FALSE;
    END IF;

    -- Resolve field value from user attributes
    CASE field_expr
        WHEN 'user.email' THEN field_value := user_email;
        WHEN 'user.disabled' THEN field_value := user_disabled::TEXT;
        WHEN 'user.totp_enabled' THEN field_value := user_totp_enabled::TEXT;
        WHEN 'user.has_password' THEN field_value := user_has_password::TEXT;
        ELSE RETURN FALSE;
    END CASE;

    -- Apply operator
    CASE operator
        WHEN 'equals' THEN
            IF field_value IS NULL THEN RETURN FALSE; END IF;
            RETURN lower(field_value) = lower(value);

        WHEN 'notequals' THEN
            IF field_value IS NULL THEN RETURN TRUE; END IF;
            RETURN lower(field_value) != lower(value);

        WHEN 'contains' THEN
            IF field_value IS NULL THEN RETURN FALSE; END IF;
            RETURN lower(field_value) LIKE '%' || lower(value) || '%';

        WHEN 'notcontains' THEN
            IF field_value IS NULL THEN RETURN TRUE; END IF;
            RETURN lower(field_value) NOT LIKE '%' || lower(value) || '%';

        WHEN 'startswith' THEN
            IF field_value IS NULL THEN RETURN FALSE; END IF;
            RETURN lower(field_value) LIKE lower(value) || '%';

        WHEN 'endswith' THEN
            IF field_value IS NULL THEN RETURN FALSE; END IF;
            RETURN lower(field_value) LIKE '%' || lower(value);

        WHEN 'in' THEN
            IF field_value IS NULL THEN RETURN FALSE; END IF;
            values_arr := string_to_array(value, ',');
            FOR i IN 1..array_length(values_arr, 1) LOOP
                values_arr[i] := lower(trim(values_arr[i]));
            END LOOP;
            RETURN lower(field_value) = ANY(values_arr);

        WHEN 'notin' THEN
            IF field_value IS NULL THEN RETURN TRUE; END IF;
            values_arr := string_to_array(value, ',');
            FOR i IN 1..array_length(values_arr, 1) LOOP
                values_arr[i] := lower(trim(values_arr[i]));
            END LOOP;
            RETURN lower(field_value) != ALL(values_arr);

        ELSE
            RETURN FALSE;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;
-- +goose StatementEnd

-- Recursive evaluator for user dynamic queries (AND/OR/NOT/parentheses).
-- Same structure as evaluate_dynamic_query() but calls evaluate_user_condition() at the leaf.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION evaluate_dynamic_user_query(
    user_email TEXT,
    user_disabled BOOLEAN,
    user_totp_enabled BOOLEAN,
    user_has_password BOOLEAN,
    query TEXT,
    depth INTEGER DEFAULT 0
) RETURNS BOOLEAN AS $$
DECLARE
    result BOOLEAN;
    work_query TEXT;
    paren_content TEXT;
    paren_result BOOLEAN;
    pos INTEGER;
    start_pos INTEGER;
    end_pos INTEGER;
    char_at TEXT;
BEGIN
    IF depth > 10 THEN
        RAISE WARNING 'Dynamic user query recursion depth exceeded (>10)';
        RETURN FALSE;
    END IF;

    IF query IS NULL OR trim(query) = '' THEN
        RETURN TRUE;
    END IF;

    work_query := trim(query);

    -- Handle parenthesized expressions
    LOOP
        start_pos := 0;
        end_pos := 0;

        FOR pos IN 1..length(work_query) LOOP
            char_at := substr(work_query, pos, 1);
            IF char_at = '(' THEN
                start_pos := pos;
            ELSIF char_at = ')' AND start_pos > 0 THEN
                end_pos := pos;
                EXIT;
            END IF;
        END LOOP;

        IF start_pos = 0 OR end_pos = 0 THEN
            EXIT;
        END IF;

        paren_content := substr(work_query, start_pos + 1, end_pos - start_pos - 1);
        paren_result := evaluate_dynamic_user_query(user_email, user_disabled, user_totp_enabled, user_has_password, paren_content, depth + 1);

        work_query := substr(work_query, 1, start_pos - 1) ||
                      CASE WHEN paren_result THEN '__TRUE__' ELSE '__FALSE__' END ||
                      substr(work_query, end_pos + 1);
    END LOOP;

    -- Handle leading NOT
    WHILE work_query ~* '^\s*not\s+' LOOP
        work_query := regexp_replace(work_query, '^\s*not\s+', '', 'i');
        result := NOT evaluate_dynamic_user_query(user_email, user_disabled, user_totp_enabled, user_has_password, work_query, depth + 1);
        RETURN result;
    END LOOP;

    -- Handle inline NOT
    WHILE work_query ~* '\s+not\s+__TRUE__' LOOP
        work_query := regexp_replace(work_query, '\s+not\s+__TRUE__', ' __FALSE__', 'gi');
    END LOOP;
    WHILE work_query ~* '\s+not\s+__FALSE__' LOOP
        work_query := regexp_replace(work_query, '\s+not\s+__FALSE__', ' __TRUE__', 'gi');
    END LOOP;

    -- Handle AND
    IF work_query ~* '\s+and\s+' THEN
        DECLARE
            parts TEXT[];
            all_true BOOLEAN := TRUE;
            part TEXT;
        BEGIN
            parts := regexp_split_to_array(work_query, '\s+and\s+', 'i');
            FOREACH part IN ARRAY parts LOOP
                IF NOT evaluate_dynamic_user_query(user_email, user_disabled, user_totp_enabled, user_has_password, part, depth + 1) THEN
                    all_true := FALSE;
                    EXIT;
                END IF;
            END LOOP;
            RETURN all_true;
        END;
    END IF;

    -- Handle OR
    IF work_query ~* '\s+or\s+' THEN
        DECLARE
            parts TEXT[];
            any_true BOOLEAN := FALSE;
            part TEXT;
        BEGIN
            parts := regexp_split_to_array(work_query, '\s+or\s+', 'i');
            FOREACH part IN ARRAY parts LOOP
                IF evaluate_dynamic_user_query(user_email, user_disabled, user_totp_enabled, user_has_password, part, depth + 1) THEN
                    any_true := TRUE;
                    EXIT;
                END IF;
            END LOOP;
            RETURN any_true;
        END;
    END IF;

    -- Handle resolved placeholders
    IF work_query = '__TRUE__' THEN
        RETURN TRUE;
    ELSIF work_query = '__FALSE__' THEN
        RETURN FALSE;
    END IF;

    -- Leaf condition
    RETURN evaluate_user_condition(user_email, user_disabled, user_totp_enabled, user_has_password, work_query);
END;
$$ LANGUAGE plpgsql IMMUTABLE;
-- +goose StatementEnd

-- Validate a user group query by testing it against dummy data.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION validate_user_group_query(query TEXT) RETURNS TEXT AS $$
BEGIN
    IF query IS NULL OR trim(query) = '' THEN
        RETURN 'query must not be empty';
    END IF;
    PERFORM evaluate_dynamic_user_query('test@example.com', FALSE, FALSE, TRUE, query);
    RETURN '';
EXCEPTION WHEN OTHERS THEN
    RETURN SQLERRM;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Evaluate a dynamic user group: compute membership from query and update projection.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION evaluate_dynamic_user_group(group_id_param TEXT) RETURNS void AS $$
DECLARE
    group_record RECORD;
    user_record RECORD;
    query_text TEXT;
    matches BOOLEAN;
    current_members TEXT[];
    new_members TEXT[];
    members_to_add TEXT[];
    members_to_remove TEXT[];
    member_id TEXT;
BEGIN
    SELECT id, dynamic_query, is_dynamic INTO group_record
    FROM user_groups_projection
    WHERE id = group_id_param AND is_deleted = FALSE;

    IF NOT FOUND OR NOT group_record.is_dynamic THEN
        DELETE FROM dynamic_user_group_evaluation_queue WHERE group_id = group_id_param;
        RETURN;
    END IF;

    query_text := group_record.dynamic_query;

    SELECT array_agg(user_id) INTO current_members
    FROM user_group_members_projection
    WHERE group_id = group_id_param;

    current_members := COALESCE(current_members, ARRAY[]::TEXT[]);

    new_members := ARRAY[]::TEXT[];
    FOR user_record IN
        SELECT id, email, disabled, totp_enabled, has_password FROM users_projection WHERE is_deleted = FALSE
    LOOP
        matches := evaluate_dynamic_user_query(user_record.email, user_record.disabled, user_record.totp_enabled, user_record.has_password, query_text);
        IF matches THEN
            new_members := array_append(new_members, user_record.id);
        END IF;
    END LOOP;

    members_to_add := ARRAY(
        SELECT unnest(new_members) EXCEPT SELECT unnest(current_members)
    );

    members_to_remove := ARRAY(
        SELECT unnest(current_members) EXCEPT SELECT unnest(new_members)
    );

    FOREACH member_id IN ARRAY members_to_add LOOP
        INSERT INTO user_group_members_projection (group_id, user_id, added_at, added_by, projection_version)
        VALUES (group_id_param, member_id, NOW(), 'system', 0)
        ON CONFLICT (group_id, user_id) DO NOTHING;
    END LOOP;

    FOREACH member_id IN ARRAY members_to_remove LOOP
        DELETE FROM user_group_members_projection
        WHERE group_id = group_id_param AND user_id = member_id;
    END LOOP;

    UPDATE user_groups_projection
    SET member_count = COALESCE(array_length(new_members, 1), 0)
    WHERE id = group_id_param;

    DELETE FROM dynamic_user_group_evaluation_queue WHERE group_id = group_id_param;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Process queued dynamic user group evaluations.
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

-- Queue all dynamic user groups for re-evaluation when a user's attributes change.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION queue_dynamic_user_groups_on_user_change() RETURNS trigger AS $$
BEGIN
    INSERT INTO dynamic_user_group_evaluation_queue (group_id, queued_at, reason)
    SELECT id, NOW(), 'user_' || COALESCE(NEW.id, OLD.id) || '_changed'
    FROM user_groups_projection
    WHERE is_dynamic = TRUE AND is_deleted = FALSE
    ON CONFLICT (group_id) DO UPDATE SET queued_at = NOW(), reason = EXCLUDED.reason;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER user_attribute_change_trigger
    AFTER INSERT OR UPDATE OF email, disabled, totp_enabled, has_password, is_deleted ON users_projection
    FOR EACH ROW
    EXECUTE FUNCTION queue_dynamic_user_groups_on_user_change();

-- Update user group event projector to handle dynamic fields.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_group_event(event events) RETURNS void AS $$
DECLARE
    is_dyn BOOLEAN;
BEGIN
    CASE event.event_type
        WHEN 'UserGroupCreated' THEN
            is_dyn := COALESCE((event.data->>'is_dynamic')::BOOLEAN, FALSE);
            INSERT INTO user_groups_projection (
                id, name, description, member_count,
                created_at, created_by, updated_at, projection_version,
                is_dynamic, dynamic_query
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
                0,
                event.occurred_at,
                event.actor_id,
                event.occurred_at,
                event.sequence_num,
                is_dyn,
                event.data->>'dynamic_query'
            );

            IF is_dyn THEN
                INSERT INTO dynamic_user_group_evaluation_queue (group_id, reason)
                VALUES (event.stream_id, 'group_created')
                ON CONFLICT (group_id) DO UPDATE SET queued_at = NOW();
            END IF;

        WHEN 'UserGroupUpdated' THEN
            UPDATE user_groups_projection
            SET name = event.data->>'name',
                description = COALESCE(event.data->>'description', ''),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserGroupQueryUpdated' THEN
            is_dyn := COALESCE((event.data->>'is_dynamic')::BOOLEAN, FALSE);
            UPDATE user_groups_projection
            SET is_dynamic = is_dyn,
                dynamic_query = event.data->>'dynamic_query',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            IF is_dyn THEN
                -- Clear existing members and re-evaluate
                DELETE FROM user_group_members_projection WHERE group_id = event.stream_id;
                UPDATE user_groups_projection SET member_count = 0 WHERE id = event.stream_id;
                INSERT INTO dynamic_user_group_evaluation_queue (group_id, reason)
                VALUES (event.stream_id, 'query_updated')
                ON CONFLICT (group_id) DO UPDATE SET queued_at = NOW();
            END IF;

        WHEN 'UserGroupDeleted' THEN
            UPDATE user_groups_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Clean up members, roles, and evaluation queue
            DELETE FROM user_group_members_projection WHERE group_id = event.stream_id;
            DELETE FROM user_group_roles_projection WHERE group_id = event.stream_id;
            DELETE FROM dynamic_user_group_evaluation_queue WHERE group_id = event.stream_id;

        WHEN 'UserGroupMemberAdded' THEN
            -- Skip if group is dynamic (membership managed by query engine)
            IF NOT EXISTS (
                SELECT 1 FROM user_groups_projection
                WHERE id = event.data->>'group_id' AND is_dynamic = TRUE
            ) THEN
                INSERT INTO user_group_members_projection (
                    group_id, user_id, added_at, added_by, projection_version
                ) VALUES (
                    event.data->>'group_id',
                    event.data->>'user_id',
                    event.occurred_at,
                    event.actor_id,
                    event.sequence_num
                )
                ON CONFLICT (group_id, user_id) DO NOTHING;

                UPDATE user_groups_projection
                SET member_count = member_count + 1,
                    updated_at = event.occurred_at,
                    projection_version = event.sequence_num
                WHERE id = event.data->>'group_id';
            END IF;

        WHEN 'UserGroupMemberRemoved' THEN
            -- Skip if group is dynamic
            IF NOT EXISTS (
                SELECT 1 FROM user_groups_projection
                WHERE id = event.data->>'group_id' AND is_dynamic = TRUE
            ) THEN
                DELETE FROM user_group_members_projection
                WHERE group_id = event.data->>'group_id'
                  AND user_id = event.data->>'user_id';

                UPDATE user_groups_projection
                SET member_count = GREATEST(member_count - 1, 0),
                    updated_at = event.occurred_at,
                    projection_version = event.sequence_num
                WHERE id = event.data->>'group_id';
            END IF;

        WHEN 'UserGroupRoleAssigned' THEN
            INSERT INTO user_group_roles_projection (
                group_id, role_id, assigned_at, assigned_by, projection_version
            ) VALUES (
                event.data->>'group_id',
                event.data->>'role_id',
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            )
            ON CONFLICT (group_id, role_id) DO NOTHING;

        WHEN 'UserGroupRoleRevoked' THEN
            DELETE FROM user_group_roles_projection
            WHERE group_id = event.data->>'group_id'
              AND role_id = event.data->>'role_id';

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Update rebuild function to also truncate the evaluation queue.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_user_groups_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE dynamic_user_group_evaluation_queue;
    TRUNCATE user_group_roles_projection;
    TRUNCATE user_group_members_projection;
    TRUNCATE user_groups_projection CASCADE;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'user_group' ORDER BY sequence_num LOOP
        PERFORM project_user_group_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down

DROP TRIGGER IF EXISTS user_attribute_change_trigger ON users_projection;
DROP FUNCTION IF EXISTS queue_dynamic_user_groups_on_user_change;
DROP FUNCTION IF EXISTS evaluate_queued_dynamic_user_groups;
DROP FUNCTION IF EXISTS evaluate_dynamic_user_group;
DROP FUNCTION IF EXISTS validate_user_group_query;
DROP FUNCTION IF EXISTS evaluate_dynamic_user_query;
DROP FUNCTION IF EXISTS evaluate_user_condition;
DROP TABLE IF EXISTS dynamic_user_group_evaluation_queue;
ALTER TABLE user_groups_projection DROP COLUMN IF EXISTS dynamic_query;
ALTER TABLE user_groups_projection DROP COLUMN IF EXISTS is_dynamic;
