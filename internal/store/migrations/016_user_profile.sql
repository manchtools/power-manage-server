-- +goose Up

-- Add OIDC profile scope columns to users_projection
ALTER TABLE users_projection ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE users_projection ADD COLUMN given_name TEXT NOT NULL DEFAULT '';
ALTER TABLE users_projection ADD COLUMN family_name TEXT NOT NULL DEFAULT '';
ALTER TABLE users_projection ADD COLUMN preferred_username TEXT NOT NULL DEFAULT '';
ALTER TABLE users_projection ADD COLUMN picture TEXT NOT NULL DEFAULT '';
ALTER TABLE users_projection ADD COLUMN locale TEXT NOT NULL DEFAULT '';

-- Update user event projector to handle profile fields
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'UserCreated' THEN
            INSERT INTO users_projection (
                id, email, password_hash, role, created_at, updated_at, projection_version, session_version, has_password,
                display_name, given_name, family_name, preferred_username, picture, locale
            ) VALUES (
                event.stream_id,
                event.data->>'email',
                COALESCE(event.data->>'password_hash', ''),
                COALESCE(event.data->>'role', 'user'),
                event.occurred_at,
                event.occurred_at,
                event.sequence_num,
                0,
                COALESCE(NULLIF(event.data->>'password_hash', ''), NULL) IS NOT NULL,
                COALESCE(event.data->>'display_name', ''),
                COALESCE(event.data->>'given_name', ''),
                COALESCE(event.data->>'family_name', ''),
                COALESCE(event.data->>'preferred_username', ''),
                COALESCE(event.data->>'picture', ''),
                COALESCE(event.data->>'locale', '')
            );

        WHEN 'UserProfileUpdated' THEN
            UPDATE users_projection
            SET display_name = COALESCE(event.data->>'display_name', ''),
                given_name = COALESCE(event.data->>'given_name', ''),
                family_name = COALESCE(event.data->>'family_name', ''),
                preferred_username = COALESCE(event.data->>'preferred_username', ''),
                picture = COALESCE(event.data->>'picture', ''),
                locale = COALESCE(event.data->>'locale', ''),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserEmailChanged' THEN
            UPDATE users_projection
            SET email = event.data->>'email',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserPasswordChanged' THEN
            UPDATE users_projection
            SET password_hash = event.data->>'password_hash',
                has_password = TRUE,
                session_version = session_version + 1,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserRoleChanged' THEN
            UPDATE users_projection
            SET role = event.data->>'role',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserSessionInvalidated' THEN
            UPDATE users_projection
            SET session_version = session_version + 1,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserDisabled' THEN
            UPDATE users_projection
            SET disabled = TRUE,
                session_version = session_version + 1,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserEnabled' THEN
            UPDATE users_projection
            SET disabled = FALSE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserLoggedIn' THEN
            UPDATE users_projection
            SET last_login_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserDeleted' THEN
            UPDATE users_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Update evaluate_user_condition to support new queryable fields
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION evaluate_user_condition(
    user_email TEXT,
    user_disabled BOOLEAN,
    user_totp_enabled BOOLEAN,
    user_has_password BOOLEAN,
    user_display_name TEXT,
    user_preferred_username TEXT,
    user_locale TEXT,
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
            WHEN 'user.display_name' THEN RETURN user_display_name IS NOT NULL AND user_display_name != '';
            WHEN 'user.preferred_username' THEN RETURN user_preferred_username IS NOT NULL AND user_preferred_username != '';
            WHEN 'user.locale' THEN RETURN user_locale IS NOT NULL AND user_locale != '';
            ELSE RETURN FALSE;
        END CASE;
    END IF;

    -- Unary: notExists
    IF condition ~* '^\s*(\S+)\s+notExists\s*$' THEN
        parts := regexp_matches(condition, '^\s*(\S+)\s+notExists\s*$', 'i');
        field_expr := lower(parts[1]);
        CASE field_expr
            WHEN 'user.email' THEN RETURN user_email IS NULL OR user_email = '';
            WHEN 'user.display_name' THEN RETURN user_display_name IS NULL OR user_display_name = '';
            WHEN 'user.preferred_username' THEN RETURN user_preferred_username IS NULL OR user_preferred_username = '';
            WHEN 'user.locale' THEN RETURN user_locale IS NULL OR user_locale = '';
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
        WHEN 'user.display_name' THEN field_value := user_display_name;
        WHEN 'user.preferred_username' THEN field_value := user_preferred_username;
        WHEN 'user.locale' THEN field_value := user_locale;
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

-- Update recursive evaluator with new parameter signature
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION evaluate_dynamic_user_query(
    user_email TEXT,
    user_disabled BOOLEAN,
    user_totp_enabled BOOLEAN,
    user_has_password BOOLEAN,
    user_display_name TEXT,
    user_preferred_username TEXT,
    user_locale TEXT,
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
        paren_result := evaluate_dynamic_user_query(user_email, user_disabled, user_totp_enabled, user_has_password, user_display_name, user_preferred_username, user_locale, paren_content, depth + 1);

        work_query := substr(work_query, 1, start_pos - 1) ||
                      CASE WHEN paren_result THEN '__TRUE__' ELSE '__FALSE__' END ||
                      substr(work_query, end_pos + 1);
    END LOOP;

    -- Handle leading NOT
    WHILE work_query ~* '^\s*not\s+' LOOP
        work_query := regexp_replace(work_query, '^\s*not\s+', '', 'i');
        result := NOT evaluate_dynamic_user_query(user_email, user_disabled, user_totp_enabled, user_has_password, user_display_name, user_preferred_username, user_locale, work_query, depth + 1);
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
                IF NOT evaluate_dynamic_user_query(user_email, user_disabled, user_totp_enabled, user_has_password, user_display_name, user_preferred_username, user_locale, part, depth + 1) THEN
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
                IF evaluate_dynamic_user_query(user_email, user_disabled, user_totp_enabled, user_has_password, user_display_name, user_preferred_username, user_locale, part, depth + 1) THEN
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
    RETURN evaluate_user_condition(user_email, user_disabled, user_totp_enabled, user_has_password, user_display_name, user_preferred_username, user_locale, work_query);
END;
$$ LANGUAGE plpgsql IMMUTABLE;
-- +goose StatementEnd

-- Update validate_user_group_query to match new signature
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION validate_user_group_query(query TEXT) RETURNS TEXT AS $$
BEGIN
    IF query IS NULL OR trim(query) = '' THEN
        RETURN 'query must not be empty';
    END IF;
    PERFORM evaluate_dynamic_user_query('test@example.com', FALSE, FALSE, TRUE, 'Test User', 'testuser', 'en', query);
    RETURN '';
EXCEPTION WHEN OTHERS THEN
    RETURN SQLERRM;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Update evaluate_dynamic_user_group to pass new columns
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
        SELECT id, email, disabled, totp_enabled, has_password, display_name, preferred_username, locale
        FROM users_projection WHERE is_deleted = FALSE
    LOOP
        matches := evaluate_dynamic_user_query(user_record.email, user_record.disabled, user_record.totp_enabled, user_record.has_password, user_record.display_name, user_record.preferred_username, user_record.locale, query_text);
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

-- Update trigger to include new profile columns
DROP TRIGGER IF EXISTS user_attribute_change_trigger ON users_projection;
CREATE TRIGGER user_attribute_change_trigger
    AFTER INSERT OR UPDATE OF email, disabled, totp_enabled, has_password, is_deleted, display_name, preferred_username, locale
    ON users_projection
    FOR EACH ROW
    EXECUTE FUNCTION queue_dynamic_user_groups_on_user_change();

-- +goose Down

DROP TRIGGER IF EXISTS user_attribute_change_trigger ON users_projection;
CREATE TRIGGER user_attribute_change_trigger
    AFTER INSERT OR UPDATE OF email, disabled, totp_enabled, has_password, is_deleted ON users_projection
    FOR EACH ROW
    EXECUTE FUNCTION queue_dynamic_user_groups_on_user_change();

-- Restore original function signatures from migration 015

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
    IF condition ~* '^\s*(\S+)\s+notExists\s*$' THEN
        parts := regexp_matches(condition, '^\s*(\S+)\s+notExists\s*$', 'i');
        field_expr := lower(parts[1]);
        CASE field_expr
            WHEN 'user.email' THEN RETURN user_email IS NULL OR user_email = '';
            ELSE RETURN FALSE;
        END CASE;
    END IF;
    IF condition ~* '^\s*(\S+)\s+(equals|notEquals|contains|notContains|startsWith|endsWith|in|notIn)\s+' THEN
        parts := regexp_matches(condition,
            '^\s*(\S+)\s+(equals|notEquals|contains|notContains|startsWith|endsWith|in|notIn)\s+[\"'']?(.+?)[\"'']?\s*$', 'i');
        IF parts IS NULL THEN RETURN FALSE; END IF;
        field_expr := lower(parts[1]);
        operator := lower(parts[2]);
        value := parts[3];
    ELSE
        RETURN FALSE;
    END IF;
    CASE field_expr
        WHEN 'user.email' THEN field_value := user_email;
        WHEN 'user.disabled' THEN field_value := user_disabled::TEXT;
        WHEN 'user.totp_enabled' THEN field_value := user_totp_enabled::TEXT;
        WHEN 'user.has_password' THEN field_value := user_has_password::TEXT;
        ELSE RETURN FALSE;
    END CASE;
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
    WHILE work_query ~* '^\s*not\s+' LOOP
        work_query := regexp_replace(work_query, '^\s*not\s+', '', 'i');
        result := NOT evaluate_dynamic_user_query(user_email, user_disabled, user_totp_enabled, user_has_password, work_query, depth + 1);
        RETURN result;
    END LOOP;
    WHILE work_query ~* '\s+not\s+__TRUE__' LOOP
        work_query := regexp_replace(work_query, '\s+not\s+__TRUE__', ' __FALSE__', 'gi');
    END LOOP;
    WHILE work_query ~* '\s+not\s+__FALSE__' LOOP
        work_query := regexp_replace(work_query, '\s+not\s+__FALSE__', ' __TRUE__', 'gi');
    END LOOP;
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
    IF work_query = '__TRUE__' THEN
        RETURN TRUE;
    ELSIF work_query = '__FALSE__' THEN
        RETURN FALSE;
    END IF;
    RETURN evaluate_user_condition(user_email, user_disabled, user_totp_enabled, user_has_password, work_query);
END;
$$ LANGUAGE plpgsql IMMUTABLE;
-- +goose StatementEnd

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

-- Restore original projector
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'UserCreated' THEN
            INSERT INTO users_projection (
                id, email, password_hash, role, created_at, updated_at, projection_version, session_version, has_password
            ) VALUES (
                event.stream_id,
                event.data->>'email',
                COALESCE(event.data->>'password_hash', ''),
                COALESCE(event.data->>'role', 'user'),
                event.occurred_at,
                event.occurred_at,
                event.sequence_num,
                0,
                COALESCE(NULLIF(event.data->>'password_hash', ''), NULL) IS NOT NULL
            );
        WHEN 'UserEmailChanged' THEN
            UPDATE users_projection
            SET email = event.data->>'email',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;
        WHEN 'UserPasswordChanged' THEN
            UPDATE users_projection
            SET password_hash = event.data->>'password_hash',
                has_password = TRUE,
                session_version = session_version + 1,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;
        WHEN 'UserRoleChanged' THEN
            UPDATE users_projection
            SET role = event.data->>'role',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;
        WHEN 'UserSessionInvalidated' THEN
            UPDATE users_projection
            SET session_version = session_version + 1,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;
        WHEN 'UserDisabled' THEN
            UPDATE users_projection
            SET disabled = TRUE,
                session_version = session_version + 1,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;
        WHEN 'UserEnabled' THEN
            UPDATE users_projection
            SET disabled = FALSE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;
        WHEN 'UserLoggedIn' THEN
            UPDATE users_projection
            SET last_login_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;
        WHEN 'UserDeleted' THEN
            UPDATE users_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;
        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

ALTER TABLE users_projection DROP COLUMN IF EXISTS display_name;
ALTER TABLE users_projection DROP COLUMN IF EXISTS given_name;
ALTER TABLE users_projection DROP COLUMN IF EXISTS family_name;
ALTER TABLE users_projection DROP COLUMN IF EXISTS preferred_username;
ALTER TABLE users_projection DROP COLUMN IF EXISTS picture;
ALTER TABLE users_projection DROP COLUMN IF EXISTS locale;
