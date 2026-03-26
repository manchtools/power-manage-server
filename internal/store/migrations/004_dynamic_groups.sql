-- +goose Up

-- ============================================================================
-- PART 4: DYNAMIC GROUP EVALUATION FUNCTIONS
-- ============================================================================

-- ============================================================================
-- DEVICE GROUP EVALUATION
-- ============================================================================

-- 1. extract_label_key() — from 001 (unchanged). IMMUTABLE.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION extract_label_key(label_expr TEXT) RETURNS TEXT AS $$
DECLARE
    parts TEXT[];
BEGIN
    IF label_expr ~* '^device\.labels\.' THEN
        RETURN substr(label_expr, 15);
    ELSIF label_expr ~* '^labels\.' THEN
        RETURN substr(label_expr, 8);
    ELSIF label_expr ~* '^device\.labels\[' THEN
        parts := regexp_matches(label_expr, '^device\.labels\[["'']?(.+?)["'']?\]$');
        IF parts IS NOT NULL THEN
            RETURN parts[1];
        END IF;
    ELSIF label_expr ~* '^labels\[' THEN
        parts := regexp_matches(label_expr, '^labels\[["'']?(.+?)["'']?\]$');
        IF parts IS NOT NULL THEN
            RETURN parts[1];
        END IF;
    END IF;
    RETURN label_expr;
END;
$$ LANGUAGE plpgsql IMMUTABLE;
-- +goose StatementEnd

-- 2. evaluate_condition() — from 001 (unchanged). IMMUTABLE. Basic label-only condition evaluation.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION evaluate_condition(device_labels JSONB, condition TEXT) RETURNS BOOLEAN AS $$
DECLARE
    parts TEXT[];
    label_expr TEXT;
    operator TEXT;
    value TEXT;
    label_key TEXT;
    label_value TEXT;
    num_label NUMERIC;
    num_val NUMERIC;
    values_arr TEXT[];
BEGIN
    condition := trim(condition);

    IF condition = '' OR condition IS NULL THEN
        RETURN TRUE;
    END IF;

    IF condition ~* '^\s*(\S+)\s+exists\s*$' THEN
        parts := regexp_matches(condition, '^\s*(\S+)\s+exists\s*$', 'i');
        label_key := extract_label_key(parts[1]);
        RETURN device_labels ? label_key;
    END IF;

    IF condition ~* '^\s*(\S+)\s+notExists\s*$' THEN
        parts := regexp_matches(condition, '^\s*(\S+)\s+notExists\s*$', 'i');
        label_key := extract_label_key(parts[1]);
        RETURN NOT (device_labels ? label_key);
    END IF;

    IF condition ~* '^\s*(\S+)\s+(equals|notEquals|contains|notContains|startsWith|endsWith|greaterThan|lessThan|greaterThanOrEquals|lessThanOrEquals|in|notIn)\s+' THEN
        parts := regexp_matches(condition, '^\s*(\S+)\s+(equals|notEquals|contains|notContains|startsWith|endsWith|greaterThan|lessThan|greaterThanOrEquals|lessThanOrEquals|in|notIn)\s+[\"'']?(.+?)[\"'']?\s*$', 'i');
        label_expr := parts[1];
        operator := lower(parts[2]);
        value := parts[3];
    ELSE
        RETURN FALSE;
    END IF;

    label_key := extract_label_key(label_expr);
    IF label_key IS NULL THEN
        RETURN FALSE;
    END IF;

    label_value := device_labels ->> label_key;

    CASE operator
        WHEN 'equals' THEN
            IF label_value IS NULL THEN RETURN FALSE; END IF;
            RETURN lower(label_value) = lower(value);

        WHEN 'notequals' THEN
            IF label_value IS NULL THEN RETURN TRUE; END IF;
            RETURN lower(label_value) != lower(value);

        WHEN 'contains' THEN
            IF label_value IS NULL THEN RETURN FALSE; END IF;
            RETURN lower(label_value) LIKE '%' || lower(value) || '%';

        WHEN 'notcontains' THEN
            IF label_value IS NULL THEN RETURN TRUE; END IF;
            RETURN lower(label_value) NOT LIKE '%' || lower(value) || '%';

        WHEN 'startswith' THEN
            IF label_value IS NULL THEN RETURN FALSE; END IF;
            RETURN lower(label_value) LIKE lower(value) || '%';

        WHEN 'endswith' THEN
            IF label_value IS NULL THEN RETURN FALSE; END IF;
            RETURN lower(label_value) LIKE '%' || lower(value);

        WHEN 'greaterthan' THEN
            IF label_value IS NULL THEN RETURN FALSE; END IF;
            BEGIN
                num_label := label_value::NUMERIC;
                num_val := value::NUMERIC;
                RETURN num_label > num_val;
            EXCEPTION WHEN OTHERS THEN
                RETURN label_value > value;
            END;

        WHEN 'lessthan' THEN
            IF label_value IS NULL THEN RETURN FALSE; END IF;
            BEGIN
                num_label := label_value::NUMERIC;
                num_val := value::NUMERIC;
                RETURN num_label < num_val;
            EXCEPTION WHEN OTHERS THEN
                RETURN label_value < value;
            END;

        WHEN 'greaterthanorequals' THEN
            IF label_value IS NULL THEN RETURN FALSE; END IF;
            BEGIN
                num_label := label_value::NUMERIC;
                num_val := value::NUMERIC;
                RETURN num_label >= num_val;
            EXCEPTION WHEN OTHERS THEN
                RETURN label_value >= value;
            END;

        WHEN 'lessthanorequals' THEN
            IF label_value IS NULL THEN RETURN FALSE; END IF;
            BEGIN
                num_label := label_value::NUMERIC;
                num_val := value::NUMERIC;
                RETURN num_label <= num_val;
            EXCEPTION WHEN OTHERS THEN
                RETURN label_value <= value;
            END;

        WHEN 'in' THEN
            IF label_value IS NULL THEN RETURN FALSE; END IF;
            values_arr := string_to_array(value, ',');
            FOR i IN 1..array_length(values_arr, 1) LOOP
                values_arr[i] := lower(trim(values_arr[i]));
            END LOOP;
            RETURN lower(label_value) = ANY(values_arr);

        WHEN 'notin' THEN
            IF label_value IS NULL THEN RETURN TRUE; END IF;
            values_arr := string_to_array(value, ',');
            FOR i IN 1..array_length(values_arr, 1) LOOP
                values_arr[i] := lower(trim(values_arr[i]));
            END LOOP;
            RETURN lower(label_value) != ALL(values_arr);

        ELSE
            RETURN FALSE;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;
-- +goose StatementEnd

-- 3. evaluate_condition_v2() — from 006. STABLE. Extended condition evaluation with inventory field support.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION evaluate_condition_v2(
    p_device_id TEXT,
    device_labels JSONB,
    condition TEXT
) RETURNS BOOLEAN AS $$
DECLARE
    parts TEXT[];
    field_expr TEXT;
    operator TEXT;
    value TEXT;
    field_name TEXT;
    field_value TEXT;
    num_field NUMERIC;
    num_val NUMERIC;
    values_arr TEXT[];
BEGIN
    condition := trim(condition);

    IF condition = '' OR condition IS NULL THEN
        RETURN TRUE;
    END IF;

    -- Check if this is a device.* (non-label) condition
    IF condition ~* '^\s*device\.' AND condition !~* '^\s*device\.labels[\.\[]' THEN
        -- Parse: device.field_name operator "value"
        IF condition ~* '^\s*device\.(\S+)\s+exists\s*$' THEN
            parts := regexp_matches(condition, '^\s*device\.(\S+)\s+exists\s*$', 'i');
            field_name := parts[1];
            field_value := resolve_inventory_field(p_device_id, field_name);
            RETURN field_value IS NOT NULL;
        END IF;

        IF condition ~* '^\s*device\.(\S+)\s+notExists\s*$' THEN
            parts := regexp_matches(condition, '^\s*device\.(\S+)\s+notExists\s*$', 'i');
            field_name := parts[1];
            field_value := resolve_inventory_field(p_device_id, field_name);
            RETURN field_value IS NULL;
        END IF;

        IF condition ~* '^\s*device\.(\S+)\s+(equals|notEquals|contains|notContains|startsWith|endsWith|greaterThan|lessThan|greaterThanOrEquals|lessThanOrEquals|in|notIn)\s+' THEN
            parts := regexp_matches(condition, '^\s*device\.(\S+)\s+(equals|notEquals|contains|notContains|startsWith|endsWith|greaterThan|lessThan|greaterThanOrEquals|lessThanOrEquals|in|notIn)\s+[\"'']?(.+?)[\"'']?\s*$', 'i');
            field_name := parts[1];
            operator := lower(parts[2]);
            value := parts[3];
        ELSE
            -- Unrecognized device.* condition
            RETURN FALSE;
        END IF;

        field_value := resolve_inventory_field(p_device_id, field_name);

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
            WHEN 'greaterthan' THEN
                IF field_value IS NULL THEN RETURN FALSE; END IF;
                BEGIN
                    num_field := field_value::NUMERIC;
                    num_val := value::NUMERIC;
                    RETURN num_field > num_val;
                EXCEPTION WHEN OTHERS THEN
                    RETURN field_value > value;
                END;
            WHEN 'lessthan' THEN
                IF field_value IS NULL THEN RETURN FALSE; END IF;
                BEGIN
                    num_field := field_value::NUMERIC;
                    num_val := value::NUMERIC;
                    RETURN num_field < num_val;
                EXCEPTION WHEN OTHERS THEN
                    RETURN field_value < value;
                END;
            WHEN 'greaterthanorequals' THEN
                IF field_value IS NULL THEN RETURN FALSE; END IF;
                BEGIN
                    num_field := field_value::NUMERIC;
                    num_val := value::NUMERIC;
                    RETURN num_field >= num_val;
                EXCEPTION WHEN OTHERS THEN
                    RETURN field_value >= value;
                END;
            WHEN 'lessthanorequals' THEN
                IF field_value IS NULL THEN RETURN FALSE; END IF;
                BEGIN
                    num_field := field_value::NUMERIC;
                    num_val := value::NUMERIC;
                    RETURN num_field <= num_val;
                EXCEPTION WHEN OTHERS THEN
                    RETURN field_value <= value;
                END;
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
    END IF;

    -- Fall back to existing label-based evaluate_condition
    RETURN evaluate_condition(device_labels, condition);
END;
$$ LANGUAGE plpgsql STABLE;
-- +goose StatementEnd

-- 4. evaluate_dynamic_query() — from 001 (unchanged). IMMUTABLE. Basic query evaluation using evaluate_condition.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION evaluate_dynamic_query(
    device_labels JSONB,
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
        RAISE WARNING 'Dynamic query recursion depth exceeded (>10)';
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
        paren_result := evaluate_dynamic_query(device_labels, paren_content, depth + 1);

        work_query := substr(work_query, 1, start_pos - 1) ||
                      CASE WHEN paren_result THEN '__TRUE__' ELSE '__FALSE__' END ||
                      substr(work_query, end_pos + 1);
    END LOOP;

    WHILE work_query ~* '^\s*not\s+' LOOP
        work_query := regexp_replace(work_query, '^\s*not\s+', '', 'i');
        result := NOT evaluate_dynamic_query(device_labels, work_query, depth + 1);
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
                IF NOT evaluate_dynamic_query(device_labels, part, depth + 1) THEN
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
                IF evaluate_dynamic_query(device_labels, part, depth + 1) THEN
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

    RETURN evaluate_condition(device_labels, work_query);
END;
$$ LANGUAGE plpgsql IMMUTABLE;
-- +goose StatementEnd

-- 5. evaluate_dynamic_query_v2() — from 006. STABLE. Extended query evaluation with device_id param.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION evaluate_dynamic_query_v2(
    p_device_id TEXT,
    device_labels JSONB,
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
        RAISE WARNING 'Dynamic query recursion depth exceeded (>10)';
        RETURN FALSE;
    END IF;

    IF query IS NULL OR trim(query) = '' THEN
        RETURN TRUE;
    END IF;

    work_query := trim(query);

    -- Resolve parentheses
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
        paren_result := evaluate_dynamic_query_v2(p_device_id, device_labels, paren_content, depth + 1);

        work_query := substr(work_query, 1, start_pos - 1) ||
                      CASE WHEN paren_result THEN '__TRUE__' ELSE '__FALSE__' END ||
                      substr(work_query, end_pos + 1);
    END LOOP;

    -- Handle NOT prefix
    WHILE work_query ~* '^\s*not\s+' LOOP
        work_query := regexp_replace(work_query, '^\s*not\s+', '', 'i');
        result := NOT evaluate_dynamic_query_v2(p_device_id, device_labels, work_query, depth + 1);
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
                IF NOT evaluate_dynamic_query_v2(p_device_id, device_labels, part, depth + 1) THEN
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
                IF evaluate_dynamic_query_v2(p_device_id, device_labels, part, depth + 1) THEN
                    any_true := TRUE;
                    EXIT;
                END IF;
            END LOOP;
            RETURN any_true;
        END;
    END IF;

    -- Handle tokens
    IF work_query = '__TRUE__' THEN
        RETURN TRUE;
    ELSIF work_query = '__FALSE__' THEN
        RETURN FALSE;
    END IF;

    -- Leaf condition: use v2 that supports both labels and inventory
    RETURN evaluate_condition_v2(p_device_id, device_labels, work_query);
END;
$$ LANGUAGE plpgsql STABLE;
-- +goose StatementEnd

-- 6. resolve_inventory_field() — from 030. STABLE. Checks devices_projection.hostname first.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION resolve_inventory_field(p_device_id TEXT, field_name TEXT) RETURNS TEXT AS $$
DECLARE
    tbl TEXT;
    col TEXT;
    result TEXT;
    rows_data JSONB;
BEGIN
    -- For hostname, check devices_projection first (always set at registration).
    IF field_name = 'hostname' THEN
        SELECT dp.hostname INTO result
        FROM devices_projection dp
        WHERE dp.id = p_device_id AND dp.is_deleted = FALSE;
        IF result IS NOT NULL THEN
            RETURN result;
        END IF;
    END IF;

    -- Map device.* fields to inventory table + column
    CASE field_name
        -- os_version table
        WHEN 'os' THEN tbl := 'os_version'; col := 'name';
        WHEN 'os_version' THEN tbl := 'os_version'; col := 'version';
        WHEN 'os_major' THEN tbl := 'os_version'; col := 'major';
        WHEN 'os_minor' THEN tbl := 'os_version'; col := 'minor';
        WHEN 'os_arch' THEN tbl := 'os_version'; col := 'arch';
        WHEN 'os_platform' THEN tbl := 'os_version'; col := 'platform';
        WHEN 'os_platform_like' THEN tbl := 'os_version'; col := 'platform_like';
        -- system_info table
        WHEN 'hostname' THEN tbl := 'system_info'; col := 'hostname';
        WHEN 'cpu_type' THEN tbl := 'system_info'; col := 'cpu_type';
        WHEN 'cpu_brand' THEN tbl := 'system_info'; col := 'cpu_brand';
        WHEN 'cpu_cores' THEN tbl := 'system_info'; col := 'physical_memory'; -- will override below
        WHEN 'cpu_logical_cores' THEN tbl := 'system_info'; col := 'cpu_logical_cores';
        WHEN 'memory_total' THEN tbl := 'system_info'; col := 'physical_memory';
        -- kernel_info table
        WHEN 'kernel' THEN tbl := 'kernel_info'; col := 'version';
        ELSE
            RETURN NULL;
    END CASE;

    -- Fix cpu_cores mapping (system_info doesn't have cpu_cores directly, use cpu_physical_cores)
    IF field_name = 'cpu_cores' THEN
        col := 'cpu_physical_cores';
    END IF;

    -- Look up value from device_inventory
    SELECT di.rows INTO rows_data
    FROM device_inventory di
    WHERE di.device_id = p_device_id AND di.table_name = tbl;

    IF rows_data IS NULL OR jsonb_array_length(rows_data) = 0 THEN
        RETURN NULL;
    END IF;

    -- Return the column value from the first row
    result := rows_data->0->>col;
    RETURN result;
END;
$$ LANGUAGE plpgsql STABLE;
-- +goose StatementEnd

-- 7. evaluate_dynamic_group() — from 006. Uses evaluate_dynamic_query_v2.
-- Uses clock_timestamp() to avoid race condition: if a trigger re-queues the group
-- during evaluation, the conditional DELETE preserves the newer queue entry.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION evaluate_dynamic_group(group_id_param TEXT) RETURNS void AS $$
DECLARE
    group_record RECORD;
    device_record RECORD;
    query_text TEXT;
    matches BOOLEAN;
    current_members TEXT[];
    new_members TEXT[];
    members_to_add TEXT[];
    members_to_remove TEXT[];
    member_id TEXT;
    eval_started_at TIMESTAMPTZ;
BEGIN
    eval_started_at := clock_timestamp();

    SELECT id, dynamic_query, is_dynamic INTO group_record
    FROM device_groups_projection
    WHERE id = group_id_param AND is_deleted = FALSE;

    IF NOT FOUND OR NOT group_record.is_dynamic THEN
        DELETE FROM dynamic_group_evaluation_queue WHERE group_id = group_id_param;
        RETURN;
    END IF;

    query_text := group_record.dynamic_query;

    SELECT array_agg(device_id) INTO current_members
    FROM device_group_members_projection
    WHERE group_id = group_id_param;

    current_members := COALESCE(current_members, ARRAY[]::TEXT[]);

    new_members := ARRAY[]::TEXT[];
    FOR device_record IN
        SELECT id, labels FROM devices_projection WHERE is_deleted = FALSE
    LOOP
        -- Use v2 which supports both labels and inventory fields
        matches := evaluate_dynamic_query_v2(device_record.id, device_record.labels, query_text);
        IF matches THEN
            new_members := array_append(new_members, device_record.id);
        END IF;
    END LOOP;

    members_to_add := ARRAY(
        SELECT unnest(new_members) EXCEPT SELECT unnest(current_members)
    );

    members_to_remove := ARRAY(
        SELECT unnest(current_members) EXCEPT SELECT unnest(new_members)
    );

    FOREACH member_id IN ARRAY members_to_add LOOP
        INSERT INTO device_group_members_projection (group_id, device_id, added_at, projection_version)
        VALUES (group_id_param, member_id, NOW(), 0)
        ON CONFLICT (group_id, device_id) DO NOTHING;
    END LOOP;

    FOREACH member_id IN ARRAY members_to_remove LOOP
        DELETE FROM device_group_members_projection
        WHERE group_id = group_id_param AND device_id = member_id;
    END LOOP;

    UPDATE device_groups_projection
    SET member_count = COALESCE(array_length(new_members, 1), 0)
    WHERE id = group_id_param;

    -- Only delete queue entries queued before evaluation started.
    -- If a trigger re-queued this group during evaluation, the newer entry survives.
    DELETE FROM dynamic_group_evaluation_queue
    WHERE group_id = group_id_param AND queued_at <= eval_started_at;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 8. evaluate_queued_dynamic_groups() — from 004. Uses 1000 limit.
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

-- 9. queue_dynamic_groups_for_device() — uses clock_timestamp() for accurate ordering.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION queue_dynamic_groups_for_device(device_id_param TEXT) RETURNS void AS $$
BEGIN
    INSERT INTO dynamic_group_evaluation_queue (group_id, queued_at, reason)
    SELECT id, clock_timestamp(), 'device_' || device_id_param || '_changed'
    FROM device_groups_projection
    WHERE is_dynamic = TRUE AND is_deleted = FALSE
    ON CONFLICT (group_id) DO UPDATE SET queued_at = clock_timestamp();
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 10. trigger_device_label_change() — from 001 (unchanged).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION trigger_device_label_change() RETURNS trigger AS $$
BEGIN
    PERFORM queue_dynamic_groups_for_device(NEW.id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 11. trigger_device_deleted() — from 001 (unchanged).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION trigger_device_deleted() RETURNS trigger AS $$
BEGIN
    IF NEW.is_deleted = TRUE AND (OLD.is_deleted = FALSE OR OLD.is_deleted IS NULL) THEN
        DELETE FROM device_group_members_projection WHERE device_id = NEW.id;
        UPDATE device_groups_projection g
        SET member_count = (
            SELECT COUNT(*) FROM device_group_members_projection m WHERE m.group_id = g.id
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 12. trigger_inventory_change() — from 006. Queues dynamic group re-evaluation when device_inventory changes.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION trigger_inventory_change() RETURNS trigger AS $$
BEGIN
    PERFORM queue_dynamic_groups_for_device(NEW.device_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 13. validate_dynamic_query() — from 006. Uses evaluate_dynamic_query_v2 for validation.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION validate_dynamic_query(query TEXT) RETURNS TEXT AS $$
DECLARE
    test_labels JSONB := '{"test": "value"}'::JSONB;
BEGIN
    IF query IS NULL OR trim(query) = '' THEN
        RETURN NULL;
    END IF;

    IF (length(query) - length(replace(query, '(', ''))) !=
       (length(query) - length(replace(query, ')', ''))) THEN
        RETURN 'Unbalanced parentheses in query';
    END IF;

    BEGIN
        -- Use v2 with a dummy device_id (validation only checks syntax)
        PERFORM evaluate_dynamic_query_v2('00000000000000000000000000', test_labels, query);
        RETURN NULL;
    EXCEPTION WHEN OTHERS THEN
        RETURN 'Query syntax error: ' || SQLERRM;
    END;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- ============================================================================
-- USER GROUP EVALUATION
-- ============================================================================

-- 14. evaluate_user_condition() — from 016 (FINAL). 8 params with profile columns.
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

-- 15. evaluate_dynamic_user_query() — from 016 (FINAL). 9 params with profile columns.
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

-- 16. evaluate_dynamic_user_group() — from 016 (FINAL). Passes profile columns from users_projection.
-- Uses clock_timestamp() to avoid race condition (same as evaluate_dynamic_group).
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
    eval_started_at TIMESTAMPTZ;
BEGIN
    eval_started_at := clock_timestamp();

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

    DELETE FROM dynamic_user_group_evaluation_queue
    WHERE group_id = group_id_param AND queued_at <= eval_started_at;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 17. evaluate_queued_dynamic_user_groups() — from 015 (unchanged by 016).
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

-- 18. queue_dynamic_user_groups_on_user_change() — uses clock_timestamp() for accurate ordering.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION queue_dynamic_user_groups_on_user_change() RETURNS trigger AS $$
BEGIN
    INSERT INTO dynamic_user_group_evaluation_queue (group_id, queued_at, reason)
    SELECT id, clock_timestamp(), 'user_' || COALESCE(NEW.id, OLD.id) || '_changed'
    FROM user_groups_projection
    WHERE is_dynamic = TRUE AND is_deleted = FALSE
    ON CONFLICT (group_id) DO UPDATE SET queued_at = clock_timestamp(), reason = EXCLUDED.reason;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- 19. validate_user_group_query() — from 016 (FINAL). Uses 7 dummy values including profile fields.
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

-- ============================================================================
-- TRIGGER FUNCTIONS FOR USER GROUPS
-- ============================================================================

-- 20. user_attribute_change_trigger — from 016 (FINAL). Includes profile columns.
-- Note: The actual CREATE TRIGGER statement is in the triggers part of the consolidated migration.
-- This is the trigger function that fires on user attribute changes.
-- The trigger itself should be:
--   CREATE TRIGGER user_attribute_change_trigger
--       AFTER INSERT OR UPDATE OF email, disabled, totp_enabled, has_password, is_deleted, display_name, preferred_username, locale
--       ON users_projection
--       FOR EACH ROW
--       EXECUTE FUNCTION queue_dynamic_user_groups_on_user_change();

-- ============================================================================
-- UTILITY FUNCTIONS
-- ============================================================================

-- 21. get_device_sync_interval() — from 001 (unchanged). STABLE.
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

-- 22. get_stream_at() — from 001 (unchanged). STABLE.
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

-- 23. queue_all_dynamic_groups() — periodic full re-evaluation safety net.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION queue_all_dynamic_groups() RETURNS void AS $$
BEGIN
    INSERT INTO dynamic_group_evaluation_queue (group_id, queued_at, reason)
    SELECT id, clock_timestamp(), 'periodic_full_evaluation'
    FROM device_groups_projection
    WHERE is_dynamic = TRUE AND is_deleted = FALSE
    ON CONFLICT (group_id) DO UPDATE SET queued_at = clock_timestamp();

    INSERT INTO dynamic_user_group_evaluation_queue (group_id, queued_at, reason)
    SELECT id, clock_timestamp(), 'periodic_full_evaluation'
    FROM user_groups_projection
    WHERE is_dynamic = TRUE AND is_deleted = FALSE
    ON CONFLICT (group_id) DO UPDATE SET queued_at = clock_timestamp();
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
-- Full teardown is handled by Part 5 down migration.
-- This stub exists for goose compatibility.
