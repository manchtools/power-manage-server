-- +goose Up

-- ============================================================================
-- Device Inventory (cached hardware/software data from agent OSQuery)
-- ============================================================================

CREATE TABLE device_inventory (
    device_id TEXT NOT NULL,
    table_name TEXT NOT NULL,
    rows JSONB NOT NULL DEFAULT '[]',
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (device_id, table_name)
);

CREATE INDEX idx_device_inventory_device ON device_inventory(device_id);

-- ============================================================================
-- OSQuery on-demand results (dispatched via web UI, polled until complete)
-- ============================================================================

CREATE TABLE osquery_results (
    query_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    table_name TEXT NOT NULL,
    completed BOOLEAN NOT NULL DEFAULT FALSE,
    success BOOLEAN NOT NULL DEFAULT FALSE,
    error TEXT NOT NULL DEFAULT '',
    rows JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_osquery_results_device ON osquery_results(device_id);
CREATE INDEX idx_osquery_results_completed ON osquery_results(completed, created_at);

-- ============================================================================
-- Extended dynamic group evaluation: support device.* fields from inventory
-- ============================================================================

-- Helper: resolve a device.* field value from inventory tables.
-- Returns NULL if the field is not available.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION resolve_inventory_field(p_device_id TEXT, field_name TEXT) RETURNS TEXT AS $$
DECLARE
    tbl TEXT;
    col TEXT;
    result TEXT;
    rows_data JSONB;
BEGIN
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

-- Extended evaluate_condition that supports both label-based and inventory-based conditions.
-- For conditions starting with "device.labels." or "labels.", delegates to existing evaluate_condition.
-- For conditions starting with "device.", looks up inventory data.
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

-- Extended evaluate_dynamic_query that passes device_id through for inventory lookups.
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

-- Update evaluate_dynamic_group to use v2 functions (passes device_id)
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
BEGIN
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

    DELETE FROM dynamic_group_evaluation_queue WHERE group_id = group_id_param;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Update validate_dynamic_query to accept device.* fields
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

-- Update CountMatchingDevicesForQuery to use v2
-- (This is a SQL query in device_groups.sql but we also update the inline usage)

-- Trigger: re-evaluate dynamic groups when inventory changes for a device
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION trigger_inventory_change() RETURNS trigger AS $$
BEGIN
    PERFORM queue_dynamic_groups_for_device(NEW.device_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER device_inventory_changed
    AFTER INSERT OR UPDATE ON device_inventory
    FOR EACH ROW
    EXECUTE FUNCTION trigger_inventory_change();

-- +goose Down

DROP TRIGGER IF EXISTS device_inventory_changed ON device_inventory;
DROP FUNCTION IF EXISTS trigger_inventory_change();

-- Restore original evaluate_dynamic_group (without v2)
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
BEGIN
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
        matches := evaluate_dynamic_query(device_record.labels, query_text);
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

    DELETE FROM dynamic_group_evaluation_queue WHERE group_id = group_id_param;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Restore original validate_dynamic_query
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
        PERFORM evaluate_dynamic_query(test_labels, query);
        RETURN NULL;
    EXCEPTION WHEN OTHERS THEN
        RETURN 'Query syntax error: ' || SQLERRM;
    END;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

DROP FUNCTION IF EXISTS evaluate_dynamic_query_v2(TEXT, JSONB, TEXT, INTEGER);
DROP FUNCTION IF EXISTS evaluate_condition_v2(TEXT, JSONB, TEXT);
DROP FUNCTION IF EXISTS resolve_inventory_field(TEXT, TEXT);
DROP TABLE IF EXISTS osquery_results;
DROP TABLE IF EXISTS device_inventory;
