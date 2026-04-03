-- +goose Up

-- Extend evaluate_condition_v2 to support device.group field for
-- checking device group membership in dynamic group queries.
-- Usage: device.group equals "Group Name"
--        device.group in "Group A,Group B"
--        device.group exists
-- Evaluates against the last materialized snapshot of group membership.

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
    group_names TEXT;
BEGIN
    condition := trim(condition);

    IF condition = '' OR condition IS NULL THEN
        RETURN TRUE;
    END IF;

    -- Check if this is a device.group condition (membership check by group name)
    IF condition ~* '^\s*device\.group\s+' THEN
        -- Collect all group names this device belongs to
        SELECT string_agg(dg.name, '|||')
        INTO group_names
        FROM device_group_members_projection dgm
        JOIN device_groups_projection dg ON dg.id = dgm.group_id AND dg.is_deleted = FALSE
        WHERE dgm.device_id = p_device_id;

        -- exists / notExists
        IF condition ~* '^\s*device\.group\s+exists\s*$' THEN
            RETURN group_names IS NOT NULL;
        END IF;
        IF condition ~* '^\s*device\.group\s+notExists\s*$' THEN
            RETURN group_names IS NULL;
        END IF;

        -- Parse operator + value
        parts := regexp_matches(condition, '^\s*device\.group\s+(equals|notEquals|contains|notContains|in|notIn)\s+[\"'']?(.+?)[\"'']?\s*$', 'i');
        IF parts IS NULL THEN
            RETURN FALSE;
        END IF;
        operator := lower(parts[1]);
        value := parts[2];

        IF group_names IS NULL THEN
            RETURN operator IN ('notequals', 'notcontains', 'notin');
        END IF;

        -- Split group names into array for membership checks
        values_arr := string_to_array(group_names, '|||');

        CASE operator
            WHEN 'equals' THEN
                -- Device is in a group with this exact name
                RETURN lower(value) = ANY(SELECT lower(unnest(values_arr)));
            WHEN 'notequals' THEN
                RETURN lower(value) != ALL(SELECT lower(unnest(values_arr)));
            WHEN 'contains' THEN
                -- Any group name contains the substring
                RETURN EXISTS(SELECT 1 FROM unnest(values_arr) AS g WHERE lower(g) LIKE '%' || lower(value) || '%');
            WHEN 'notcontains' THEN
                RETURN NOT EXISTS(SELECT 1 FROM unnest(values_arr) AS g WHERE lower(g) LIKE '%' || lower(value) || '%');
            WHEN 'in' THEN
                -- Device is in any of the comma-separated group names
                DECLARE
                    check_names TEXT[];
                    cn TEXT;
                BEGIN
                    check_names := string_to_array(value, ',');
                    FOREACH cn IN ARRAY check_names LOOP
                        IF lower(trim(cn)) = ANY(SELECT lower(unnest(values_arr))) THEN
                            RETURN TRUE;
                        END IF;
                    END LOOP;
                    RETURN FALSE;
                END;
            WHEN 'notin' THEN
                DECLARE
                    check_names TEXT[];
                    cn TEXT;
                BEGIN
                    check_names := string_to_array(value, ',');
                    FOREACH cn IN ARRAY check_names LOOP
                        IF lower(trim(cn)) = ANY(SELECT lower(unnest(values_arr))) THEN
                            RETURN FALSE;
                        END IF;
                    END LOOP;
                    RETURN TRUE;
                END;
            ELSE
                RETURN FALSE;
        END CASE;
    END IF;

    -- Check if this is a device.* (non-label, non-group) condition
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

-- +goose Down

-- Restore original evaluate_condition_v2 without device.group support.
-- The down migration re-creates the function from 004_dynamic_groups.sql.
-- This is safe because CREATE OR REPLACE is idempotent.
