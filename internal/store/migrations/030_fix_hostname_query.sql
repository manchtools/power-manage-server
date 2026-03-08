-- +goose Up

-- Fix resolve_inventory_field to check devices_projection.hostname first.
-- Previously, device.hostname lookups only checked device_inventory (osquery data),
-- which is empty for devices that haven't sent inventory yet. The hostname is always
-- available in devices_projection from registration.
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

-- +goose Down

-- Restore original function without devices_projection fallback.
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

    -- Fix cpu_cores mapping
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
