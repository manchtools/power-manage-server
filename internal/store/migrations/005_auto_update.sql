-- +goose Up

-- Add auto_update_agents column to server_settings_projection
ALTER TABLE server_settings_projection
    ADD COLUMN auto_update_agents BOOLEAN NOT NULL DEFAULT FALSE;

-- Update the projection function to handle the new field
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_server_settings_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ServerSettingUpdated' THEN
            UPDATE server_settings_projection
            SET user_provisioning_enabled = COALESCE((event.data->>'user_provisioning_enabled')::BOOLEAN, user_provisioning_enabled),
                ssh_access_for_all = COALESCE((event.data->>'ssh_access_for_all')::BOOLEAN, ssh_access_for_all),
                auto_update_agents = COALESCE((event.data->>'auto_update_agents')::BOOLEAN, auto_update_agents),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = 'global';
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down

-- Restore the projection function without auto_update_agents
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_server_settings_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ServerSettingUpdated' THEN
            UPDATE server_settings_projection
            SET user_provisioning_enabled = COALESCE((event.data->>'user_provisioning_enabled')::BOOLEAN, user_provisioning_enabled),
                ssh_access_for_all = COALESCE((event.data->>'ssh_access_for_all')::BOOLEAN, ssh_access_for_all),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = 'global';
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

ALTER TABLE server_settings_projection DROP COLUMN auto_update_agents;
