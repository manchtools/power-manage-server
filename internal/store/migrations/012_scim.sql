-- +goose Up

-- Add SCIM columns to identity_providers_projection
ALTER TABLE identity_providers_projection
    ADD COLUMN scim_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN scim_token_hash TEXT NOT NULL DEFAULT '';

-- SCIM group mapping: maps external SCIM group IDs to internal user groups
CREATE TABLE scim_group_mapping_projection (
    id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES identity_providers_projection(id),
    scim_group_id TEXT NOT NULL,
    scim_display_name TEXT NOT NULL DEFAULT '',
    user_group_id TEXT NOT NULL REFERENCES user_groups_projection(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    projection_version BIGINT NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX idx_scim_group_mapping_provider_scim
    ON scim_group_mapping_projection(provider_id, scim_group_id);
CREATE INDEX idx_scim_group_mapping_provider
    ON scim_group_mapping_projection(provider_id);
CREATE INDEX idx_scim_group_mapping_user_group
    ON scim_group_mapping_projection(user_group_id);

-- Update identity_provider projector to handle SCIM events
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_identity_provider_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'IdentityProviderCreated' THEN
            INSERT INTO identity_providers_projection (
                id, name, slug, provider_type, enabled,
                client_id, client_secret_encrypted,
                issuer_url, authorization_url, token_url, userinfo_url,
                scopes, auto_create_users, auto_link_by_email,
                default_role_id, disable_password_for_linked,
                group_claim, group_mapping,
                created_at, created_by, updated_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                event.data->>'slug',
                COALESCE(event.data->>'provider_type', 'oidc'),
                TRUE,
                event.data->>'client_id',
                COALESCE(event.data->>'client_secret_encrypted', ''),
                event.data->>'issuer_url',
                COALESCE(event.data->>'authorization_url', ''),
                COALESCE(event.data->>'token_url', ''),
                COALESCE(event.data->>'userinfo_url', ''),
                CASE WHEN jsonb_typeof(event.data->'scopes') = 'array' THEN ARRAY(SELECT jsonb_array_elements_text(event.data->'scopes')) ELSE '{}' END,
                COALESCE((event.data->>'auto_create_users')::BOOLEAN, FALSE),
                COALESCE((event.data->>'auto_link_by_email')::BOOLEAN, FALSE),
                COALESCE(event.data->>'default_role_id', ''),
                COALESCE((event.data->>'disable_password_for_linked')::BOOLEAN, FALSE),
                COALESCE(event.data->>'group_claim', ''),
                COALESCE((event.data->'group_mapping')::JSONB, '{}'),
                event.occurred_at,
                event.actor_id,
                event.occurred_at,
                event.sequence_num
            );

        WHEN 'IdentityProviderUpdated' THEN
            UPDATE identity_providers_projection
            SET name = COALESCE(event.data->>'name', name),
                enabled = COALESCE((event.data->>'enabled')::BOOLEAN, enabled),
                client_id = COALESCE(NULLIF(event.data->>'client_id', ''), client_id),
                client_secret_encrypted = COALESCE(NULLIF(event.data->>'client_secret_encrypted', ''), client_secret_encrypted),
                issuer_url = COALESCE(NULLIF(event.data->>'issuer_url', ''), issuer_url),
                authorization_url = COALESCE(event.data->>'authorization_url', authorization_url),
                token_url = COALESCE(event.data->>'token_url', token_url),
                userinfo_url = COALESCE(event.data->>'userinfo_url', userinfo_url),
                scopes = CASE WHEN jsonb_typeof(event.data->'scopes') = 'array' THEN ARRAY(SELECT jsonb_array_elements_text(event.data->'scopes')) ELSE scopes END,
                auto_create_users = COALESCE((event.data->>'auto_create_users')::BOOLEAN, auto_create_users),
                auto_link_by_email = COALESCE((event.data->>'auto_link_by_email')::BOOLEAN, auto_link_by_email),
                default_role_id = COALESCE(event.data->>'default_role_id', default_role_id),
                disable_password_for_linked = COALESCE((event.data->>'disable_password_for_linked')::BOOLEAN, disable_password_for_linked),
                group_claim = COALESCE(event.data->>'group_claim', group_claim),
                group_mapping = COALESCE((event.data->'group_mapping')::JSONB, group_mapping),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'IdentityProviderDeleted' THEN
            UPDATE identity_providers_projection
            SET is_deleted = TRUE,
                enabled = FALSE,
                scim_enabled = FALSE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Clean up identity links and SCIM group mappings for this provider
            DELETE FROM identity_links_projection WHERE provider_id = event.stream_id;
            DELETE FROM scim_group_mapping_projection WHERE provider_id = event.stream_id;

        WHEN 'IdentityProviderSCIMEnabled' THEN
            UPDATE identity_providers_projection
            SET scim_enabled = TRUE,
                scim_token_hash = event.data->>'scim_token_hash',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'IdentityProviderSCIMDisabled' THEN
            UPDATE identity_providers_projection
            SET scim_enabled = FALSE,
                scim_token_hash = '',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Clean up SCIM group mappings
            DELETE FROM scim_group_mapping_projection WHERE provider_id = event.stream_id;

        WHEN 'IdentityProviderSCIMTokenRotated' THEN
            UPDATE identity_providers_projection
            SET scim_token_hash = event.data->>'scim_token_hash',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'IdentityLinked' THEN
            INSERT INTO identity_links_projection (
                id, user_id, provider_id, external_id,
                external_email, external_name,
                linked_at, last_login_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'user_id',
                event.data->>'provider_id',
                event.data->>'external_id',
                COALESCE(event.data->>'external_email', ''),
                COALESCE(event.data->>'external_name', ''),
                event.occurred_at,
                event.occurred_at,
                event.sequence_num
            )
            ON CONFLICT (provider_id, external_id) DO UPDATE SET
                external_email = EXCLUDED.external_email,
                external_name = EXCLUDED.external_name,
                last_login_at = EXCLUDED.last_login_at,
                projection_version = EXCLUDED.projection_version;

        WHEN 'IdentityLinkLoginUpdated' THEN
            UPDATE identity_links_projection
            SET last_login_at = event.occurred_at,
                external_email = COALESCE(NULLIF(event.data->>'external_email', ''), external_email),
                external_name = COALESCE(NULLIF(event.data->>'external_name', ''), external_name),
                projection_version = event.sequence_num
            WHERE provider_id = event.data->>'provider_id'
              AND external_id = event.data->>'external_id';

        WHEN 'IdentityUnlinked' THEN
            DELETE FROM identity_links_projection
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Projector for scim_group_mapping events
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_scim_group_mapping_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'SCIMGroupMapped' THEN
            INSERT INTO scim_group_mapping_projection (
                id, provider_id, scim_group_id, scim_display_name,
                user_group_id, created_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'provider_id',
                event.data->>'scim_group_id',
                COALESCE(event.data->>'scim_display_name', ''),
                event.data->>'user_group_id',
                event.occurred_at,
                event.sequence_num
            )
            ON CONFLICT (provider_id, scim_group_id) DO UPDATE SET
                scim_display_name = EXCLUDED.scim_display_name,
                user_group_id = EXCLUDED.user_group_id,
                projection_version = EXCLUDED.projection_version;

        WHEN 'SCIMGroupUnmapped' THEN
            DELETE FROM scim_group_mapping_projection
            WHERE provider_id = event.data->>'provider_id'
              AND scim_group_id = event.data->>'scim_group_id';

        WHEN 'SCIMGroupMappingUpdated' THEN
            UPDATE scim_group_mapping_projection
            SET scim_display_name = COALESCE(event.data->>'scim_display_name', scim_display_name),
                projection_version = event.sequence_num
            WHERE provider_id = event.data->>'provider_id'
              AND scim_group_id = event.data->>'scim_group_id';

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Add scim_group_mapping to the master projector
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_event() RETURNS trigger AS $$
BEGIN
    CASE NEW.stream_type
        WHEN 'user' THEN
            BEGIN
                PERFORM project_user_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'token' THEN
            BEGIN
                PERFORM project_token_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'device' THEN
            BEGIN
                PERFORM project_device_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'action' THEN
            BEGIN
                PERFORM project_action_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'definition' THEN
            BEGIN
                PERFORM project_action_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, 'definition->action', SQLERRM);
            END;

            BEGIN
                PERFORM project_definition_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, 'definition->definition', SQLERRM);
            END;

        WHEN 'action_set' THEN
            BEGIN
                PERFORM project_action_set_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'device_group' THEN
            BEGIN
                PERFORM project_device_group_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'assignment' THEN
            BEGIN
                PERFORM project_assignment_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'execution' THEN
            BEGIN
                PERFORM project_execution_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'user_selection' THEN
            BEGIN
                PERFORM project_user_selection_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'role' THEN
            BEGIN
                PERFORM project_role_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'user_role' THEN
            BEGIN
                PERFORM project_user_role_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'totp' THEN
            BEGIN
                PERFORM project_totp_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'user_group' THEN
            BEGIN
                PERFORM project_user_group_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'identity_provider' THEN
            BEGIN
                PERFORM project_identity_provider_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'scim_group_mapping' THEN
            BEGIN
                PERFORM project_scim_group_mapping_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        ELSE
            NULL;
    END CASE;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down

DROP FUNCTION IF EXISTS project_scim_group_mapping_event;
DROP TABLE IF EXISTS scim_group_mapping_projection;
ALTER TABLE identity_providers_projection DROP COLUMN IF EXISTS scim_enabled;
ALTER TABLE identity_providers_projection DROP COLUMN IF EXISTS scim_token_hash;
