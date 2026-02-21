-- +goose Up

-- Identity providers (OIDC SSO) projection
CREATE TABLE identity_providers_projection (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    provider_type TEXT NOT NULL DEFAULT 'oidc',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    client_id TEXT NOT NULL,
    client_secret_encrypted TEXT NOT NULL DEFAULT '',
    issuer_url TEXT NOT NULL,
    authorization_url TEXT NOT NULL DEFAULT '',
    token_url TEXT NOT NULL DEFAULT '',
    userinfo_url TEXT NOT NULL DEFAULT '',
    scopes TEXT[] NOT NULL DEFAULT '{}',
    auto_create_users BOOLEAN NOT NULL DEFAULT FALSE,
    auto_link_by_email BOOLEAN NOT NULL DEFAULT FALSE,
    default_role_id TEXT NOT NULL DEFAULT '',
    attribute_mapping JSONB NOT NULL DEFAULT '{}',
    disable_password_for_linked BOOLEAN NOT NULL DEFAULT FALSE,
    group_claim TEXT NOT NULL DEFAULT '',
    group_mapping JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX idx_identity_providers_slug ON identity_providers_projection(slug) WHERE is_deleted = FALSE;

-- Identity links: maps external IdP identities to local users
CREATE TABLE identity_links_projection (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users_projection(id),
    provider_id TEXT NOT NULL REFERENCES identity_providers_projection(id),
    external_id TEXT NOT NULL,
    external_email TEXT NOT NULL DEFAULT '',
    external_name TEXT NOT NULL DEFAULT '',
    linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,
    projection_version BIGINT NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX idx_identity_links_provider_external ON identity_links_projection(provider_id, external_id);
CREATE UNIQUE INDEX idx_identity_links_user_provider ON identity_links_projection(user_id, provider_id);
CREATE INDEX idx_identity_links_user ON identity_links_projection(user_id);

-- Auth states for OIDC flow (CSRF protection, PKCE)
CREATE TABLE auth_states (
    state TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES identity_providers_projection(id),
    nonce TEXT NOT NULL DEFAULT '',
    code_verifier TEXT NOT NULL DEFAULT '',
    redirect_uri TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_auth_states_expires ON auth_states(expires_at);

-- Add has_password column to users_projection
-- Existing users all have passwords, SSO-only users will have has_password=FALSE
ALTER TABLE users_projection ADD COLUMN has_password BOOLEAN NOT NULL DEFAULT TRUE;

-- Make password_hash nullable for SSO-only users
ALTER TABLE users_projection ALTER COLUMN password_hash DROP NOT NULL;

-- Projector function for identity_provider events
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
                COALESCE(ARRAY(SELECT jsonb_array_elements_text(event.data->'scopes')), '{}'),
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
                scopes = COALESCE(ARRAY(SELECT jsonb_array_elements_text(event.data->'scopes')), scopes),
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
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Clean up identity links for this provider
            DELETE FROM identity_links_projection WHERE provider_id = event.stream_id;

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

-- Update the user projector to handle has_password for SSO users
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

-- Add identity_provider stream type to the master projector
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

        ELSE
            NULL;
    END CASE;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down

DROP FUNCTION IF EXISTS project_identity_provider_event;
DROP TABLE IF EXISTS auth_states;
DROP TABLE IF EXISTS identity_links_projection;
DROP TABLE IF EXISTS identity_providers_projection;
ALTER TABLE users_projection DROP COLUMN IF EXISTS has_password;
