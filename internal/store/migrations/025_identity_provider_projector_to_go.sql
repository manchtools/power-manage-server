-- Replace project_identity_provider_event() with a no-op stub. The
-- actual projection logic now lives in
-- projectors.IdentityProviderListener (Go, post-commit). The shared
-- project_event() dispatcher trigger still PERFORMs
-- project_identity_provider_event(NEW); the no-op stub keeps the
-- dispatch quiet until the dispatcher is rewritten to skip ported
-- stream types.
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. All nine event types (IdP CRUD + SCIM toggles +
--     identity-link CRUD) atomic with the event commit.
--   - After: Go listener fires post-commit. Multi-write paths
--     (IdentityProviderDeleted, IdentityProviderSCIMDisabled) wrap
--     their writes in store.WithTx. Per the asymmetric-guard
--     discipline (CR caught it on #101, documented in
--     `feedback_projector_multiwrite_guard_asymmetry`), the guarded
--     soft-delete returns rows-affected and the listener
--     SHORT-CIRCUITS the cascade DELETEs when n == 0 — preventing a
--     stale RebuildAll-style replay from nuking live identity_links
--     or scim_group_mappings on a never-actually-deleted IdP.
--
-- Tightening: every UPDATE has a `WHERE projection_version < $N`
-- guard. The PL/pgSQL projector lacked these.
--
-- See manchtools/power-manage-server#104. Ninth port under the
-- projector-migration pattern.
--
-- Refs tracker #107.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_identity_provider_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.IdentityProviderListener. See
    -- migration comment + the listener wiring in cmd/control/main.go
    -- via projectors.WireAll.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the original PL/pgSQL projector verbatim from migration 003.

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
