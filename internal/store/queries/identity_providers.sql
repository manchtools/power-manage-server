-- name: GetIdentityProviderByID :one
SELECT * FROM identity_providers_projection
WHERE id = $1 AND is_deleted = FALSE;

-- name: GetIdentityProviderBySlug :one
SELECT * FROM identity_providers_projection
WHERE slug = $1 AND is_deleted = FALSE;

-- name: ListIdentityProviders :many
SELECT * FROM identity_providers_projection
WHERE is_deleted = FALSE
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountIdentityProviders :one
SELECT COUNT(*) FROM identity_providers_projection
WHERE is_deleted = FALSE;

-- name: ListEnabledIdentityProviders :many
SELECT * FROM identity_providers_projection
WHERE is_deleted = FALSE AND enabled = TRUE
ORDER BY name ASC;

-- name: GetLinkedProvidersDisablingPassword :many
SELECT ip.* FROM identity_providers_projection ip
JOIN identity_links_projection il ON il.provider_id = ip.id
WHERE il.user_id = $1
  AND ip.is_deleted = FALSE
  AND ip.enabled = TRUE
  AND ip.disable_password_for_linked = TRUE;

-- name: InsertIdentityProviderProjection :exec
-- IdentityProviderCreated handler. ON CONFLICT DO NOTHING for replay
-- safety (reconciler may re-deliver the event). All COALESCE defaults
-- are normalized to zero values at the listener layer.
INSERT INTO identity_providers_projection (
    id, name, slug, provider_type, enabled,
    client_id, client_secret_encrypted,
    issuer_url, authorization_url, token_url, userinfo_url,
    scopes, auto_create_users, auto_link_by_email,
    default_role_id, disable_password_for_linked,
    group_claim, group_mapping,
    created_at, created_by, updated_at, projection_version,
    trust_email_assertions
) VALUES ($1, $2, $3, $4, TRUE, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $18, $20, $21)
ON CONFLICT (id) DO NOTHING;

-- name: UpdateIdentityProviderProjection :exec
-- IdentityProviderUpdated handler. nil pointer params land as SQL NULL
-- which COALESCE preserves the existing column value. The listener
-- collapses empty-string to nil for NULLIF-shaped fields (client_id,
-- client_secret_encrypted, issuer_url) before dispatch. Stale-replay
-- guard via projection_version.
UPDATE identity_providers_projection
SET name = COALESCE(sqlc.narg('name')::TEXT, name),
    enabled = COALESCE(sqlc.narg('enabled')::BOOLEAN, enabled),
    client_id = COALESCE(sqlc.narg('client_id')::TEXT, client_id),
    client_secret_encrypted = COALESCE(sqlc.narg('client_secret_encrypted')::TEXT, client_secret_encrypted),
    issuer_url = COALESCE(sqlc.narg('issuer_url')::TEXT, issuer_url),
    authorization_url = COALESCE(sqlc.narg('authorization_url')::TEXT, authorization_url),
    token_url = COALESCE(sqlc.narg('token_url')::TEXT, token_url),
    userinfo_url = COALESCE(sqlc.narg('userinfo_url')::TEXT, userinfo_url),
    scopes = COALESCE(sqlc.narg('scopes')::TEXT[], scopes),
    auto_create_users = COALESCE(sqlc.narg('auto_create_users')::BOOLEAN, auto_create_users),
    auto_link_by_email = COALESCE(sqlc.narg('auto_link_by_email')::BOOLEAN, auto_link_by_email),
    default_role_id = COALESCE(sqlc.narg('default_role_id')::TEXT, default_role_id),
    disable_password_for_linked = COALESCE(sqlc.narg('disable_password_for_linked')::BOOLEAN, disable_password_for_linked),
    group_claim = COALESCE(sqlc.narg('group_claim')::TEXT, group_claim),
    group_mapping = COALESCE(sqlc.narg('group_mapping')::JSONB, group_mapping),
    trust_email_assertions = COALESCE(sqlc.narg('trust_email_assertions')::BOOLEAN, trust_email_assertions),
    updated_at = sqlc.arg('updated_at'),
    projection_version = sqlc.arg('projection_version')
WHERE id = sqlc.arg('id')
  AND projection_version < sqlc.arg('projection_version');

-- name: SoftDeleteIdentityProviderProjection :execrows
-- IdentityProviderDeleted handler — first half. Returns rows-affected
-- so the listener can SHORT-CIRCUIT the cascade DELETEs when
-- projection_version guard rejects a stale replay (per the
-- multi-write-asymmetric-guard discipline that CR caught on #101).
UPDATE identity_providers_projection
SET is_deleted = TRUE,
    enabled = FALSE,
    scim_enabled = FALSE,
    updated_at = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: DeleteIdentityLinksByProvider :exec
-- IdentityProviderDeleted handler — second half (cascade). Run only
-- if SoftDeleteIdentityProviderProjection affected a row.
DELETE FROM identity_links_projection WHERE provider_id = $1;

-- name: DeleteSCIMGroupMappingsByProvider :exec
-- IdentityProviderDeleted handler — third half (cascade). Also reused
-- by IdentityProviderSCIMDisabled (where SCIM mapping cleanup is the
-- only side-effect besides flipping scim_enabled).
DELETE FROM scim_group_mapping_projection WHERE provider_id = $1;

-- name: SetIdentityProviderSCIMEnabled :exec
-- IdentityProviderSCIMEnabled handler. scim_token_hash is required
-- on enable — the handler never emits this event without one.
UPDATE identity_providers_projection
SET scim_enabled = TRUE,
    scim_token_hash = $2,
    updated_at = $3,
    projection_version = $4
WHERE id = $1
  AND projection_version < $4;

-- name: SetIdentityProviderSCIMDisabled :execrows
-- IdentityProviderSCIMDisabled handler. Returns rows-affected so the
-- listener can SHORT-CIRCUIT the SCIM mapping cascade DELETE on stale
-- replay.
UPDATE identity_providers_projection
SET scim_enabled = FALSE,
    scim_token_hash = '',
    updated_at = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: RotateIdentityProviderSCIMToken :exec
-- IdentityProviderSCIMTokenRotated handler. Updates only the hash
-- (does not touch scim_enabled, so accidental rotation on a disabled
-- provider stays disabled).
UPDATE identity_providers_projection
SET scim_token_hash = $2,
    updated_at = $3,
    projection_version = $4
WHERE id = $1
  AND projection_version < $4;
