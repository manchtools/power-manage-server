-- OIDC identity providers. client_secret_encrypted holds AES-256-GCM
-- ciphertext bound to this provider row; scim_token_hash holds a
-- non-reversible digest. Neither plaintext is representable here.

-- name: InsertIdentityProvider :one
INSERT INTO identity_providers (
    id, name, slug, provider_type, enabled,
    client_id, cli_client_id, client_secret_encrypted,
    issuer_url, authorization_url, token_url, userinfo_url,
    scopes, auto_create_users, auto_link_by_email, trust_email_assertions,
    default_role_id, group_claim, group_mapping,
    created_at, created_by, updated_at
)
VALUES (
    ?, ?, ?, ?, ?,
    ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?,
    ?, ?, ?
)
RETURNING *;

-- name: GetIdentityProvider :one
SELECT * FROM identity_providers WHERE id = ? AND is_deleted = FALSE;

-- name: GetIdentityProviderBySlug :one
SELECT * FROM identity_providers WHERE slug = ? AND is_deleted = FALSE;

-- name: ListIdentityProviders :many
SELECT * FROM identity_providers
WHERE is_deleted = FALSE AND id > ?
ORDER BY id
LIMIT ?;

-- name: ListEnabledIdentityProviders :many
SELECT * FROM identity_providers
WHERE is_deleted = FALSE AND enabled = TRUE
ORDER BY name;

-- name: CountIdentityProviders :one
SELECT COUNT(*) FROM identity_providers WHERE is_deleted = FALSE;

-- name: UpdateIdentityProvider :one
UPDATE identity_providers
SET name = ?,
    enabled = ?,
    client_id = ?,
    cli_client_id = ?,
    client_secret_encrypted = ?,
    issuer_url = ?,
    authorization_url = ?,
    token_url = ?,
    userinfo_url = ?,
    scopes = ?,
    auto_create_users = ?,
    auto_link_by_email = ?,
    trust_email_assertions = ?,
    default_role_id = ?,
    group_claim = ?,
    group_mapping = ?,
    updated_at = ?
WHERE id = ? AND is_deleted = FALSE
RETURNING *;

-- name: SoftDeleteIdentityProvider :execrows
-- Soft delete, not erasure: identity_links point at this row and must
-- stay resolvable as evidence of who was once linked where.
UPDATE identity_providers SET is_deleted = TRUE, updated_at = ?
WHERE id = ? AND is_deleted = FALSE;

-- name: SetIdentityProviderSCIM :one
-- Enable, disable and rotate all land here: enabling writes a fresh
-- token hash, disabling writes FALSE and an empty hash, so a disabled
-- provider cannot be reached with a token issued before.
UPDATE identity_providers
SET scim_enabled = ?, scim_token_hash = ?, updated_at = ?
WHERE id = ? AND is_deleted = FALSE
RETURNING *;
