-- OIDC identity providers. client_secret_encrypted holds AES-256-GCM
-- ciphertext bound to this provider row; scim_token_hash holds a
-- non-reversible digest. Neither plaintext is representable here.

-- name: InsertIdentityProvider :one
INSERT INTO identity_providers (
    id, name, slug, provider_type, enabled,
    client_id, client_secret_encrypted,
    issuer_url, authorization_url, token_url, userinfo_url,
    scopes, auto_create_users, auto_link_by_email, trust_email_assertions,
    default_role_id, group_claim, group_mapping,
    created_at, created_by, updated_at
)
VALUES (
    $1, $2, $3, $4, $5,
    $6, $7,
    $8, $9, $10, $11,
    $12, $13, $14, $15,
    $16, $17, $18,
    $19, $20, $19
)
RETURNING *;

-- name: GetIdentityProvider :one
SELECT * FROM identity_providers WHERE id = $1 AND is_deleted = FALSE;

-- name: GetIdentityProviderBySlug :one
SELECT * FROM identity_providers WHERE slug = $1 AND is_deleted = FALSE;

-- name: ListIdentityProviders :many
SELECT * FROM identity_providers
WHERE is_deleted = FALSE AND id > $1
ORDER BY id
LIMIT $2;

-- name: ListEnabledIdentityProviders :many
SELECT * FROM identity_providers
WHERE is_deleted = FALSE AND enabled = TRUE
ORDER BY name;

-- name: CountIdentityProviders :one
SELECT COUNT(*) FROM identity_providers WHERE is_deleted = FALSE;

-- name: UpdateIdentityProvider :one
UPDATE identity_providers
SET name = $2,
    enabled = $3,
    client_id = $4,
    client_secret_encrypted = $5,
    issuer_url = $6,
    authorization_url = $7,
    token_url = $8,
    userinfo_url = $9,
    scopes = $10,
    auto_create_users = $11,
    auto_link_by_email = $12,
    trust_email_assertions = $13,
    default_role_id = $14,
    group_claim = $15,
    group_mapping = $16,
    updated_at = $17
WHERE id = $1 AND is_deleted = FALSE
RETURNING *;

-- name: SoftDeleteIdentityProvider :execrows
-- Soft delete, not erasure: identity_links point at this row and must
-- stay resolvable as evidence of who was once linked where.
UPDATE identity_providers SET is_deleted = TRUE, updated_at = $2
WHERE id = $1 AND is_deleted = FALSE;

-- name: SetIdentityProviderSCIM :one
-- Enable, disable and rotate all land here: enabling writes a fresh
-- token hash, disabling writes FALSE and an empty hash, so a disabled
-- provider cannot be reached with a token issued before.
UPDATE identity_providers
SET scim_enabled = $2, scim_token_hash = $3, updated_at = $4
WHERE id = $1 AND is_deleted = FALSE
RETURNING *;
