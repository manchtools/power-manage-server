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
