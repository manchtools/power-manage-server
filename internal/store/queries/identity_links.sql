-- name: GetIdentityLinkByProviderAndExternalID :one
SELECT * FROM identity_links_projection
WHERE provider_id = $1 AND external_id = $2;

-- name: GetIdentityLinkByID :one
SELECT * FROM identity_links_projection
WHERE id = $1;

-- name: ListIdentityLinksForUser :many
SELECT il.*, ip.name AS provider_name, ip.slug AS provider_slug
FROM identity_links_projection il
JOIN identity_providers_projection ip ON ip.id = il.provider_id
WHERE il.user_id = $1 AND ip.is_deleted = FALSE
ORDER BY il.linked_at DESC;

-- name: CountIdentityLinksForUser :one
SELECT COUNT(*) FROM identity_links_projection
WHERE user_id = $1;

-- name: GetIdentityLinkByProviderAndUser :one
SELECT * FROM identity_links_projection
WHERE provider_id = $1 AND user_id = $2;

-- name: ListLinkedProviderIDsForUser :many
SELECT provider_id FROM identity_links_projection
WHERE user_id = $1;
