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

-- name: ListIdentityLinksByProvider :many
SELECT il.*, u.has_password
FROM identity_links_projection il
JOIN users_projection u ON u.id = il.user_id
WHERE il.provider_id = $1 AND u.is_deleted = FALSE;

-- name: UpsertIdentityLink :exec
-- IdentityLinked handler. ON CONFLICT (provider_id, external_id) DO
-- UPDATE matches the PL/pgSQL projector — re-linking the same
-- external identity (e.g. on next login) refreshes external_email,
-- external_name, and last_login_at without minting a new row.
INSERT INTO identity_links_projection (
    id, user_id, provider_id, external_id,
    external_email, external_name,
    linked_at, last_login_at, projection_version
) VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8)
ON CONFLICT (provider_id, external_id) DO UPDATE SET
    external_email = EXCLUDED.external_email,
    external_name = EXCLUDED.external_name,
    last_login_at = EXCLUDED.last_login_at,
    projection_version = EXCLUDED.projection_version;

-- name: UpdateIdentityLinkLogin :exec
-- IdentityLinkLoginUpdated handler. Empty external_email /
-- external_name preserve existing (NULLIF semantics) — the handler
-- emits this on every successful SSO login but doesn't always carry
-- email/name updates.
UPDATE identity_links_projection
SET last_login_at = sqlc.arg('last_login_at'),
    external_email = COALESCE(NULLIF(sqlc.arg('external_email')::TEXT, ''), external_email),
    external_name = COALESCE(NULLIF(sqlc.arg('external_name')::TEXT, ''), external_name),
    projection_version = sqlc.arg('projection_version')
WHERE provider_id = sqlc.arg('provider_id')
  AND external_id = sqlc.arg('external_id')
  AND projection_version < sqlc.arg('projection_version');

-- name: DeleteIdentityLinkByID :exec
-- IdentityUnlinked handler. Stream_id IS the link id (set by the
-- handler that emitted IdentityLinked).
DELETE FROM identity_links_projection WHERE id = $1;
