-- The binding between one external subject at one provider and one
-- local user. Both directions are uniquely indexed, so a second link
-- cannot be used to take over an existing account.

-- name: InsertIdentityLink :one
INSERT INTO identity_links (id, user_id, provider_id, external_id, external_email, external_name, linked_at, last_login_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
RETURNING *;

-- name: GetIdentityLink :one
SELECT * FROM identity_links WHERE id = $1;

-- name: GetIdentityLinkByProviderAndExternalID :one
SELECT * FROM identity_links WHERE provider_id = $1 AND external_id = $2;

-- name: ListIdentityLinksForUser :many
SELECT
    l.id,
    l.user_id,
    l.provider_id,
    l.external_id,
    l.external_email,
    l.external_name,
    l.linked_at,
    l.last_login_at,
    p.name AS provider_name,
    p.slug AS provider_slug
FROM identity_links l
JOIN identity_providers p ON p.id = l.provider_id
WHERE l.user_id = $1
ORDER BY l.id;

-- name: TouchIdentityLinkLogin :one
UPDATE identity_links
SET last_login_at = $2, external_email = $3, external_name = $4
WHERE id = $1
RETURNING *;

-- name: DeleteIdentityLink :one
DELETE FROM identity_links WHERE id = $1 RETURNING *;

-- name: DeleteIdentityLinksForUser :execrows
DELETE FROM identity_links WHERE user_id = $1;
