-- The binding between one external subject at one provider and one
-- local user. Both directions are uniquely indexed, so a second link
-- cannot be used to take over an existing account.

-- name: InsertIdentityLink :one
INSERT INTO identity_links (id, user_id, provider_id, external_id, external_email, external_name, linked_at, last_login_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetIdentityLink :one
SELECT * FROM identity_links WHERE id = ?;

-- name: GetIdentityLinkByProviderAndExternalID :one
SELECT * FROM identity_links WHERE provider_id = ? AND external_id = ?;

-- name: GetIdentityLinkByProviderAndUser :one
-- The ownership question: is this subject bound to this provider? No
-- row is the answer a provider gets for every subject it did not
-- provision, which is what keeps one directory out of another's users.
SELECT * FROM identity_links WHERE provider_id = ? AND user_id = ?;

-- name: UpdateIdentityLinkExternalIdentity :one
UPDATE identity_links
SET external_id = ?, external_email = ?, external_name = ?
WHERE id = ?
RETURNING *;

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
WHERE l.user_id = ?
ORDER BY l.id;

-- name: TouchIdentityLinkLogin :one
UPDATE identity_links
SET last_login_at = ?, external_email = ?, external_name = ?
WHERE id = ?
RETURNING *;

-- name: DeleteIdentityLink :one
DELETE FROM identity_links WHERE id = ? RETURNING *;

-- name: DeleteIdentityLinksForUser :execrows
DELETE FROM identity_links WHERE user_id = ?;
