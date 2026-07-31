-- The subject view a SCIM directory is allowed to see.
--
-- Every statement joins identity_links and filters on provider_id: a
-- directory addresses only the subjects it is itself bound to, so a
-- second directory's subjects are not merely hidden from the response,
-- they never enter the result set.

-- name: ListSCIMUsers :many
SELECT sqlc.embed(u), l.external_id
FROM users u
JOIN identity_links l ON l.user_id = u.id
WHERE l.provider_id = $1 AND u.is_deleted = FALSE
ORDER BY u.id
LIMIT $2 OFFSET $3;

-- name: CountSCIMUsers :one
SELECT COUNT(*)
FROM users u
JOIN identity_links l ON l.user_id = u.id
WHERE l.provider_id = $1 AND u.is_deleted = FALSE;

-- name: FindSCIMUserByEmail :one
SELECT sqlc.embed(u), l.external_id
FROM users u
JOIN identity_links l ON l.user_id = u.id
WHERE l.provider_id = $1 AND u.email = $2 AND u.is_deleted = FALSE;

-- name: FindSCIMUserByExternalID :one
SELECT sqlc.embed(u), l.external_id
FROM users u
JOIN identity_links l ON l.user_id = u.id
WHERE l.provider_id = $1 AND l.external_id = $2 AND u.is_deleted = FALSE;
