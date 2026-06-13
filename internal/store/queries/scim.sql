-- name: GetIdentityProviderBySlugForSCIM :one
-- WS5 #5: SCIM follows the provider login switch. A provider disabled for
-- login (enabled = FALSE) must also reject SCIM, even with a valid bearer —
-- otherwise an operator who "turned off" an IdP leaves its automated
-- provisioning channel wide open. SCIM additionally requires scim_enabled.
SELECT * FROM identity_providers_projection
WHERE slug = $1 AND is_deleted = FALSE AND scim_enabled = TRUE AND enabled = TRUE;

-- name: GetSCIMGroupMapping :one
SELECT * FROM scim_group_mapping_projection
WHERE provider_id = $1 AND scim_group_id = $2;

-- name: GetSCIMGroupMappingByUserGroup :one
SELECT * FROM scim_group_mapping_projection
WHERE provider_id = $1 AND user_group_id = $2;

-- name: ListSCIMGroupMappings :many
SELECT sgm.*
FROM scim_group_mapping_projection sgm
WHERE sgm.provider_id = $1
ORDER BY sgm.scim_display_name;

-- name: CountSCIMGroupMappings :one
SELECT count(*) FROM scim_group_mapping_projection
WHERE provider_id = $1;

-- name: GetUserByExternalSCIMID :one
SELECT u.* FROM users_projection u
JOIN identity_links_projection il ON il.user_id = u.id
WHERE il.provider_id = $1 AND il.external_id = $2 AND u.is_deleted = FALSE;

-- name: ListSCIMUsers :many
SELECT u.*, il.external_id AS scim_external_id
FROM users_projection u
JOIN identity_links_projection il ON il.user_id = u.id
WHERE il.provider_id = $1 AND u.is_deleted = FALSE
ORDER BY u.created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountSCIMUsers :one
SELECT count(*) FROM users_projection u
JOIN identity_links_projection il ON il.user_id = u.id
WHERE il.provider_id = $1 AND u.is_deleted = FALSE;

-- name: FindSCIMUserByEmail :one
SELECT u.*, il.external_id AS scim_external_id
FROM users_projection u
JOIN identity_links_projection il ON il.user_id = u.id
WHERE il.provider_id = $1 AND u.email = $2 AND u.is_deleted = FALSE;

-- name: FindSCIMUserByExternalID :one
SELECT u.*, il.external_id AS scim_external_id
FROM users_projection u
JOIN identity_links_projection il ON il.user_id = u.id
WHERE il.provider_id = $1 AND il.external_id = $2 AND u.is_deleted = FALSE;

-- name: IsUserGroupSCIMManaged :one
SELECT EXISTS(
    SELECT 1 FROM scim_group_mapping_projection
    WHERE user_group_id = $1
) AS is_scim_managed;

-- name: GetUserGroupWithMembers :one
SELECT ug.*, (
    SELECT count(*) FROM user_group_members_projection ugm
    WHERE ugm.group_id = ug.id
) AS actual_member_count
FROM user_groups_projection ug
WHERE ug.id = $1 AND ug.is_deleted = FALSE;


-- name: UpsertSCIMGroupMapping :exec
-- SCIMGroupMapped handler. ON CONFLICT (provider_id, scim_group_id)
-- DO UPDATE matches the PL/pgSQL projector — re-mapping the same
-- (provider, scim_group) refreshes scim_display_name + user_group_id
-- without minting a duplicate row.
INSERT INTO scim_group_mapping_projection (
    id, provider_id, scim_group_id, scim_display_name,
    user_group_id, created_at, projection_version
) VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (provider_id, scim_group_id) DO UPDATE SET
    scim_display_name = EXCLUDED.scim_display_name,
    user_group_id = EXCLUDED.user_group_id,
    projection_version = EXCLUDED.projection_version;

-- name: DeleteSCIMGroupMappingByCompositeKey :exec
-- SCIMGroupUnmapped handler. Plain DELETE — silently no-op on a
-- miss matches the PL/pgSQL projector's behaviour under repeated
-- unmap events.
DELETE FROM scim_group_mapping_projection
WHERE provider_id = $1
  AND scim_group_id = $2;

-- name: UpdateSCIMGroupMappingDisplayName :exec
-- SCIMGroupMappingUpdated handler. Only display_name is updatable;
-- nil pointer collapses to SQL NULL, COALESCE preserves existing.
-- Stale-replay guard via projection_version.
UPDATE scim_group_mapping_projection
SET scim_display_name = COALESCE(sqlc.narg('scim_display_name')::TEXT, scim_display_name),
    projection_version = sqlc.arg('projection_version')
WHERE provider_id = sqlc.arg('provider_id')
  AND scim_group_id = sqlc.arg('scim_group_id')
  AND projection_version < sqlc.arg('projection_version');
