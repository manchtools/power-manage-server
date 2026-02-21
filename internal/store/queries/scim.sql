-- name: GetIdentityProviderBySlugForSCIM :one
SELECT * FROM identity_providers_projection
WHERE slug = $1 AND is_deleted = FALSE AND scim_enabled = TRUE;

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

-- name: GetUserGroupWithMembers :one
SELECT ug.*, (
    SELECT count(*) FROM user_group_members_projection ugm
    WHERE ugm.group_id = ug.id
) AS actual_member_count
FROM user_groups_projection ug
WHERE ug.id = $1 AND ug.is_deleted = FALSE;

