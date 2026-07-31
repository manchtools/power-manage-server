-- The binding between one group at one SCIM directory and one local
-- user group. (provider_id, scim_group_id) is uniquely indexed, so a
-- directory group can never be mapped to two local groups at once.

-- name: InsertSCIMGroupMapping :one
INSERT INTO scim_group_mapping (id, provider_id, scim_group_id, scim_display_name, user_group_id, created_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetSCIMGroupMapping :one
SELECT * FROM scim_group_mapping WHERE provider_id = $1 AND scim_group_id = $2;

-- name: GetSCIMGroupMappingByUserGroup :one
SELECT * FROM scim_group_mapping WHERE provider_id = $1 AND user_group_id = $2;

-- name: ListSCIMGroupMappings :many
SELECT * FROM scim_group_mapping WHERE provider_id = $1 ORDER BY id;

-- name: UpdateSCIMGroupMappingDisplayName :one
UPDATE scim_group_mapping SET scim_display_name = $3
WHERE provider_id = $1 AND scim_group_id = $2
RETURNING *;

-- name: DeleteSCIMGroupMapping :one
DELETE FROM scim_group_mapping WHERE id = $1 RETURNING *;
