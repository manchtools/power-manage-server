-- The binding between one group at one SCIM directory and one local
-- user group. (provider_id, scim_group_id) is uniquely indexed, so a
-- directory group can never be mapped to two local groups at once.

-- name: InsertSCIMGroupMapping :one
INSERT INTO scim_group_mapping (id, provider_id, scim_group_id, scim_display_name, user_group_id, created_at)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetSCIMGroupMapping :one
SELECT * FROM scim_group_mapping WHERE provider_id = ? AND scim_group_id = ?;

-- name: GetSCIMGroupMappingByUserGroup :one
SELECT * FROM scim_group_mapping WHERE provider_id = ? AND user_group_id = ?;

-- name: ListSCIMGroupMappings :many
SELECT * FROM scim_group_mapping WHERE provider_id = ? ORDER BY id;

-- name: UpdateSCIMGroupMappingDisplayName :one
UPDATE scim_group_mapping SET scim_display_name = ?
WHERE provider_id = ? AND scim_group_id = ?
RETURNING *;

-- name: DeleteSCIMGroupMapping :one
DELETE FROM scim_group_mapping WHERE id = ? RETURNING *;
