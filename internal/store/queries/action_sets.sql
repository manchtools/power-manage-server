-- Action Sets queries

-- name: GetActionSetByID :one
SELECT * FROM action_sets_projection
WHERE id = $1 AND is_deleted = FALSE;

-- name: GetActionSetByName :one
SELECT * FROM action_sets_projection
WHERE name = $1 AND is_deleted = FALSE;

-- name: ListActionSets :many
SELECT * FROM action_sets_projection
WHERE is_deleted = FALSE
  AND (sqlc.arg(unassigned_only)::BOOLEAN = FALSE OR NOT EXISTS (
    SELECT 1 FROM definition_members_projection dm WHERE dm.action_set_id = id
  ))
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountActionSets :one
SELECT COUNT(*) FROM action_sets_projection
WHERE is_deleted = FALSE
  AND (sqlc.arg(unassigned_only)::BOOLEAN = FALSE OR NOT EXISTS (
    SELECT 1 FROM definition_members_projection dm WHERE dm.action_set_id = id
  ));

-- Action Set Members queries

-- name: ListActionSetMembers :many
SELECT m.set_id, m.action_id, m.sort_order, m.added_at, m.projection_version,
       a.name AS action_name, a.action_type
FROM action_set_members_projection m
JOIN actions_projection a ON a.id = m.action_id AND a.is_deleted = FALSE
WHERE m.set_id = $1
ORDER BY m.sort_order ASC;

-- name: GetActionSetMember :one
SELECT * FROM action_set_members_projection
WHERE set_id = $1 AND action_id = $2;

-- name: ListActionsInSet :many
SELECT a.* FROM actions_projection a
JOIN action_set_members_projection m ON a.id = m.action_id
WHERE m.set_id = $1 AND a.is_deleted = FALSE
ORDER BY m.sort_order ASC;
