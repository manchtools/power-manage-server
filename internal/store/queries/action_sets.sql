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
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountActionSets :one
SELECT COUNT(*) FROM action_sets_projection
WHERE is_deleted = FALSE;

-- Action Set Members queries

-- name: ListActionSetMembers :many
SELECT * FROM action_set_members_projection
WHERE set_id = $1
ORDER BY sort_order ASC;

-- name: GetActionSetMember :one
SELECT * FROM action_set_members_projection
WHERE set_id = $1 AND action_id = $2;

-- name: ListActionsInSet :many
SELECT a.* FROM actions_projection a
JOIN action_set_members_projection m ON a.id = m.action_id
WHERE m.set_id = $1 AND a.is_deleted = FALSE
ORDER BY m.sort_order ASC;
