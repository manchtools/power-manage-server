-- Definitions queries (collection of action sets)

-- name: GetDefinitionByID :one
SELECT * FROM definitions_projection
WHERE id = $1 AND is_deleted = FALSE;

-- name: GetDefinitionByName :one
SELECT * FROM definitions_projection
WHERE name = $1 AND is_deleted = FALSE;

-- name: ListDefinitions :many
SELECT * FROM definitions_projection
WHERE is_deleted = FALSE
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountDefinitions :one
SELECT COUNT(*) FROM definitions_projection
WHERE is_deleted = FALSE;

-- Definition Members queries

-- name: ListDefinitionMembers :many
SELECT * FROM definition_members_projection
WHERE definition_id = $1
ORDER BY sort_order ASC;

-- name: GetDefinitionMember :one
SELECT * FROM definition_members_projection
WHERE definition_id = $1 AND action_set_id = $2;

-- name: ListActionSetsInDefinition :many
SELECT s.* FROM action_sets_projection s
JOIN definition_members_projection m ON s.id = m.action_set_id
WHERE m.definition_id = $1 AND s.is_deleted = FALSE
ORDER BY m.sort_order ASC;
