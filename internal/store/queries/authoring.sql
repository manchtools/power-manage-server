-- Read-side inputs for compiling authored Actions, ActionSets and Definitions
-- into flat agent manifests. Deleted authoring rows never produce work.

-- name: GetManifestAction :one
SELECT * FROM actions
WHERE id = $1 AND is_deleted = FALSE;

-- name: GetManifestActionSet :one
SELECT * FROM action_sets
WHERE id = $1 AND is_deleted = FALSE;

-- name: ListManifestActionSetActions :many
SELECT a.*
FROM action_set_members m
JOIN actions a ON a.id = m.action_id AND a.is_deleted = FALSE
WHERE m.set_id = $1
ORDER BY m.sort_order, a.id;

-- name: GetManifestDefinition :one
SELECT * FROM definitions
WHERE id = $1 AND is_deleted = FALSE;

-- name: ListManifestDefinitionActionSets :many
SELECT s.*
FROM definition_members m
JOIN action_sets s ON s.id = m.action_set_id AND s.is_deleted = FALSE
WHERE m.definition_id = $1
ORDER BY m.sort_order, s.id;

-- name: ListManifestDefinitionActions :many
SELECT m.action_set_id, a.*
FROM definition_members m
JOIN action_sets s ON s.id = m.action_set_id AND s.is_deleted = FALSE
JOIN action_set_members sm ON sm.set_id = s.id
JOIN actions a ON a.id = sm.action_id AND a.is_deleted = FALSE
WHERE m.definition_id = $1
ORDER BY m.sort_order, s.id, sm.sort_order, a.id;
