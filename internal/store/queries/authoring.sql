-- Read-side inputs for compiling authored Actions, ActionSets and Definitions
-- into flat agent manifests. Deleted authoring rows never produce work.

-- name: GetManifestAction :one
SELECT * FROM actions
WHERE id = $1 AND is_deleted = FALSE;

-- name: CountActions :one
SELECT COUNT(*) FROM actions
WHERE is_deleted = FALSE AND is_system = FALSE;

-- name: InsertAuthoringAction :one
INSERT INTO actions (
    id, name, description, action_type, desired_state, params,
    params_canonical, timeout_seconds, schedule, is_system,
    created_at, created_by
) VALUES (
    sqlc.arg(id), sqlc.arg(name), NULLIF(sqlc.arg(description)::text, ''),
    sqlc.arg(action_type), sqlc.arg(desired_state), sqlc.arg(params),
    sqlc.arg(params_canonical), sqlc.arg(timeout_seconds), sqlc.narg(schedule),
    sqlc.arg(is_system), sqlc.arg(created_at), sqlc.arg(created_by)
)
RETURNING *;

-- name: RenameAuthoringAction :one
UPDATE actions
SET name = sqlc.arg(name), updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id)
  AND is_deleted = FALSE
  AND (is_system = FALSE OR sqlc.arg(allow_system)::boolean)
RETURNING *;

-- name: UpdateAuthoringActionDescription :one
UPDATE actions
SET description = NULLIF(sqlc.arg(description)::text, ''),
    updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id)
  AND is_deleted = FALSE
  AND (is_system = FALSE OR sqlc.arg(allow_system)::boolean)
RETURNING *;

-- name: UpdateAuthoringActionParams :one
UPDATE actions
SET desired_state = sqlc.arg(desired_state),
    params = sqlc.arg(params),
    params_canonical = sqlc.arg(params_canonical),
    timeout_seconds = CASE
        WHEN sqlc.arg(timeout_set)::boolean THEN sqlc.arg(timeout_seconds)::integer
        ELSE timeout_seconds
    END,
    schedule = CASE
        WHEN sqlc.arg(schedule_set)::boolean THEN sqlc.narg(schedule)::jsonb
        ELSE schedule
    END,
    updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id)
  AND is_deleted = FALSE
  AND (is_system = FALSE OR sqlc.arg(allow_system)::boolean)
RETURNING *;

-- name: DeleteActionMemberships :many
DELETE FROM action_set_members
WHERE action_id = $1
RETURNING set_id;

-- name: SoftDeleteAuthoringAction :one
UPDATE actions
SET is_deleted = TRUE, updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id)
  AND is_deleted = FALSE
  AND (is_system = FALSE OR sqlc.arg(allow_system)::boolean)
RETURNING *;

-- name: GetManifestActionSet :one
SELECT * FROM action_sets
WHERE id = $1 AND is_deleted = FALSE;

-- name: CountActionSets :one
SELECT COUNT(*) FROM action_sets
WHERE is_deleted = FALSE;

-- name: InsertAuthoringActionSet :one
INSERT INTO action_sets (
    id, name, description, schedule, on_failure, created_at, created_by
) VALUES (
    sqlc.arg(id), sqlc.arg(name), sqlc.arg(description), sqlc.arg(schedule),
    sqlc.arg(on_failure), sqlc.arg(created_at), sqlc.arg(created_by)
)
RETURNING *;

-- name: RenameAuthoringActionSet :one
UPDATE action_sets
SET name = sqlc.arg(name), updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

-- name: UpdateAuthoringActionSetDescription :one
UPDATE action_sets
SET description = sqlc.arg(description), updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

-- name: UpdateAuthoringActionSetPolicy :one
UPDATE action_sets
SET schedule = sqlc.arg(schedule),
    on_failure = sqlc.arg(on_failure),
    updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

-- name: AddAuthoringActionSetMember :one
INSERT INTO action_set_members (set_id, action_id, sort_order, added_at)
SELECT sqlc.arg(set_id), sqlc.arg(action_id), sqlc.arg(sort_order), sqlc.arg(added_at)
WHERE EXISTS (
    SELECT 1 FROM action_sets
    WHERE id = sqlc.arg(set_id) AND is_deleted = FALSE
)
AND EXISTS (
    SELECT 1 FROM actions
    WHERE id = sqlc.arg(action_id) AND is_deleted = FALSE AND is_system = FALSE
)
ON CONFLICT (set_id, action_id) DO NOTHING
RETURNING *;

-- name: RemoveAuthoringActionSetMember :one
DELETE FROM action_set_members
WHERE set_id = sqlc.arg(set_id) AND action_id = sqlc.arg(action_id)
RETURNING *;

-- name: ReorderAuthoringActionSetMember :one
UPDATE action_set_members
SET sort_order = sqlc.arg(sort_order)
WHERE set_id = sqlc.arg(set_id) AND action_id = sqlc.arg(action_id)
RETURNING *;

-- name: ListActionSetMembers :many
SELECT m.action_id, m.sort_order, a.name AS action_name, a.action_type
FROM action_set_members m
JOIN actions a ON a.id = m.action_id AND a.is_deleted = FALSE
WHERE m.set_id = $1
ORDER BY m.sort_order, m.action_id;

-- name: DeleteAuthoringActionSetMembers :many
DELETE FROM action_set_members
WHERE set_id = $1
RETURNING action_id;

-- name: DeleteDefinitionMembershipsForActionSet :many
DELETE FROM definition_members
WHERE action_set_id = $1
RETURNING definition_id;

-- name: SoftDeleteAuthoringActionSet :one
UPDATE action_sets
SET is_deleted = TRUE, updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

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
