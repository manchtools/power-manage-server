-- Read-side inputs for compiling authored Actions, ActionSets and Definitions
-- into flat agent manifests. Deleted authoring rows never produce work.

-- name: GetManifestAction :one
SELECT * FROM actions
WHERE id = $1 AND is_deleted = FALSE;

-- name: ListAuthoringActions :many
WITH assignment_groups AS (
    SELECT a.source_type, a.source_id, a.target_id AS group_id
    FROM assignments a
    WHERE a.is_deleted = FALSE AND a.target_type = 'device_group'
    UNION ALL
    SELECT a.source_type, a.source_id, a.target_id
    FROM assignments a
    WHERE a.is_deleted = FALSE AND a.target_type = 'user_group'
    UNION ALL
    SELECT a.source_type, a.source_id, m.group_id
    FROM assignments a
    JOIN devices d ON d.id = a.target_id AND d.is_deleted = FALSE
    JOIN device_group_members m ON m.device_id = d.id
    JOIN device_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
    WHERE a.is_deleted = FALSE AND a.target_type = 'device'
    UNION ALL
    SELECT a.source_type, a.source_id, m.group_id
    FROM assignments a
    JOIN users u ON u.id = a.target_id AND u.is_deleted = FALSE
    JOIN user_group_members m ON m.user_id = u.id
    JOIN user_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
    WHERE a.is_deleted = FALSE AND a.target_type = 'user'
), visible_action_ids AS (
    SELECT ag.source_id AS action_id
    FROM assignment_groups ag
    WHERE ag.source_type = 'action'
      AND ag.group_id = ANY(sqlc.arg(scope_group_ids)::text[])
    UNION
    SELECT m.action_id
    FROM action_set_members m
    JOIN action_sets s ON s.id = m.set_id AND s.is_deleted = FALSE
    JOIN assignment_groups ag ON ag.source_type = 'action_set' AND ag.source_id = s.id
    WHERE ag.group_id = ANY(sqlc.arg(scope_group_ids)::text[])
    UNION
    SELECT sm.action_id
    FROM definition_members dm
    JOIN definitions d ON d.id = dm.definition_id AND d.is_deleted = FALSE
    JOIN action_sets s ON s.id = dm.action_set_id AND s.is_deleted = FALSE
    JOIN action_set_members sm ON sm.set_id = s.id
    JOIN assignment_groups ag ON ag.source_type = 'definition' AND ag.source_id = d.id
    WHERE ag.group_id = ANY(sqlc.arg(scope_group_ids)::text[])
    UNION
    SELECT r.action_id
    FROM compliance_policy_rules r
    JOIN compliance_policies p ON p.id = r.policy_id AND p.is_deleted = FALSE
    JOIN assignment_groups ag ON ag.source_type = 'compliance_policy' AND ag.source_id = p.id
    WHERE ag.group_id = ANY(sqlc.arg(scope_group_ids)::text[])
)
SELECT a.*
FROM actions a
WHERE a.is_deleted = FALSE
  AND a.is_system = FALSE
  AND a.id > sqlc.arg(after_id)
  AND (sqlc.arg(type_filter)::integer = 0 OR a.action_type = sqlc.arg(type_filter)::integer)
  AND (
      NOT sqlc.arg(unassigned_only)::boolean
      OR NOT EXISTS (
          SELECT 1 FROM assignments x
          WHERE x.source_type = 'action' AND x.source_id = a.id AND x.is_deleted = FALSE
      )
  )
  AND (
      NOT sqlc.arg(scope_restricted)::boolean
      OR EXISTS (SELECT 1 FROM visible_action_ids v WHERE v.action_id = a.id)
  )
ORDER BY a.id
LIMIT sqlc.arg(row_limit);

-- name: CountAuthoringActions :one
WITH assignment_groups AS (
    SELECT a.source_type, a.source_id, a.target_id AS group_id
    FROM assignments a
    WHERE a.is_deleted = FALSE AND a.target_type = 'device_group'
    UNION ALL
    SELECT a.source_type, a.source_id, a.target_id
    FROM assignments a
    WHERE a.is_deleted = FALSE AND a.target_type = 'user_group'
    UNION ALL
    SELECT a.source_type, a.source_id, m.group_id
    FROM assignments a
    JOIN devices d ON d.id = a.target_id AND d.is_deleted = FALSE
    JOIN device_group_members m ON m.device_id = d.id
    JOIN device_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
    WHERE a.is_deleted = FALSE AND a.target_type = 'device'
    UNION ALL
    SELECT a.source_type, a.source_id, m.group_id
    FROM assignments a
    JOIN users u ON u.id = a.target_id AND u.is_deleted = FALSE
    JOIN user_group_members m ON m.user_id = u.id
    JOIN user_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
    WHERE a.is_deleted = FALSE AND a.target_type = 'user'
), visible_action_ids AS (
    SELECT ag.source_id AS action_id
    FROM assignment_groups ag
    WHERE ag.source_type = 'action'
      AND ag.group_id = ANY(sqlc.arg(scope_group_ids)::text[])
    UNION
    SELECT m.action_id
    FROM action_set_members m
    JOIN action_sets s ON s.id = m.set_id AND s.is_deleted = FALSE
    JOIN assignment_groups ag ON ag.source_type = 'action_set' AND ag.source_id = s.id
    WHERE ag.group_id = ANY(sqlc.arg(scope_group_ids)::text[])
    UNION
    SELECT sm.action_id
    FROM definition_members dm
    JOIN definitions d ON d.id = dm.definition_id AND d.is_deleted = FALSE
    JOIN action_sets s ON s.id = dm.action_set_id AND s.is_deleted = FALSE
    JOIN action_set_members sm ON sm.set_id = s.id
    JOIN assignment_groups ag ON ag.source_type = 'definition' AND ag.source_id = d.id
    WHERE ag.group_id = ANY(sqlc.arg(scope_group_ids)::text[])
    UNION
    SELECT r.action_id
    FROM compliance_policy_rules r
    JOIN compliance_policies p ON p.id = r.policy_id AND p.is_deleted = FALSE
    JOIN assignment_groups ag ON ag.source_type = 'compliance_policy' AND ag.source_id = p.id
    WHERE ag.group_id = ANY(sqlc.arg(scope_group_ids)::text[])
)
SELECT COUNT(*)
FROM actions a
WHERE a.is_deleted = FALSE
  AND a.is_system = FALSE
  AND (sqlc.arg(type_filter)::integer = 0 OR a.action_type = sqlc.arg(type_filter)::integer)
  AND (
      NOT sqlc.arg(unassigned_only)::boolean
      OR NOT EXISTS (
          SELECT 1 FROM assignments x
          WHERE x.source_type = 'action' AND x.source_id = a.id AND x.is_deleted = FALSE
      )
  )
  AND (
      NOT sqlc.arg(scope_restricted)::boolean
      OR EXISTS (SELECT 1 FROM visible_action_ids v WHERE v.action_id = a.id)
  );

-- name: ListAuthoringAssignmentsForSource :many
SELECT target_type, target_id
FROM assignments
WHERE source_type = sqlc.arg(source_type)
  AND source_id = sqlc.arg(source_id)
  AND is_deleted = FALSE
ORDER BY target_type, target_id;

-- name: ListContainingActionSetIDs :many
SELECT m.set_id
FROM action_set_members m
JOIN action_sets s ON s.id = m.set_id AND s.is_deleted = FALSE
WHERE m.action_id = $1
ORDER BY m.set_id;

-- name: ListContainingDefinitionIDs :many
SELECT m.definition_id
FROM definition_members m
JOIN definitions d ON d.id = m.definition_id AND d.is_deleted = FALSE
WHERE m.action_set_id = $1
ORDER BY m.definition_id;

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

-- name: ListAuthoringActionSets :many
WITH assignment_groups AS (
    SELECT a.source_type, a.source_id, a.target_id AS group_id
    FROM assignments a
    WHERE a.is_deleted = FALSE AND a.target_type = 'device_group'
    UNION ALL
    SELECT a.source_type, a.source_id, a.target_id
    FROM assignments a
    WHERE a.is_deleted = FALSE AND a.target_type = 'user_group'
    UNION ALL
    SELECT a.source_type, a.source_id, m.group_id
    FROM assignments a
    JOIN devices d ON d.id = a.target_id AND d.is_deleted = FALSE
    JOIN device_group_members m ON m.device_id = d.id
    JOIN device_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
    WHERE a.is_deleted = FALSE AND a.target_type = 'device'
    UNION ALL
    SELECT a.source_type, a.source_id, m.group_id
    FROM assignments a
    JOIN users u ON u.id = a.target_id AND u.is_deleted = FALSE
    JOIN user_group_members m ON m.user_id = u.id
    JOIN user_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
    WHERE a.is_deleted = FALSE AND a.target_type = 'user'
), visible_set_ids AS (
    SELECT ag.source_id AS set_id
    FROM assignment_groups ag
    WHERE ag.source_type = 'action_set'
      AND ag.group_id = ANY(sqlc.arg(scope_group_ids)::text[])
    UNION
    SELECT m.action_set_id
    FROM definition_members m
    JOIN definitions d ON d.id = m.definition_id AND d.is_deleted = FALSE
    JOIN assignment_groups ag ON ag.source_type = 'definition' AND ag.source_id = d.id
    WHERE ag.group_id = ANY(sqlc.arg(scope_group_ids)::text[])
)
SELECT s.*,
       (
           SELECT COUNT(*)
           FROM action_set_members m
           JOIN actions a ON a.id = m.action_id AND a.is_deleted = FALSE
           WHERE m.set_id = s.id
       ) AS member_count
FROM action_sets s
WHERE s.is_deleted = FALSE
  AND s.id > sqlc.arg(after_id)
  AND (
      NOT sqlc.arg(unassigned_only)::boolean
      OR NOT EXISTS (
          SELECT 1 FROM assignments x
          WHERE x.source_type = 'action_set' AND x.source_id = s.id AND x.is_deleted = FALSE
      )
  )
  AND (
      NOT sqlc.arg(scope_restricted)::boolean
      OR EXISTS (SELECT 1 FROM visible_set_ids v WHERE v.set_id = s.id)
  )
ORDER BY s.id
LIMIT sqlc.arg(row_limit);

-- name: CountAuthoringActionSets :one
WITH assignment_groups AS (
    SELECT a.source_type, a.source_id, a.target_id AS group_id
    FROM assignments a
    WHERE a.is_deleted = FALSE AND a.target_type = 'device_group'
    UNION ALL
    SELECT a.source_type, a.source_id, a.target_id
    FROM assignments a
    WHERE a.is_deleted = FALSE AND a.target_type = 'user_group'
    UNION ALL
    SELECT a.source_type, a.source_id, m.group_id
    FROM assignments a
    JOIN devices d ON d.id = a.target_id AND d.is_deleted = FALSE
    JOIN device_group_members m ON m.device_id = d.id
    JOIN device_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
    WHERE a.is_deleted = FALSE AND a.target_type = 'device'
    UNION ALL
    SELECT a.source_type, a.source_id, m.group_id
    FROM assignments a
    JOIN users u ON u.id = a.target_id AND u.is_deleted = FALSE
    JOIN user_group_members m ON m.user_id = u.id
    JOIN user_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
    WHERE a.is_deleted = FALSE AND a.target_type = 'user'
), visible_set_ids AS (
    SELECT ag.source_id AS set_id
    FROM assignment_groups ag
    WHERE ag.source_type = 'action_set'
      AND ag.group_id = ANY(sqlc.arg(scope_group_ids)::text[])
    UNION
    SELECT m.action_set_id
    FROM definition_members m
    JOIN definitions d ON d.id = m.definition_id AND d.is_deleted = FALSE
    JOIN assignment_groups ag ON ag.source_type = 'definition' AND ag.source_id = d.id
    WHERE ag.group_id = ANY(sqlc.arg(scope_group_ids)::text[])
)
SELECT COUNT(*)
FROM action_sets s
WHERE s.is_deleted = FALSE
  AND (
      NOT sqlc.arg(unassigned_only)::boolean
      OR NOT EXISTS (
          SELECT 1 FROM assignments x
          WHERE x.source_type = 'action_set' AND x.source_id = s.id AND x.is_deleted = FALSE
      )
  )
  AND (
      NOT sqlc.arg(scope_restricted)::boolean
      OR EXISTS (SELECT 1 FROM visible_set_ids v WHERE v.set_id = s.id)
  );

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

-- name: ListAuthoringDefinitions :many
WITH assignment_groups AS (
    SELECT a.source_type, a.source_id, a.target_id AS group_id
    FROM assignments a
    WHERE a.is_deleted = FALSE AND a.target_type = 'device_group'
    UNION ALL
    SELECT a.source_type, a.source_id, a.target_id
    FROM assignments a
    WHERE a.is_deleted = FALSE AND a.target_type = 'user_group'
    UNION ALL
    SELECT a.source_type, a.source_id, m.group_id
    FROM assignments a
    JOIN devices d ON d.id = a.target_id AND d.is_deleted = FALSE
    JOIN device_group_members m ON m.device_id = d.id
    JOIN device_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
    WHERE a.is_deleted = FALSE AND a.target_type = 'device'
    UNION ALL
    SELECT a.source_type, a.source_id, m.group_id
    FROM assignments a
    JOIN users u ON u.id = a.target_id AND u.is_deleted = FALSE
    JOIN user_group_members m ON m.user_id = u.id
    JOIN user_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
    WHERE a.is_deleted = FALSE AND a.target_type = 'user'
)
SELECT d.id, d.name, d.description, d.schedule, d.created_at, d.created_by,
       d.updated_at, d.is_deleted, d.search_tsv,
       (
           SELECT COUNT(*)
           FROM definition_members m
           JOIN action_sets s ON s.id = m.action_set_id AND s.is_deleted = FALSE
           WHERE m.definition_id = d.id
       ) AS member_count
FROM definitions d
WHERE d.is_deleted = FALSE
  AND d.id > sqlc.arg(after_id)
  AND (
      NOT sqlc.arg(scope_restricted)::boolean
      OR EXISTS (
          SELECT 1 FROM assignment_groups ag
          WHERE ag.source_type = 'definition'
            AND ag.source_id = d.id
            AND ag.group_id = ANY(sqlc.arg(scope_group_ids)::text[])
      )
  )
ORDER BY d.id
LIMIT sqlc.arg(row_limit);

-- name: CountAuthoringDefinitions :one
WITH assignment_groups AS (
    SELECT a.source_type, a.source_id, a.target_id AS group_id
    FROM assignments a
    WHERE a.is_deleted = FALSE AND a.target_type = 'device_group'
    UNION ALL
    SELECT a.source_type, a.source_id, a.target_id
    FROM assignments a
    WHERE a.is_deleted = FALSE AND a.target_type = 'user_group'
    UNION ALL
    SELECT a.source_type, a.source_id, m.group_id
    FROM assignments a
    JOIN devices d ON d.id = a.target_id AND d.is_deleted = FALSE
    JOIN device_group_members m ON m.device_id = d.id
    JOIN device_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
    WHERE a.is_deleted = FALSE AND a.target_type = 'device'
    UNION ALL
    SELECT a.source_type, a.source_id, m.group_id
    FROM assignments a
    JOIN users u ON u.id = a.target_id AND u.is_deleted = FALSE
    JOIN user_group_members m ON m.user_id = u.id
    JOIN user_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
    WHERE a.is_deleted = FALSE AND a.target_type = 'user'
)
SELECT COUNT(*)
FROM definitions d
WHERE d.is_deleted = FALSE
  AND (
      NOT sqlc.arg(scope_restricted)::boolean
      OR EXISTS (
          SELECT 1 FROM assignment_groups ag
          WHERE ag.source_type = 'definition'
            AND ag.source_id = d.id
            AND ag.group_id = ANY(sqlc.arg(scope_group_ids)::text[])
      )
  );

-- name: InsertAuthoringDefinition :one
INSERT INTO definitions (
    id, name, description, schedule, created_at, created_by
) VALUES (
    sqlc.arg(id), sqlc.arg(name), sqlc.arg(description), sqlc.arg(schedule),
    sqlc.arg(created_at), sqlc.arg(created_by)
)
RETURNING *;

-- name: RenameAuthoringDefinition :one
UPDATE definitions
SET name = sqlc.arg(name), updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

-- name: UpdateAuthoringDefinitionDescription :one
UPDATE definitions
SET description = sqlc.arg(description), updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

-- name: UpdateAuthoringDefinitionSchedule :one
UPDATE definitions
SET schedule = sqlc.arg(schedule), updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

-- name: AddAuthoringDefinitionMember :one
INSERT INTO definition_members (definition_id, action_set_id, sort_order, added_at)
SELECT sqlc.arg(definition_id), sqlc.arg(action_set_id), sqlc.arg(sort_order), sqlc.arg(added_at)
WHERE EXISTS (
    SELECT 1 FROM definitions
    WHERE id = sqlc.arg(definition_id) AND is_deleted = FALSE
)
AND EXISTS (
    SELECT 1 FROM action_sets
    WHERE id = sqlc.arg(action_set_id) AND is_deleted = FALSE
)
ON CONFLICT (definition_id, action_set_id) DO NOTHING
RETURNING *;

-- name: RemoveAuthoringDefinitionMember :one
DELETE FROM definition_members
WHERE definition_id = sqlc.arg(definition_id) AND action_set_id = sqlc.arg(action_set_id)
RETURNING *;

-- name: ReorderAuthoringDefinitionMember :one
UPDATE definition_members
SET sort_order = sqlc.arg(sort_order)
WHERE definition_id = sqlc.arg(definition_id) AND action_set_id = sqlc.arg(action_set_id)
RETURNING *;

-- name: ListDefinitionMembers :many
SELECT m.action_set_id, m.sort_order, s.name AS action_set_name
FROM definition_members m
JOIN action_sets s ON s.id = m.action_set_id AND s.is_deleted = FALSE
WHERE m.definition_id = $1
ORDER BY m.sort_order, m.action_set_id;

-- name: DeleteAuthoringDefinitionMembers :many
DELETE FROM definition_members
WHERE definition_id = $1
RETURNING action_set_id;

-- name: SoftDeleteAuthoringDefinition :one
UPDATE definitions
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
