-- Assignments queries

-- name: GetAssignmentByID :one
SELECT * FROM assignments_projection
WHERE id = $1 AND is_deleted = FALSE;

-- name: GetAssignment :one
SELECT * FROM assignments_projection
WHERE source_type = $1 AND source_id = $2 AND target_type = $3 AND target_id = $4 AND is_deleted = FALSE;

-- name: ListAssignments :many
SELECT * FROM assignments_projection
WHERE is_deleted = FALSE
  AND ($1::TEXT = '' OR source_type = $1)
  AND ($2::TEXT = '' OR source_id = $2)
  AND ($3::TEXT = '' OR target_type = $3)
  AND ($4::TEXT = '' OR target_id = $4)
ORDER BY created_at DESC
LIMIT $5 OFFSET $6;

-- name: CountAssignments :one
SELECT COUNT(*) FROM assignments_projection
WHERE is_deleted = FALSE
  AND ($1::TEXT = '' OR source_type = $1)
  AND ($2::TEXT = '' OR source_id = $2)
  AND ($3::TEXT = '' OR target_type = $3)
  AND ($4::TEXT = '' OR target_id = $4);

-- Get all assignments for a specific source
-- name: ListAssignmentsForSource :many
SELECT * FROM assignments_projection
WHERE source_type = $1 AND source_id = $2 AND is_deleted = FALSE
ORDER BY created_at DESC;

-- Get all assignments for a specific target
-- name: ListAssignmentsForTarget :many
SELECT * FROM assignments_projection
WHERE target_type = $1 AND target_id = $2 AND is_deleted = FALSE
ORDER BY created_at DESC;

-- Get all direct assignments for a device (not including group memberships)
-- name: ListDirectAssignmentsForDevice :many
SELECT * FROM assignments_projection
WHERE target_type = 'device' AND target_id = $1 AND is_deleted = FALSE
ORDER BY created_at DESC;

-- Get all assignments for device groups the device belongs to
-- name: ListGroupAssignmentsForDevice :many
SELECT a.* FROM assignments_projection a
JOIN device_group_members_projection m ON a.target_id = m.group_id
WHERE a.target_type = 'device_group'
  AND m.device_id = $1
  AND a.is_deleted = FALSE
ORDER BY a.created_at DESC;

-- Get all actions assigned to a device (directly or via groups) with proper ordering
-- Actions are ordered by: assignment_sort_order, definition_sort_order, action_set_sort_order, action_sort_order
-- This ensures actions from definitions run in the correct sequence
-- name: ListAssignedActionsForDevice :many
WITH assigned_actions AS (
  -- Direct action assignments (no hierarchy, use assignment sort_order only)
  SELECT
    a.*,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    0 as definition_sort,
    0 as action_set_sort,
    0 as action_sort
  FROM actions_projection a
  JOIN assignments_projection asn ON asn.source_type = 'action' AND asn.source_id = a.id
  WHERE asn.target_type = 'device' AND asn.target_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Action assignments via device group
  SELECT
    a.*,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    0 as definition_sort,
    0 as action_set_sort,
    0 as action_sort
  FROM actions_projection a
  JOIN assignments_projection asn ON asn.source_type = 'action' AND asn.source_id = a.id
  JOIN device_group_members_projection m ON asn.target_id = m.group_id
  WHERE asn.target_type = 'device_group' AND m.device_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Actions via action set assignments (direct to device)
  SELECT
    a.*,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    0 as definition_sort,
    COALESCE(sm.sort_order, 0) as action_set_sort,
    COALESCE(sm.sort_order, 0) as action_sort
  FROM actions_projection a
  JOIN action_set_members_projection sm ON sm.action_id = a.id
  JOIN assignments_projection asn ON asn.source_type = 'action_set' AND asn.source_id = sm.set_id
  WHERE asn.target_type = 'device' AND asn.target_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Actions via action set assignments (via device group)
  SELECT
    a.*,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    0 as definition_sort,
    COALESCE(sm.sort_order, 0) as action_set_sort,
    COALESCE(sm.sort_order, 0) as action_sort
  FROM actions_projection a
  JOIN action_set_members_projection sm ON sm.action_id = a.id
  JOIN assignments_projection asn ON asn.source_type = 'action_set' AND asn.source_id = sm.set_id
  JOIN device_group_members_projection m ON asn.target_id = m.group_id
  WHERE asn.target_type = 'device_group' AND m.device_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Actions via definition assignments (direct to device)
  SELECT
    a.*,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    COALESCE(dm.sort_order, 0) as definition_sort,
    COALESCE(sm.sort_order, 0) as action_set_sort,
    COALESCE(sm.sort_order, 0) as action_sort
  FROM actions_projection a
  JOIN action_set_members_projection sm ON sm.action_id = a.id
  JOIN definition_members_projection dm ON dm.action_set_id = sm.set_id
  JOIN assignments_projection asn ON asn.source_type = 'definition' AND asn.source_id = dm.definition_id
  WHERE asn.target_type = 'device' AND asn.target_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Actions via definition assignments (via device group)
  SELECT
    a.*,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    COALESCE(dm.sort_order, 0) as definition_sort,
    COALESCE(sm.sort_order, 0) as action_set_sort,
    COALESCE(sm.sort_order, 0) as action_sort
  FROM actions_projection a
  JOIN action_set_members_projection sm ON sm.action_id = a.id
  JOIN definition_members_projection dm ON dm.action_set_id = sm.set_id
  JOIN assignments_projection asn ON asn.source_type = 'definition' AND asn.source_id = dm.definition_id
  JOIN device_group_members_projection m ON asn.target_id = m.group_id
  WHERE asn.target_type = 'device_group' AND m.device_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE
),
-- First deduplicate by taking the lowest sort order for each action
deduped AS (
  SELECT DISTINCT ON (id)
    id, name, description, action_type, desired_state, params, timeout_seconds,
    created_at, created_by, is_deleted, projection_version, signature, params_canonical,
    assignment_sort, definition_sort, action_set_sort, action_sort
  FROM assigned_actions
  ORDER BY id, assignment_sort, definition_sort, action_set_sort, action_sort
)
-- Then return in the correct execution order
SELECT id, name, description, action_type, desired_state, params, timeout_seconds,
       created_at, created_by, is_deleted, projection_version, signature, params_canonical
FROM deduped
ORDER BY assignment_sort, definition_sort, action_set_sort, action_sort, id;

-- Get all resolved actions for a device with conflict resolution.
-- This is used by the agent sync to determine what actions to apply.
-- Conflict resolution: excluded (2) > required (0) > available+selected > available+rejected > unselected (skip)
-- name: ListResolvedActionsForDevice :many
-- Resolution priority: action > action_set > definition
-- Within each level: excluded > required > available
WITH all_assignments AS (
  -- Direct action assignments (source_priority = 1, highest)
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical,
    asn.mode,
    asn.source_type AS asn_source_type,
    asn.source_id AS asn_source_id,
    1 AS source_priority,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    0 as definition_sort,
    0 as action_set_sort,
    0 as action_sort
  FROM actions_projection a
  JOIN assignments_projection asn ON asn.source_type = 'action' AND asn.source_id = a.id
  WHERE asn.target_type = 'device' AND asn.target_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Action assignments via device group (source_priority = 1, highest)
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical,
    asn.mode,
    asn.source_type AS asn_source_type,
    asn.source_id AS asn_source_id,
    1 AS source_priority,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    0 as definition_sort,
    0 as action_set_sort,
    0 as action_sort
  FROM actions_projection a
  JOIN assignments_projection asn ON asn.source_type = 'action' AND asn.source_id = a.id
  JOIN device_group_members_projection m ON asn.target_id = m.group_id
  WHERE asn.target_type = 'device_group' AND m.device_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Actions via action set assignments (direct to device, source_priority = 2)
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical,
    asn.mode,
    asn.source_type AS asn_source_type,
    asn.source_id AS asn_source_id,
    2 AS source_priority,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    0 as definition_sort,
    COALESCE(sm.sort_order, 0) as action_set_sort,
    COALESCE(sm.sort_order, 0) as action_sort
  FROM actions_projection a
  JOIN action_set_members_projection sm ON sm.action_id = a.id
  JOIN assignments_projection asn ON asn.source_type = 'action_set' AND asn.source_id = sm.set_id
  WHERE asn.target_type = 'device' AND asn.target_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Actions via action set assignments (via device group, source_priority = 2)
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical,
    asn.mode,
    asn.source_type AS asn_source_type,
    asn.source_id AS asn_source_id,
    2 AS source_priority,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    0 as definition_sort,
    COALESCE(sm.sort_order, 0) as action_set_sort,
    COALESCE(sm.sort_order, 0) as action_sort
  FROM actions_projection a
  JOIN action_set_members_projection sm ON sm.action_id = a.id
  JOIN assignments_projection asn ON asn.source_type = 'action_set' AND asn.source_id = sm.set_id
  JOIN device_group_members_projection m ON asn.target_id = m.group_id
  WHERE asn.target_type = 'device_group' AND m.device_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Actions via definition assignments (direct to device, source_priority = 3, lowest)
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical,
    asn.mode,
    asn.source_type AS asn_source_type,
    asn.source_id AS asn_source_id,
    3 AS source_priority,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    COALESCE(dm.sort_order, 0) as definition_sort,
    COALESCE(sm.sort_order, 0) as action_set_sort,
    COALESCE(sm.sort_order, 0) as action_sort
  FROM actions_projection a
  JOIN action_set_members_projection sm ON sm.action_id = a.id
  JOIN definition_members_projection dm ON dm.action_set_id = sm.set_id
  JOIN assignments_projection asn ON asn.source_type = 'definition' AND asn.source_id = dm.definition_id
  WHERE asn.target_type = 'device' AND asn.target_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Actions via definition assignments (via device group, source_priority = 3, lowest)
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical,
    asn.mode,
    asn.source_type AS asn_source_type,
    asn.source_id AS asn_source_id,
    3 AS source_priority,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    COALESCE(dm.sort_order, 0) as definition_sort,
    COALESCE(sm.sort_order, 0) as action_set_sort,
    COALESCE(sm.sort_order, 0) as action_sort
  FROM actions_projection a
  JOIN action_set_members_projection sm ON sm.action_id = a.id
  JOIN definition_members_projection dm ON dm.action_set_id = sm.set_id
  JOIN assignments_projection asn ON asn.source_type = 'definition' AND asn.source_id = dm.definition_id
  JOIN device_group_members_projection m ON asn.target_id = m.group_id
  WHERE asn.target_type = 'device_group' AND m.device_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE
),
-- Join with user selections for available assignments
with_selections AS (
  SELECT aa.*,
    CASE WHEN aa.mode = 1 THEN us.selected ELSE NULL END AS user_selected
  FROM all_assignments aa
  LEFT JOIN user_selections_projection us
    ON us.device_id = $1
    AND us.source_type = aa.asn_source_type
    AND us.source_id = aa.asn_source_id
),
-- Find the highest priority source level for each action
priority_per_action AS (
  SELECT id, MIN(source_priority) AS min_priority
  FROM with_selections
  GROUP BY id
),
-- Filter to only keep assignments at the highest priority level for each action
filtered AS (
  SELECT ws.*
  FROM with_selections ws
  JOIN priority_per_action ppa ON ws.id = ppa.id AND ws.source_priority = ppa.min_priority
),
-- Resolve conflicts per action at the winning priority level: excluded > required > available
effective AS (
  SELECT
    id, name, description, action_type, desired_state, params, timeout_seconds,
    created_at, created_by, is_deleted, projection_version,
    signature, params_canonical,
    CASE
      WHEN bool_or(mode = 2) THEN -1                           -- excluded: don't apply this action
      WHEN bool_or(mode = 0) THEN 0                            -- required: apply
      WHEN bool_or(mode = 1 AND user_selected = TRUE) THEN 0   -- available+selected → apply
      WHEN bool_or(mode = 1 AND user_selected = FALSE) THEN -1 -- available+rejected → skip
      ELSE -1                                                    -- unselected available → skip
    END AS effective_mode,
    MIN(assignment_sort) AS assignment_sort,
    MIN(definition_sort) AS definition_sort,
    MIN(action_set_sort) AS action_set_sort,
    MIN(action_sort) AS action_sort
  FROM filtered
  GROUP BY id, name, description, action_type, desired_state, params, timeout_seconds,
           created_at, created_by, is_deleted, projection_version,
           signature, params_canonical
)
-- Return actions that should be applied, using action's stored desired_state
SELECT id, name, description, action_type, desired_state,
  params, timeout_seconds, created_at, created_by, is_deleted,
  projection_version, signature, params_canonical
FROM effective
WHERE effective_mode >= 0
ORDER BY assignment_sort, definition_sort, action_set_sort, action_sort, id;

-- Get action IDs that are EXCLUDED at the device/device_group layer.
-- Used by the resolution merge to block these actions from the user layer.
-- name: ListDeviceLayerExcludedActionIDs :many
WITH dev_assignments AS (
  SELECT a.id AS action_id, asn.mode, 1 AS source_priority
  FROM actions_projection a
  JOIN assignments_projection asn ON asn.source_type = 'action' AND asn.source_id = a.id
  WHERE asn.target_type = 'device' AND asn.target_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  SELECT a.id AS action_id, asn.mode, 1 AS source_priority
  FROM actions_projection a
  JOIN assignments_projection asn ON asn.source_type = 'action' AND asn.source_id = a.id
  JOIN device_group_members_projection m ON asn.target_id = m.group_id
  WHERE asn.target_type = 'device_group' AND m.device_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  SELECT a.id AS action_id, asn.mode, 2 AS source_priority
  FROM actions_projection a
  JOIN action_set_members_projection sm ON sm.action_id = a.id
  JOIN assignments_projection asn ON asn.source_type = 'action_set' AND asn.source_id = sm.set_id
  WHERE asn.target_type = 'device' AND asn.target_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  SELECT a.id AS action_id, asn.mode, 2 AS source_priority
  FROM actions_projection a
  JOIN action_set_members_projection sm ON sm.action_id = a.id
  JOIN assignments_projection asn ON asn.source_type = 'action_set' AND asn.source_id = sm.set_id
  JOIN device_group_members_projection m ON asn.target_id = m.group_id
  WHERE asn.target_type = 'device_group' AND m.device_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  SELECT a.id AS action_id, asn.mode, 3 AS source_priority
  FROM actions_projection a
  JOIN action_set_members_projection sm ON sm.action_id = a.id
  JOIN definition_members_projection dm ON dm.action_set_id = sm.set_id
  JOIN assignments_projection asn ON asn.source_type = 'definition' AND asn.source_id = dm.definition_id
  WHERE asn.target_type = 'device' AND asn.target_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  SELECT a.id AS action_id, asn.mode, 3 AS source_priority
  FROM actions_projection a
  JOIN action_set_members_projection sm ON sm.action_id = a.id
  JOIN definition_members_projection dm ON dm.action_set_id = sm.set_id
  JOIN assignments_projection asn ON asn.source_type = 'definition' AND asn.source_id = dm.definition_id
  JOIN device_group_members_projection m ON asn.target_id = m.group_id
  WHERE asn.target_type = 'device_group' AND m.device_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE
),
dev_priority AS (
  SELECT action_id, MIN(source_priority) AS min_priority
  FROM dev_assignments
  GROUP BY action_id
),
dev_filtered AS (
  SELECT da.action_id, da.mode
  FROM dev_assignments da
  JOIN dev_priority dp ON da.action_id = dp.action_id AND da.source_priority = dp.min_priority
)
SELECT action_id AS id FROM dev_filtered
GROUP BY action_id
HAVING bool_or(mode = 2);

-- Get all resolved actions from user/user_group layer for a device.
-- Looks up the device's assigned_user_id, then finds assignments targeting
-- that user or any of the user's groups. Same resolution logic as device layer.
-- name: ListUserLayerResolvedActionsForDevice :many
WITH device_owner AS (
  SELECT d.assigned_user_id FROM devices_projection d
  WHERE d.id = $1 AND d.is_deleted = FALSE AND d.assigned_user_id IS NOT NULL
),
owner_groups AS (
  SELECT ugm.group_id FROM user_group_members_projection ugm
  JOIN user_groups_projection ug ON ug.id = ugm.group_id AND ug.is_deleted = FALSE
  WHERE ugm.user_id = (SELECT assigned_user_id FROM device_owner)
),
all_assignments AS (
  -- Direct action → user (source_priority = 1)
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical,
    asn.mode,
    asn.source_type AS asn_source_type,
    asn.source_id AS asn_source_id,
    1 AS source_priority,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    0 as definition_sort,
    0 as action_set_sort,
    0 as action_sort
  FROM actions_projection a
  JOIN assignments_projection asn ON asn.source_type = 'action' AND asn.source_id = a.id
  WHERE asn.target_type = 'user' AND asn.target_id = (SELECT assigned_user_id FROM device_owner)
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Direct action → user_group (source_priority = 1)
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical,
    asn.mode,
    asn.source_type AS asn_source_type,
    asn.source_id AS asn_source_id,
    1 AS source_priority,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    0 as definition_sort,
    0 as action_set_sort,
    0 as action_sort
  FROM actions_projection a
  JOIN assignments_projection asn ON asn.source_type = 'action' AND asn.source_id = a.id
  WHERE asn.target_type = 'user_group' AND asn.target_id IN (SELECT group_id FROM owner_groups)
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Action set → user (source_priority = 2)
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical,
    asn.mode,
    asn.source_type AS asn_source_type,
    asn.source_id AS asn_source_id,
    2 AS source_priority,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    0 as definition_sort,
    COALESCE(sm.sort_order, 0) as action_set_sort,
    COALESCE(sm.sort_order, 0) as action_sort
  FROM actions_projection a
  JOIN action_set_members_projection sm ON sm.action_id = a.id
  JOIN assignments_projection asn ON asn.source_type = 'action_set' AND asn.source_id = sm.set_id
  WHERE asn.target_type = 'user' AND asn.target_id = (SELECT assigned_user_id FROM device_owner)
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Action set → user_group (source_priority = 2)
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical,
    asn.mode,
    asn.source_type AS asn_source_type,
    asn.source_id AS asn_source_id,
    2 AS source_priority,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    0 as definition_sort,
    COALESCE(sm.sort_order, 0) as action_set_sort,
    COALESCE(sm.sort_order, 0) as action_sort
  FROM actions_projection a
  JOIN action_set_members_projection sm ON sm.action_id = a.id
  JOIN assignments_projection asn ON asn.source_type = 'action_set' AND asn.source_id = sm.set_id
  WHERE asn.target_type = 'user_group' AND asn.target_id IN (SELECT group_id FROM owner_groups)
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Definition → user (source_priority = 3)
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical,
    asn.mode,
    asn.source_type AS asn_source_type,
    asn.source_id AS asn_source_id,
    3 AS source_priority,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    COALESCE(dm.sort_order, 0) as definition_sort,
    COALESCE(sm.sort_order, 0) as action_set_sort,
    COALESCE(sm.sort_order, 0) as action_sort
  FROM actions_projection a
  JOIN action_set_members_projection sm ON sm.action_id = a.id
  JOIN definition_members_projection dm ON dm.action_set_id = sm.set_id
  JOIN assignments_projection asn ON asn.source_type = 'definition' AND asn.source_id = dm.definition_id
  WHERE asn.target_type = 'user' AND asn.target_id = (SELECT assigned_user_id FROM device_owner)
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Definition → user_group (source_priority = 3)
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical,
    asn.mode,
    asn.source_type AS asn_source_type,
    asn.source_id AS asn_source_id,
    3 AS source_priority,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    COALESCE(dm.sort_order, 0) as definition_sort,
    COALESCE(sm.sort_order, 0) as action_set_sort,
    COALESCE(sm.sort_order, 0) as action_sort
  FROM actions_projection a
  JOIN action_set_members_projection sm ON sm.action_id = a.id
  JOIN definition_members_projection dm ON dm.action_set_id = sm.set_id
  JOIN assignments_projection asn ON asn.source_type = 'definition' AND asn.source_id = dm.definition_id
  WHERE asn.target_type = 'user_group' AND asn.target_id IN (SELECT group_id FROM owner_groups)
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE
),
with_selections AS (
  SELECT aa.*,
    CASE WHEN aa.mode = 1 THEN us.selected ELSE NULL END AS user_selected
  FROM all_assignments aa
  LEFT JOIN user_selections_projection us
    ON us.device_id = $1
    AND us.source_type = aa.asn_source_type
    AND us.source_id = aa.asn_source_id
),
priority_per_action AS (
  SELECT id, MIN(source_priority) AS min_priority
  FROM with_selections
  GROUP BY id
),
filtered AS (
  SELECT ws.*
  FROM with_selections ws
  JOIN priority_per_action ppa ON ws.id = ppa.id AND ws.source_priority = ppa.min_priority
),
effective AS (
  SELECT
    id, name, description, action_type, desired_state, params, timeout_seconds,
    created_at, created_by, is_deleted, projection_version,
    signature, params_canonical,
    CASE
      WHEN bool_or(mode = 2) THEN -1
      WHEN bool_or(mode = 0) THEN 0
      WHEN bool_or(mode = 1 AND user_selected = TRUE) THEN 0
      WHEN bool_or(mode = 1 AND user_selected = FALSE) THEN -1
      ELSE -1
    END AS effective_mode,
    MIN(assignment_sort) AS assignment_sort,
    MIN(definition_sort) AS definition_sort,
    MIN(action_set_sort) AS action_set_sort,
    MIN(action_sort) AS action_sort
  FROM filtered
  GROUP BY id, name, description, action_type, desired_state, params, timeout_seconds,
           created_at, created_by, is_deleted, projection_version,
           signature, params_canonical
)
SELECT id, name, description, action_type, desired_state,
  params, timeout_seconds, created_at, created_by, is_deleted,
  projection_version, signature, params_canonical
FROM effective
WHERE effective_mode >= 0
ORDER BY assignment_sort, definition_sort, action_set_sort, action_sort, id;

-- Get all assignments targeting a user directly or via their user groups.
-- name: ListAssignmentsForUser :many
SELECT * FROM assignments_projection
WHERE is_deleted = FALSE AND (
  (target_type = 'user' AND target_id = $1)
  OR (target_type = 'user_group' AND target_id IN (
    SELECT group_id FROM user_group_members_projection WHERE user_id = $1
  ))
)
ORDER BY created_at DESC;
