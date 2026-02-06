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
    id, name, description, action_type, params, timeout_seconds,
    created_at, created_by, is_deleted, projection_version, signature, params_canonical,
    assignment_sort, definition_sort, action_set_sort, action_sort
  FROM assigned_actions
  ORDER BY id, assignment_sort, definition_sort, action_set_sort, action_sort
)
-- Then return in the correct execution order
SELECT id, name, description, action_type, params, timeout_seconds,
       created_at, created_by, is_deleted, projection_version, signature, params_canonical
FROM deduped
ORDER BY assignment_sort, definition_sort, action_set_sort, action_sort, id;

-- Get all resolved actions for a device with desired_state computed from assignment modes.
-- This is used by the agent sync to determine what actions to apply and with what desired_state.
-- Conflict resolution: absent (2) > present (0) > available+selected > available+rejected > unselected (excluded)
-- name: ListResolvedActionsForDevice :many
-- Resolution priority: action > action_set > definition
-- Within each level: absent > present > available
WITH all_assignments AS (
  -- Direct action assignments (source_priority = 1, highest)
  SELECT
    a.id, a.name, a.description, a.action_type, a.params, a.timeout_seconds,
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
    a.id, a.name, a.description, a.action_type, a.params, a.timeout_seconds,
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
    a.id, a.name, a.description, a.action_type, a.params, a.timeout_seconds,
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
    a.id, a.name, a.description, a.action_type, a.params, a.timeout_seconds,
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
    a.id, a.name, a.description, a.action_type, a.params, a.timeout_seconds,
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
    a.id, a.name, a.description, a.action_type, a.params, a.timeout_seconds,
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
-- Resolve conflicts per action at the winning priority level: absent > present > available
effective AS (
  SELECT
    id, name, description, action_type, params, timeout_seconds,
    created_at, created_by, is_deleted, projection_version,
    signature, params_canonical,
    CASE
      WHEN bool_or(mode = 2) THEN 2                            -- absent wins
      WHEN bool_or(mode = 0) THEN 0                            -- present wins
      WHEN bool_or(mode = 1 AND user_selected = TRUE) THEN 0   -- available+selected → present
      WHEN bool_or(mode = 1 AND user_selected = FALSE) THEN 2  -- available+rejected → absent
      ELSE -1                                                    -- unselected available → exclude
    END AS effective_mode,
    MIN(assignment_sort) AS assignment_sort,
    MIN(definition_sort) AS definition_sort,
    MIN(action_set_sort) AS action_set_sort,
    MIN(action_sort) AS action_sort
  FROM filtered
  GROUP BY id, name, description, action_type, params, timeout_seconds,
           created_at, created_by, is_deleted, projection_version,
           signature, params_canonical
)
-- Return with computed desired_state: mode 2 (absent) → 1, mode 0 (present) → 0
SELECT id, name, description, action_type,
  CASE WHEN effective_mode = 2 THEN 1 ELSE 0 END AS desired_state,
  params, timeout_seconds, created_at, created_by, is_deleted,
  projection_version, signature, params_canonical
FROM effective
WHERE effective_mode >= 0
ORDER BY assignment_sort, definition_sort, action_set_sort, action_sort, id;
