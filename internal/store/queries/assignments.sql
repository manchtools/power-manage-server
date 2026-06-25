-- Assignments queries

-- name: GetAssignmentByID :one
SELECT * FROM assignments_projection
WHERE id = $1 AND is_deleted = FALSE;

-- name: GetAssignment :one
SELECT * FROM assignments_projection
WHERE source_type = $1 AND source_id = $2 AND target_type = $3 AND target_id = $4 AND is_deleted = FALSE;

-- name: ListAssignments :many
SELECT a.*,
  COALESCE(CASE a.source_type
    WHEN 'action' THEN (SELECT name FROM actions_projection WHERE id = a.source_id)
    WHEN 'action_set' THEN (SELECT name FROM action_sets_projection WHERE id = a.source_id)
    WHEN 'definition' THEN (SELECT name FROM definitions_projection WHERE id = a.source_id)
    WHEN 'compliance_policy' THEN (SELECT name FROM compliance_policies_projection WHERE id = a.source_id)
  END, '')::TEXT AS source_name,
  COALESCE(CASE a.target_type
    WHEN 'device' THEN (SELECT hostname FROM devices_projection WHERE id = a.target_id)
    WHEN 'device_group' THEN (SELECT name FROM device_groups_projection WHERE id = a.target_id)
    WHEN 'user' THEN (SELECT email FROM users_projection WHERE id = a.target_id)
    WHEN 'user_group' THEN (SELECT name FROM user_groups_projection WHERE id = a.target_id)
  END, '')::TEXT AS target_name
FROM assignments_projection a
WHERE a.is_deleted = FALSE
  AND ($1::TEXT = '' OR a.source_type = $1)
  AND ($2::TEXT = '' OR a.source_id = $2)
  AND ($3::TEXT = '' OR a.target_type = $3)
  AND ($4::TEXT = '' OR a.target_id = $4)
ORDER BY a.created_at DESC
LIMIT $5 OFFSET $6;

-- name: CountAssignments :one
SELECT COUNT(*) FROM assignments_projection
WHERE is_deleted = FALSE
  AND ($1::TEXT = '' OR source_type = $1)
  AND ($2::TEXT = '' OR source_id = $2)
  AND ($3::TEXT = '' OR target_type = $3)
  AND ($4::TEXT = '' OR target_id = $4);

-- name: ListAssignedSourceIDs :many
-- Distinct source_ids with at least one live assignment of the given
-- source_type. Backs the search index `assigned` TAG during a warm rebuild
-- (one query per type instead of a per-entity COUNT).
SELECT DISTINCT source_id FROM assignments_projection
WHERE source_type = $1 AND is_deleted = FALSE;

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

  UNION ALL

  -- Actions via compliance policy assignments (direct to device)
  SELECT
    a.*,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    0 as definition_sort,
    0 as action_set_sort,
    0 as action_sort
  FROM actions_projection a
  JOIN compliance_policy_rules_projection r ON r.action_id = a.id
  JOIN compliance_policies_projection p ON p.id = r.policy_id AND p.is_deleted = FALSE
  JOIN assignments_projection asn ON asn.source_type = 'compliance_policy' AND asn.source_id = r.policy_id
  WHERE asn.target_type = 'device' AND asn.target_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Actions via compliance policy assignments (via device group)
  SELECT
    a.*,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    0 as definition_sort,
    0 as action_set_sort,
    0 as action_sort
  FROM actions_projection a
  JOIN compliance_policy_rules_projection r ON r.action_id = a.id
  JOIN compliance_policies_projection p ON p.id = r.policy_id AND p.is_deleted = FALSE
  JOIN assignments_projection asn ON asn.source_type = 'compliance_policy' AND asn.source_id = r.policy_id
  JOIN device_group_members_projection m ON asn.target_id = m.group_id
  WHERE asn.target_type = 'device_group' AND m.device_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE
),
-- First deduplicate by taking the lowest sort order for each action
deduped AS (
  SELECT DISTINCT ON (id)
    id, name, description, action_type, desired_state, params, timeout_seconds,
    created_at, created_by, is_deleted, projection_version, signature, params_canonical, schedule,
    assignment_sort, definition_sort, action_set_sort, action_sort
  FROM assigned_actions
  ORDER BY id, assignment_sort, definition_sort, action_set_sort, action_sort
)
-- Then return in the correct execution order
SELECT id, name, description, action_type, desired_state, params, timeout_seconds,
       created_at, created_by, is_deleted, projection_version, signature, params_canonical, schedule
FROM deduped
ORDER BY assignment_sort, definition_sort, action_set_sort, action_sort, id;

-- Get all resolved actions for a device with conflict resolution.
-- This is used by the agent sync to determine what actions to apply.
-- Conflict resolution: excluded (2) > uninstall (3) > required (0) >
-- available+selected > available+rejected > unselected (skip)
-- name: ListResolvedActionsForDevice :many
-- Resolution priority: action > action_set > definition
-- Within each level: excluded > uninstall > required > available
WITH all_assignments AS (
  -- Direct action assignments (source_priority = 1, highest)
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical, a.schedule,
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
    a.signature, a.params_canonical, a.schedule,
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
    a.signature, a.params_canonical, a.schedule,
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
    a.signature, a.params_canonical, a.schedule,
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
    a.signature, a.params_canonical, a.schedule,
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
    a.signature, a.params_canonical, a.schedule,
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

  UNION ALL

  -- Actions via compliance policy assignments (direct to device, source_priority = 4).
  -- Compliance policies do not support assignment modes; mode is always REQUIRED (0).
  -- UNINSTALL (3) is intentionally not applicable here — compliance rules express
  -- "this state must hold", which has no removal semantics.
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical, a.schedule,
    0 AS mode,
    asn.source_type AS asn_source_type,
    asn.source_id AS asn_source_id,
    4 AS source_priority,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    0 as definition_sort,
    0 as action_set_sort,
    0 as action_sort
  FROM actions_projection a
  JOIN compliance_policy_rules_projection r ON r.action_id = a.id
  JOIN compliance_policies_projection p ON p.id = r.policy_id AND p.is_deleted = FALSE
  JOIN assignments_projection asn ON asn.source_type = 'compliance_policy' AND asn.source_id = r.policy_id
  WHERE asn.target_type = 'device' AND asn.target_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Actions via compliance policy assignments (via device group, source_priority = 4).
  -- See note above: compliance policies have no UNINSTALL semantics; mode is always 0.
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical, a.schedule,
    0 AS mode,
    asn.source_type AS asn_source_type,
    asn.source_id AS asn_source_id,
    4 AS source_priority,
    COALESCE(asn.sort_order, 0) as assignment_sort,
    0 as definition_sort,
    0 as action_set_sort,
    0 as action_sort
  FROM actions_projection a
  JOIN compliance_policy_rules_projection r ON r.action_id = a.id
  JOIN compliance_policies_projection p ON p.id = r.policy_id AND p.is_deleted = FALSE
  JOIN assignments_projection asn ON asn.source_type = 'compliance_policy' AND asn.source_id = r.policy_id
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
-- Resolve conflicts per action at the winning priority level:
-- excluded > uninstall > required > available
effective AS (
  SELECT
    id, name, description, action_type, desired_state, params, timeout_seconds,
    created_at, created_by, is_deleted, projection_version,
    signature, params_canonical, schedule,
    CASE
      WHEN bool_or(mode = 2) THEN FALSE
      WHEN bool_or(mode = 3) THEN TRUE
      WHEN bool_or(mode = 0) THEN TRUE
      WHEN bool_or(mode = 1 AND user_selected = TRUE) THEN TRUE
      ELSE FALSE
    END AS should_apply,
    bool_or(mode = 3) AS force_absent,
    MIN(assignment_sort) AS assignment_sort,
    MIN(definition_sort) AS definition_sort,
    MIN(action_set_sort) AS action_set_sort,
    MIN(action_sort) AS action_sort
  FROM filtered
  GROUP BY id, name, description, action_type, desired_state, params, timeout_seconds,
           created_at, created_by, is_deleted, projection_version,
           signature, params_canonical, schedule
)
-- Return actions that should be applied, forcing ABSENT for UNINSTALL.
SELECT id, name, description, action_type,
  (CASE WHEN force_absent THEN 1 ELSE desired_state END)::INTEGER AS desired_state,
  params, timeout_seconds, created_at, created_by, is_deleted,
  projection_version, signature, params_canonical, schedule
FROM effective
WHERE should_apply
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

  UNION ALL

  SELECT a.id AS action_id, 0 AS mode, 4 AS source_priority
  FROM actions_projection a
  JOIN compliance_policy_rules_projection r ON r.action_id = a.id
  JOIN compliance_policies_projection p ON p.id = r.policy_id AND p.is_deleted = FALSE
  JOIN assignments_projection asn ON asn.source_type = 'compliance_policy' AND asn.source_id = r.policy_id
  WHERE asn.target_type = 'device' AND asn.target_id = $1
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  SELECT a.id AS action_id, 0 AS mode, 4 AS source_priority
  FROM actions_projection a
  JOIN compliance_policy_rules_projection r ON r.action_id = a.id
  JOIN compliance_policies_projection p ON p.id = r.policy_id AND p.is_deleted = FALSE
  JOIN assignments_projection asn ON asn.source_type = 'compliance_policy' AND asn.source_id = r.policy_id
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
-- Only EXCLUDED (mode = 2) blocks the action from the user layer.
-- UNINSTALL (mode = 3) is deliberately NOT included here: an UNINSTALL assignment
-- must still resolve at the device layer (with desired_state forced to ABSENT)
-- so the action runs and removes managed state. Treating UNINSTALL as exclusion
-- would suppress the removal entirely.
SELECT action_id AS id FROM dev_filtered
GROUP BY action_id
HAVING bool_or(mode = 2);

-- Get all resolved actions from user/user_group layer for a device.
-- Looks up all users assigned to the device (directly or via user groups),
-- then finds assignments targeting those users or any of their groups.
-- name: ListUserLayerResolvedActionsForDevice :many
WITH device_owners AS (
  SELECT dau.user_id FROM device_assigned_users_projection dau WHERE dau.device_id = $1
  UNION
  SELECT ugm.user_id FROM device_assigned_groups_projection dag
  JOIN user_group_members_projection ugm ON ugm.group_id = dag.group_id
  WHERE dag.device_id = $1
),
owner_groups AS (
  SELECT DISTINCT ugm.group_id FROM user_group_members_projection ugm
  JOIN user_groups_projection ug ON ug.id = ugm.group_id AND ug.is_deleted = FALSE
  WHERE ugm.user_id IN (SELECT user_id FROM device_owners)
),
all_assignments AS (
  -- Direct action → user (source_priority = 1)
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical, a.schedule,
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
  WHERE asn.target_type = 'user' AND asn.target_id IN (SELECT user_id FROM device_owners)
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Direct action → user_group (source_priority = 1)
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical, a.schedule,
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
    a.signature, a.params_canonical, a.schedule,
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
  WHERE asn.target_type = 'user' AND asn.target_id IN (SELECT user_id FROM device_owners)
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Action set → user_group (source_priority = 2)
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical, a.schedule,
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
    a.signature, a.params_canonical, a.schedule,
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
  WHERE asn.target_type = 'user' AND asn.target_id IN (SELECT user_id FROM device_owners)
    AND asn.is_deleted = FALSE AND a.is_deleted = FALSE

  UNION ALL

  -- Definition → user_group (source_priority = 3)
  SELECT
    a.id, a.name, a.description, a.action_type, a.desired_state, a.params, a.timeout_seconds,
    a.created_at, a.created_by, a.is_deleted, a.projection_version,
    a.signature, a.params_canonical, a.schedule,
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
    signature, params_canonical, schedule,
    CASE
      WHEN bool_or(mode = 2) THEN FALSE
      WHEN bool_or(mode = 3) THEN TRUE
      WHEN bool_or(mode = 0) THEN TRUE
      WHEN bool_or(mode = 1 AND user_selected = TRUE) THEN TRUE
      ELSE FALSE
    END AS should_apply,
    bool_or(mode = 3) AS force_absent,
    MIN(assignment_sort) AS assignment_sort,
    MIN(definition_sort) AS definition_sort,
    MIN(action_set_sort) AS action_set_sort,
    MIN(action_sort) AS action_sort
  FROM filtered
  GROUP BY id, name, description, action_type, desired_state, params, timeout_seconds,
           created_at, created_by, is_deleted, projection_version,
           signature, params_canonical, schedule
)
SELECT id, name, description, action_type,
  (CASE WHEN force_absent THEN 1 ELSE desired_state END)::INTEGER AS desired_state,
  params, timeout_seconds, created_at, created_by, is_deleted,
  projection_version, signature, params_canonical, schedule
FROM effective
WHERE should_apply
ORDER BY assignment_sort, definition_sort, action_set_sort, action_sort, id;

-- Projector writes (manchtools/power-manage-server#137). Replaces the
-- deleted PL/pgSQL project_assignment_event() function; called from
-- projectors.ApplyAssignment via projectors.AssignmentListener.
--
-- Tightening vs the PL/pgSQL projector: every UPDATE carries an
-- explicit `WHERE projection_version < $N` guard and uses :execrows so
-- the listener can short-circuit cascades on stale-replay (asymmetric-
-- guard discipline; see role_listener / action_set_listener for the
-- canonical shape).
--
-- Compliance cascade is intentionally NOT ported in this wave: the
-- compliance projector is still PL/pgSQL (project_compliance_event /
-- project_compliance_policy_event remain live, see migrations 003 +
-- 029-style follow-ups). The assignment listener invokes the existing
-- evaluate_device_compliance_policies() PL/pgSQL function via
-- EvaluateDeviceCompliancePolicies so the cascade behaviour is
-- preserved verbatim until the compliance port lands.

-- name: InsertAssignmentProjection :execrows
-- AssignmentCreated handler. The PL/pgSQL projector used
-- ON CONFLICT (source_type, source_id, target_type, target_id) DO UPDATE
-- so a re-create of a previously soft-deleted assignment revives the
-- row in place rather than failing the unique-tuple constraint. We
-- preserve that semantics, but tighten the UPDATE branch with a
-- projection_version guard so a stale reconciler replay doesn't
-- silently roll back a fresher row.
--
-- :execrows lets the listener short-circuit the compliance cascade
-- when the conditional UPDATE branch is rejected by the guard
-- (n == 0). The first AssignmentCreated for a (source, target) tuple
-- always lands on the INSERT path and reports n == 1 — the n == 0
-- ambiguity only arises on the UPDATE branch, so a guarded-out replay
-- is the ONLY thing that produces n == 0. Insert OR successful update
-- both yield n == 1; the cascade fires for either, matching the
-- PL/pgSQL projector which ran the cascade unconditionally for
-- AssignmentCreated.
INSERT INTO assignments_projection (
    id, source_type, source_id, target_type, target_id,
    sort_order, mode, created_at, created_by, projection_version
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (source_type, source_id, target_type, target_id) DO UPDATE
    SET is_deleted        = FALSE,
        sort_order        = EXCLUDED.sort_order,
        mode              = EXCLUDED.mode,
        projection_version = EXCLUDED.projection_version
    WHERE assignments_projection.projection_version < EXCLUDED.projection_version;

-- name: UpdateAssignmentModeProjection :execrows
-- AssignmentModeChanged handler. Single UPDATE guarded by
-- projection_version. The handler layer (assignment_handler.go) does
-- not currently emit AssignmentModeChanged — assignments are immutable
-- per the project's mutation model — but the projector keeps parity
-- with the PL/pgSQL version so any historical events in production
-- event stores still replay cleanly during a rebuild.
UPDATE assignments_projection
SET mode               = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: UpdateAssignmentSortOrderProjection :execrows
-- AssignmentSortOrderChanged handler. Same parity rationale as
-- UpdateAssignmentModeProjection: not emitted today, but the PL/pgSQL
-- projector handled the event and a rebuild against an event store
-- containing such events must replay them identically.
UPDATE assignments_projection
SET sort_order         = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: SoftDeleteAssignmentProjection :one
-- AssignmentDeleted handler. The PL/pgSQL projector did SELECT-then-
-- UPDATE because the AssignmentDeleted event payload is empty —
-- source/target details have to be recovered from the existing row to
-- drive the compliance cascade. Combine into one statement via UPDATE
-- ... RETURNING so the listener gets the row + the rows-affected
-- signal in a single round-trip and the read happens against the same
-- snapshot the UPDATE writes against.
--
-- :one + nullable scan: when the projection_version guard rejects the
-- UPDATE, RETURNING produces zero rows and pgx surfaces ErrNoRows.
-- The listener treats that as "stale replay, skip the compliance
-- cascade" — same shape as SoftDelete on action_set + role +
-- identity_provider, just with the row contents tunnelled out at the
-- same time.
UPDATE assignments_projection
SET is_deleted         = TRUE,
    projection_version = $2
WHERE id = $1
  AND projection_version < $2
RETURNING source_type, source_id, target_type, target_id;

-- name: ListDeviceGroupMemberDeviceIDs :many
-- AssignmentCreated / AssignmentDeleted handler — compliance cascade
-- helper. Mirrors the PL/pgSQL `FOR v_device_id IN SELECT device_id
-- FROM device_group_members_projection WHERE group_id = ...` loop. The
-- listener iterates the returned device IDs and calls
-- EvaluateDeviceCompliancePolicies for each.
SELECT device_id
FROM device_group_members_projection
WHERE group_id = $1;

-- name: DeleteCompliancePolicyEvaluationsForDevicePolicy :exec
-- AssignmentDeleted handler — compliance cascade cleanup. Mirrors the
-- PL/pgSQL `DELETE FROM compliance_policy_evaluation_projection WHERE
-- device_id = ... AND policy_id = ...`. Runs BEFORE
-- EvaluateDeviceCompliancePolicies so the re-evaluation sees a clean
-- slate for the unassigned policy.
DELETE FROM compliance_policy_evaluation_projection
WHERE device_id = $1
  AND policy_id = $2;

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

-- Permission-derived TTY user actions.
--
-- Every user that holds the StartTerminal permission (directly or via
-- a user-group role) and has a linked system_tty_action_id should
-- have their pm-tty-<username> account materialized on every device,
-- regardless of any assignment. The action-resolution layer queries
-- this and merges the rows into the per-device action list, so a
-- bulk-enrolled (unassigned) device still gets the TTY accounts it
-- needs for terminal sessions to succeed.
--
-- DISTINCT ON (a.id) collapses the row when a user receives the
-- StartTerminal permission via multiple roles or via direct + group
-- grants — the resolver only wants each TTY action once.
--
-- Filtering rules: skip soft-deleted users, actions, roles, and
-- groups so stale projection rows can't leak through and surface a
-- TTY account that should have been cleaned up.
-- name: ListSystemTtyActionsForDevice :many
-- #7: scope-aware. Returns the tty action of every user who holds
-- StartTerminal GLOBAL or scoped to a device_group containing $1.
-- scope_kind/scope_id live on user_roles_projection /
-- user_group_roles_projection (the S2 columns inside migration 010's
-- DO-block) — sqlc can't resolve them, so the generated method is
-- HAND-MAINTAINED; keep it in sync. A user_group-scoped StartTerminal
-- grant has no device meaning and is excluded.
SELECT DISTINCT ON (a.id)
       a.id, a.name, a.description, a.action_type, a.desired_state,
       a.params, a.timeout_seconds, a.created_at, a.created_by,
       a.is_deleted, a.projection_version,
       a.signature, a.params_canonical, a.schedule
FROM users_projection u
JOIN actions_projection a
  ON a.id = u.system_tty_action_id AND a.is_deleted = FALSE
WHERE u.is_deleted = FALSE
  AND u.system_tty_action_id <> ''
  AND EXISTS (
    SELECT 1
    FROM roles_projection r
    JOIN user_roles_projection ur ON ur.role_id = r.id
    WHERE ur.user_id = u.id AND r.is_deleted = FALSE
      AND 'StartTerminal' = ANY(r.permissions)
      AND (
        ur.scope_kind IS NULL
        OR (ur.scope_kind = 'device_group'
            AND EXISTS (SELECT 1 FROM device_group_members_projection m
                        WHERE m.group_id = ur.scope_id AND m.device_id = $1))
      )
    UNION ALL
    SELECT 1
    FROM roles_projection r
    JOIN user_group_roles_projection ugr ON ugr.role_id = r.id
    JOIN user_group_members_projection ugm ON ugm.group_id = ugr.group_id
    JOIN user_groups_projection ug ON ug.id = ugm.group_id AND ug.is_deleted = FALSE
    WHERE ugm.user_id = u.id AND r.is_deleted = FALSE
      AND 'StartTerminal' = ANY(r.permissions)
      AND (
        ugr.scope_kind IS NULL
        OR (ugr.scope_kind = 'device_group'
            AND EXISTS (SELECT 1 FROM device_group_members_projection m
                        WHERE m.group_id = ugr.scope_id AND m.device_id = $1))
      )
  );

-- Global TerminalAdmin AdminPolicy actions.
--
-- Two well-known rows in actions_projection — bootstrapped at startup
-- (server BootstrapGlobalTerminalAdminActions) and re-signed in place
-- by the reconciler when membership changes. The resolution layer
-- merges these into every device's resolved action list so the
-- pm-tty-* operators get their sudoers fragment regardless of
-- assignment.
--
-- #70 ships with the two GLOBAL rows. #7 extends this to per-scope
-- actions: the two :global rows reach every device, PLUS any
-- system:terminal-admin-{limited,full}:<deviceGroupID> whose group
-- contains $1. split_part(name,':',3) extracts the device-group id
-- (ULIDs are colon-free).
-- name: ListTerminalAdminActionsForDevice :many
SELECT id, name, description, action_type, desired_state,
       params, timeout_seconds, created_at, created_by,
       is_deleted, projection_version,
       signature, params_canonical, schedule
FROM actions_projection
WHERE is_deleted = FALSE
  AND (
    name IN ('system:terminal-admin-limited:global',
             'system:terminal-admin-full:global')
    OR (
      (name LIKE 'system:terminal-admin-limited:%'
        OR name LIKE 'system:terminal-admin-full:%')
      AND split_part(name, ':', 3) IN (
        SELECT m.group_id FROM device_group_members_projection m
        WHERE m.device_id = $1
      )
    )
  );

-- name: ListScopedTerminalAdminActionNames :many
-- Names of every PER-SCOPE terminal-admin action (excluding the two
-- :global actions), so the per-scope reconciler can empty the cohort of
-- any scope that no longer has a holder. Names are
-- system:terminal-admin-{limited,full}:<deviceGroupID> (#7).
SELECT name FROM actions_projection
WHERE is_deleted = FALSE
  AND (name LIKE 'system:terminal-admin-limited:%'
       OR name LIKE 'system:terminal-admin-full:%')
  AND name NOT IN ('system:terminal-admin-limited:global',
                   'system:terminal-admin-full:global');

-- #7 spec 14 — scoped object visibility. The following queries back the
-- search index `scope_group_ids` TAG (direct device-/user-group assignment ids
-- per object) and the live effective/direct scope walk in the object handlers.

-- name: ListScopeGroupIDsForSource :many
-- Device-/user-group ids one object is DIRECTLY assigned to. Backs the search
-- index `scope_group_ids` for an incremental object reindex (#7 spec 14).
SELECT target_id FROM assignments_projection
WHERE source_type = $1 AND source_id = $2
  AND target_type IN ('device_group', 'user_group')
  AND is_deleted = FALSE;

-- name: ListScopeGroupAssignmentsBySourceType :many
-- (source_id, group_id) pairs for every object of a type that is directly
-- assigned to a device-/user-group. One query per type drives the search warm
-- rebuild of `scope_group_ids` (mirrors ListAssignedSourceIDs).
SELECT source_id, target_id FROM assignments_projection
WHERE source_type = $1
  AND target_type IN ('device_group', 'user_group')
  AND is_deleted = FALSE;

-- name: ListActionSetIDsContainingAction :many
-- Reverse container edge: the action-set ids that contain an action. Used by the
-- handler's EFFECTIVE (transitive read) scope walk (#7 spec 14).
SELECT set_id FROM action_set_members_projection WHERE action_id = $1;

-- name: ListDefinitionIDsContainingActionSet :many
-- Reverse container edge: the definition ids that contain an action-set.
SELECT definition_id FROM definition_members_projection WHERE action_set_id = $1;
