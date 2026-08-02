-- name: GetAuthoringCompliancePolicy :one
SELECT * FROM compliance_policies
WHERE id = ? AND is_deleted = FALSE;

-- name: ListAuthoringCompliancePolicies :many
WITH assignment_groups(source_type, source_id, group_id) AS (
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
SELECT p.id, p.name, p.description, p.created_at, p.created_by,
       p.is_deleted,
       (
           SELECT COUNT(*)
           FROM compliance_policy_rules r
           JOIN actions a ON a.id = r.action_id AND a.is_deleted = FALSE
           WHERE r.policy_id = p.id
       ) AS rule_count
FROM compliance_policies p
WHERE p.is_deleted = FALSE
  AND p.id > sqlc.arg(after_id)
  AND (
      NOT sqlc.arg(scope_restricted)
      OR EXISTS (
          SELECT 1 FROM assignment_groups ag
          WHERE ag.source_type = 'compliance_policy'
            AND ag.source_id = p.id
            AND ag.group_id IN (SELECT CAST(value AS TEXT) FROM json_each(sqlc.arg(scope_group_ids_json)))
      )
  )
ORDER BY p.id
LIMIT sqlc.arg(row_limit);

-- name: CountAuthoringCompliancePolicies :one
WITH assignment_groups(source_type, source_id, group_id) AS (
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
FROM compliance_policies p
WHERE p.is_deleted = FALSE
  AND (
      NOT sqlc.arg(scope_restricted)
      OR EXISTS (
          SELECT 1 FROM assignment_groups ag
          WHERE ag.source_type = 'compliance_policy'
            AND ag.source_id = p.id
            AND ag.group_id IN (SELECT CAST(value AS TEXT) FROM json_each(sqlc.arg(scope_group_ids_json)))
      )
  );

-- name: InsertAuthoringCompliancePolicy :one
INSERT INTO compliance_policies (id, name, description, created_at, created_by)
VALUES (sqlc.arg(id), sqlc.arg(name), sqlc.arg(description), sqlc.arg(created_at), sqlc.arg(created_by))
RETURNING *;

-- name: RenameAuthoringCompliancePolicy :one
UPDATE compliance_policies
SET name = sqlc.arg(name)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

-- name: UpdateAuthoringCompliancePolicyDescription :one
UPDATE compliance_policies
SET description = sqlc.arg(description)
WHERE id = sqlc.arg(id) AND is_deleted = FALSE
RETURNING *;

-- name: AddAuthoringCompliancePolicyRule :one
INSERT INTO compliance_policy_rules (
    policy_id, action_id, action_name, grace_period_hours, added_at
)
SELECT sqlc.arg(policy_id), sqlc.arg(action_id), sqlc.arg(action_name),
       sqlc.arg(grace_period_hours), sqlc.arg(added_at)
WHERE EXISTS (
    SELECT 1 FROM compliance_policies
    WHERE id = sqlc.arg(policy_id) AND is_deleted = FALSE
)
AND EXISTS (
    SELECT 1 FROM actions
    WHERE id = sqlc.arg(action_id) AND is_deleted = FALSE
)
ON CONFLICT (policy_id, action_id) DO NOTHING
RETURNING *;

-- name: RemoveAuthoringCompliancePolicyRule :one
DELETE FROM compliance_policy_rules
WHERE policy_id = sqlc.arg(policy_id) AND action_id = sqlc.arg(action_id)
RETURNING *;

-- name: UpdateAuthoringCompliancePolicyRule :one
UPDATE compliance_policy_rules
SET grace_period_hours = sqlc.arg(grace_period_hours)
WHERE policy_id = sqlc.arg(policy_id) AND action_id = sqlc.arg(action_id)
RETURNING *;

-- name: ListCompliancePolicyRules :many
SELECT r.policy_id, r.action_id, a.name AS action_name,
       r.grace_period_hours, r.added_at
FROM compliance_policy_rules r
JOIN actions a ON a.id = r.action_id AND a.is_deleted = FALSE
WHERE r.policy_id = ?
ORDER BY r.action_id;

-- name: ListContainingCompliancePolicyIDs :many
SELECT r.policy_id
FROM compliance_policy_rules r
JOIN compliance_policies p ON p.id = r.policy_id AND p.is_deleted = FALSE
WHERE r.action_id = ?
ORDER BY r.policy_id;

-- name: DeleteCompliancePolicyRulesForAction :many
DELETE FROM compliance_policy_rules
WHERE action_id = ?
RETURNING policy_id;

-- name: DeleteCompliancePolicyEvaluationsForAction :many
DELETE FROM compliance_policy_evaluation
WHERE action_id = ?
RETURNING policy_id;

-- name: DeleteComplianceResultsForAction :many
DELETE FROM compliance_results
WHERE action_id = ?
RETURNING device_id;

-- name: DeleteAuthoringCompliancePolicyRules :many
DELETE FROM compliance_policy_rules
WHERE policy_id = ?
RETURNING action_id;

-- name: DeleteCompliancePolicyEvaluations :many
DELETE FROM compliance_policy_evaluation
WHERE policy_id = ?
RETURNING device_id;

-- name: DeleteCompliancePolicyAssignments :many
DELETE FROM assignments
WHERE source_type = 'compliance_policy' AND source_id = ?
RETURNING id;

-- name: SoftDeleteAuthoringCompliancePolicy :one
UPDATE compliance_policies
SET is_deleted = TRUE
WHERE id = ? AND is_deleted = FALSE
RETURNING *;
