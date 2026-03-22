-- Compliance policy queries

-- name: GetCompliancePolicyByID :one
SELECT * FROM compliance_policies_projection
WHERE id = $1 AND is_deleted = FALSE;

-- name: GetCompliancePolicyByName :one
SELECT * FROM compliance_policies_projection
WHERE name = $1 AND is_deleted = FALSE;

-- name: ListCompliancePolicies :many
SELECT * FROM compliance_policies_projection
WHERE is_deleted = FALSE
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountCompliancePolicies :one
SELECT COUNT(*) FROM compliance_policies_projection
WHERE is_deleted = FALSE;

-- name: ListCompliancePolicyRules :many
SELECT * FROM compliance_policy_rules_projection
WHERE policy_id = $1
ORDER BY action_name;

-- name: GetDeviceCompliancePolicyEvaluations :many
SELECT
    e.device_id,
    e.policy_id,
    e.action_id,
    e.compliant,
    e.first_failed_at,
    e.status,
    e.checked_at,
    e.projection_version,
    r.grace_period_hours,
    r.action_name,
    p.name as policy_name
FROM compliance_policy_evaluation_projection e
JOIN compliance_policy_rules_projection r
  ON r.policy_id = e.policy_id AND r.action_id = e.action_id
JOIN compliance_policies_projection p
  ON p.id = e.policy_id AND p.is_deleted = FALSE
WHERE e.device_id = $1
ORDER BY p.name, r.action_name;
