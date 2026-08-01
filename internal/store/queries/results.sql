-- name: GetOSQueryResult :one
SELECT query_id, device_id, completed, success, error, rows, created_at
FROM osquery_results
WHERE query_id = $1;

-- name: GetDeviceLogResult :one
SELECT query_id, device_id, completed, success, error, logs, created_at
FROM log_query_results
WHERE query_id = $1;

-- name: ListDeviceComplianceResults :many
SELECT cr.action_id, a.name AS action_name, cr.compliant,
       cr.detection_output, cr.checked_at
FROM compliance_results cr
JOIN actions a ON a.id = cr.action_id AND a.is_deleted = FALSE
WHERE cr.device_id = $1
ORDER BY cr.action_id;

-- name: ListDeviceComplianceEvaluations :many
SELECT e.policy_id, p.name AS policy_name,
       e.action_id, a.name AS action_name,
       e.status, e.compliant, r.grace_period_hours,
       e.checked_at, e.first_failed_at, cr.detection_output
FROM compliance_policy_evaluation e
JOIN compliance_policies p ON p.id = e.policy_id AND p.is_deleted = FALSE
JOIN compliance_policy_rules r ON r.policy_id = e.policy_id AND r.action_id = e.action_id
JOIN actions a ON a.id = e.action_id AND a.is_deleted = FALSE
LEFT JOIN compliance_results cr ON cr.device_id = e.device_id AND cr.action_id = e.action_id
WHERE e.device_id = $1
ORDER BY e.policy_id, e.action_id;
