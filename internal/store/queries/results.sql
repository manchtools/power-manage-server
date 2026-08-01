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

-- name: GetExecutionView :one
SELECT e.*, COALESCE(a.name, '')::text AS action_name
FROM executions e
JOIN devices d ON d.id = e.device_id AND d.is_deleted = FALSE
LEFT JOIN actions a ON a.id = e.action_id AND a.is_deleted = FALSE
WHERE e.id = $1;

-- name: CancelPendingExecution :execrows
UPDATE executions
SET status = 'cancelled', completed_at = $2
WHERE id = $1 AND status IN ('scheduled', 'pending');

-- name: InsertExecution :one
INSERT INTO executions (
    id, device_id, action_id, action_type, desired_state, params,
    timeout_seconds, status, created_at, scheduled_for,
    created_by_type, created_by_id
) VALUES (
    sqlc.arg(id), sqlc.arg(device_id), sqlc.narg(action_id),
    sqlc.arg(action_type), sqlc.arg(desired_state), sqlc.arg(params),
    sqlc.arg(timeout_seconds), sqlc.arg(status), sqlc.arg(created_at),
    sqlc.narg(scheduled_for), sqlc.arg(created_by_type), sqlc.arg(created_by_id)
)
RETURNING *;

-- name: ListExecutionViews :many
SELECT e.*, COALESCE(a.name, '')::text AS action_name
FROM executions e
JOIN devices d ON d.id = e.device_id AND d.is_deleted = FALSE
LEFT JOIN actions a ON a.id = e.action_id AND a.is_deleted = FALSE
WHERE (sqlc.arg(after_id)::text = '' OR e.id < sqlc.arg(after_id))
  AND (sqlc.arg(device_id)::text = '' OR e.device_id = sqlc.arg(device_id))
  AND (sqlc.arg(status)::text = '' OR e.status = sqlc.arg(status))
  AND (sqlc.arg(action_type)::integer = 0 OR e.action_type = sqlc.arg(action_type))
  AND (
      sqlc.arg(search)::text = ''
      OR strpos(lower(COALESCE(a.name, '')), lower(sqlc.arg(search))) > 0
      OR strpos(lower(d.hostname), lower(sqlc.arg(search))) > 0
  )
  AND (
      NOT sqlc.arg(scope_restricted)::boolean
      OR EXISTS (
          SELECT 1 FROM device_group_members dgm
          WHERE dgm.device_id = e.device_id
            AND dgm.group_id = ANY(sqlc.arg(scope_group_ids)::text[])
      )
  )
  AND (
      sqlc.narg(assigned_user_id)::text IS NULL
      OR EXISTS (
          SELECT 1 FROM device_assigned_users dau
          WHERE dau.device_id = e.device_id
            AND dau.user_id = sqlc.narg(assigned_user_id)
      )
      OR EXISTS (
          SELECT 1
          FROM device_assigned_groups dag
          JOIN user_group_members ugm ON ugm.group_id = dag.group_id
          JOIN user_groups ug ON ug.id = dag.group_id AND ug.is_deleted = FALSE
          WHERE dag.device_id = e.device_id
            AND ugm.user_id = sqlc.narg(assigned_user_id)
      )
  )
ORDER BY e.id DESC
LIMIT sqlc.arg(row_limit);

-- name: CountExecutionViews :one
SELECT COUNT(*)
FROM executions e
JOIN devices d ON d.id = e.device_id AND d.is_deleted = FALSE
LEFT JOIN actions a ON a.id = e.action_id AND a.is_deleted = FALSE
WHERE (sqlc.arg(device_id)::text = '' OR e.device_id = sqlc.arg(device_id))
  AND (sqlc.arg(status)::text = '' OR e.status = sqlc.arg(status))
  AND (sqlc.arg(action_type)::integer = 0 OR e.action_type = sqlc.arg(action_type))
  AND (
      sqlc.arg(search)::text = ''
      OR strpos(lower(COALESCE(a.name, '')), lower(sqlc.arg(search))) > 0
      OR strpos(lower(d.hostname), lower(sqlc.arg(search))) > 0
  )
  AND (
      NOT sqlc.arg(scope_restricted)::boolean
      OR EXISTS (
          SELECT 1 FROM device_group_members dgm
          WHERE dgm.device_id = e.device_id
            AND dgm.group_id = ANY(sqlc.arg(scope_group_ids)::text[])
      )
  )
  AND (
      sqlc.narg(assigned_user_id)::text IS NULL
      OR EXISTS (
          SELECT 1 FROM device_assigned_users dau
          WHERE dau.device_id = e.device_id
            AND dau.user_id = sqlc.narg(assigned_user_id)
      )
      OR EXISTS (
          SELECT 1
          FROM device_assigned_groups dag
          JOIN user_group_members ugm ON ugm.group_id = dag.group_id
          JOIN user_groups ug ON ug.id = dag.group_id AND ug.is_deleted = FALSE
          WHERE dag.device_id = e.device_id
            AND ugm.user_id = sqlc.narg(assigned_user_id)
      )
  );
