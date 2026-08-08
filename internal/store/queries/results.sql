-- name: GetOSQueryResult :one
SELECT query_id, device_id, completed, success, error, rows, created_at
FROM osquery_results
WHERE query_id = ?;

-- name: InsertPendingOSQueryResult :exec
INSERT INTO osquery_results (
    query_id, device_id, table_name, completed, success, error, rows, created_at
) VALUES (
    sqlc.arg(query_id), sqlc.arg(device_id), sqlc.arg(table_name),
    FALSE, FALSE, '', '[]', sqlc.arg(created_at)
);

-- name: FailPendingOSQueryResult :execrows
UPDATE osquery_results
SET completed = TRUE, success = FALSE, error = sqlc.arg(error),
    rows = '[]', completed_at = sqlc.arg(completed_at)
WHERE query_id = sqlc.arg(query_id)
  AND device_id = sqlc.arg(device_id)
  AND completed = FALSE;

-- name: CompleteOSQueryResult :execrows
UPDATE osquery_results
SET completed = TRUE, success = sqlc.arg(success), error = sqlc.arg(error),
    rows = sqlc.arg(rows), completed_at = sqlc.arg(completed_at)
WHERE query_id = sqlc.arg(query_id)
  AND device_id = sqlc.arg(device_id)
  AND completed = FALSE;

-- name: GetDeviceLogResult :one
SELECT query_id, device_id, completed, success, error, logs, created_at
FROM log_query_results
WHERE query_id = ?;

-- name: InsertPendingLogQueryResult :exec
INSERT INTO log_query_results (
    query_id, device_id, completed, success, error, logs, created_at
) VALUES (
    sqlc.arg(query_id), sqlc.arg(device_id), FALSE, FALSE, '', '', sqlc.arg(created_at)
);

-- name: FailPendingLogQueryResult :execrows
UPDATE log_query_results
SET completed = TRUE, success = FALSE, error = sqlc.arg(error),
    logs = '', completed_at = sqlc.arg(completed_at)
WHERE query_id = sqlc.arg(query_id)
  AND device_id = sqlc.arg(device_id)
  AND completed = FALSE;

-- name: CompleteLogQueryResult :execrows
UPDATE log_query_results
SET completed = TRUE, success = sqlc.arg(success), error = sqlc.arg(error),
    logs = sqlc.arg(logs), completed_at = sqlc.arg(completed_at)
WHERE query_id = sqlc.arg(query_id)
  AND device_id = sqlc.arg(device_id)
  AND completed = FALSE;

-- name: UpsertDeviceInventoryTable :exec
INSERT INTO device_inventory (device_id, table_name, rows, collected_at)
VALUES (sqlc.arg(device_id), sqlc.arg(table_name), sqlc.arg(rows), sqlc.arg(collected_at))
ON CONFLICT (device_id, table_name) DO UPDATE
SET rows = EXCLUDED.rows, collected_at = EXCLUDED.collected_at;

-- name: ListDeviceComplianceResults :many
SELECT cr.action_id, a.name AS action_name, cr.compliant,
       cr.detection_output, cr.checked_at
FROM compliance_results cr
JOIN actions a ON a.id = cr.action_id AND a.is_deleted = FALSE
WHERE cr.device_id = ?
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
WHERE e.device_id = ?
ORDER BY e.policy_id, e.action_id;

-- Compliance ingestion is this statement and the three below it. All four run
-- inside the execution-result transaction, so the compliance surface cannot
-- disagree with the execution evidence it is derived from.

-- name: UpsertDeviceComplianceResult :execrows
INSERT INTO compliance_results (
    device_id, action_id, action_name, compliant, detection_output, checked_at
)
SELECT sqlc.arg(device_id), a.id, a.name, sqlc.arg(compliant),
       sqlc.narg(detection_output), sqlc.arg(checked_at)
FROM actions a
WHERE a.id = sqlc.arg(action_id) AND a.is_deleted = FALSE
ON CONFLICT (device_id, action_id) DO UPDATE
SET action_name = excluded.action_name,
    compliant = excluded.compliant,
    detection_output = excluded.detection_output,
    checked_at = excluded.checked_at;

-- name: ListComplianceRuleEvaluationTargets :many
SELECT r.policy_id, r.grace_period_hours, e.first_failed_at
FROM compliance_policy_rules r
JOIN compliance_policies p ON p.id = r.policy_id AND p.is_deleted = FALSE
LEFT JOIN compliance_policy_evaluation e
       ON e.policy_id = r.policy_id AND e.action_id = r.action_id
      AND e.device_id = sqlc.arg(device_id)
WHERE r.action_id = sqlc.arg(action_id)
ORDER BY r.policy_id;

-- name: UpsertCompliancePolicyEvaluation :exec
INSERT INTO compliance_policy_evaluation (
    device_id, policy_id, action_id, compliant, first_failed_at, status, checked_at
) VALUES (
    sqlc.arg(device_id), sqlc.arg(policy_id), sqlc.arg(action_id),
    sqlc.arg(compliant), sqlc.narg(first_failed_at), sqlc.arg(status), sqlc.arg(checked_at)
)
ON CONFLICT (device_id, policy_id, action_id) DO UPDATE
SET compliant = excluded.compliant,
    first_failed_at = excluded.first_failed_at,
    status = excluded.status,
    checked_at = excluded.checked_at;

-- Rolls the device summary up from the rows just written. severity orders the
-- statuses by how bad they are (non-compliant worst, then grace, then unknown,
-- then compliant) because the stored enum is not in that order. A check that
-- belongs to no live policy rule has no grace period, so it contributes
-- directly. No rows at all leaves the device UNKNOWN, which is what
-- distinguishes "never checked" from "checked and failed".

-- name: RefreshDeviceComplianceStatus :execrows
UPDATE devices
SET compliance_total = (
        SELECT COUNT(*)
        FROM compliance_results cr
        JOIN actions a ON a.id = cr.action_id AND a.is_deleted = FALSE
        WHERE cr.device_id = sqlc.arg(device_id)
    ),
    compliance_passing = (
        SELECT COUNT(*)
        FROM compliance_results cr
        JOIN actions a ON a.id = cr.action_id AND a.is_deleted = FALSE
        WHERE cr.device_id = sqlc.arg(device_id) AND cr.compliant
    ),
    compliance_checked_at = CASE
        WHEN NOT EXISTS (
            SELECT 1
            FROM compliance_results cr
            JOIN actions a ON a.id = cr.action_id AND a.is_deleted = FALSE
            WHERE cr.device_id = sqlc.arg(device_id)
        ) THEN NULL
        WHEN compliance_checked_at IS NULL OR compliance_checked_at < sqlc.arg(checked_at)
        THEN sqlc.arg(checked_at)
        ELSE compliance_checked_at
    END,
    compliance_status = (
        SELECT CASE
                   WHEN COUNT(*) = 0 THEN 0
                   WHEN MAX(severity) = 3 THEN 2
                   WHEN MAX(severity) = 2 THEN 3
                   WHEN MAX(severity) = 1 THEN 0
                   ELSE 1
               END
        FROM (
            SELECT CASE e.status WHEN 2 THEN 3 WHEN 3 THEN 2 WHEN 0 THEN 1 ELSE 0 END AS severity
            FROM compliance_policy_evaluation e
            JOIN compliance_policies p ON p.id = e.policy_id AND p.is_deleted = FALSE
            JOIN compliance_policy_rules r ON r.policy_id = e.policy_id AND r.action_id = e.action_id
            JOIN actions a ON a.id = e.action_id AND a.is_deleted = FALSE
            WHERE e.device_id = sqlc.arg(device_id)
            UNION ALL
            SELECT CASE WHEN cr.compliant THEN 0 ELSE 3 END
            FROM compliance_results cr
            JOIN actions a ON a.id = cr.action_id AND a.is_deleted = FALSE
            WHERE cr.device_id = sqlc.arg(device_id)
              AND NOT EXISTS (
                  SELECT 1
                  FROM compliance_policy_rules r
                  JOIN compliance_policies p ON p.id = r.policy_id AND p.is_deleted = FALSE
                  WHERE r.action_id = cr.action_id
              )
        )
    )
WHERE id = sqlc.arg(device_id) AND is_deleted = FALSE;

-- name: GetExecutionView :one
SELECT e.*, COALESCE(a.name, '') AS action_name
FROM executions e
JOIN devices d ON d.id = e.device_id AND d.is_deleted = FALSE
LEFT JOIN actions a ON a.id = e.action_id AND a.is_deleted = FALSE
WHERE e.id = ?;

-- name: CancelPendingExecution :execrows
UPDATE executions
SET status = 'cancelled', completed_at = ?
WHERE id = ? AND status IN ('scheduled', 'pending');

-- name: InsertExecution :one
INSERT INTO executions (
    id, delivery_id, device_id, action_id, action_type, desired_state, params,
    timeout_seconds, status, created_at, scheduled_for,
    created_by_type, created_by_id
) VALUES (
    sqlc.arg(id), sqlc.arg(delivery_id), sqlc.arg(device_id), sqlc.narg(action_id),
    sqlc.arg(action_type), sqlc.arg(desired_state), sqlc.arg(params),
    sqlc.arg(timeout_seconds), sqlc.arg(status), sqlc.arg(created_at),
    sqlc.narg(scheduled_for), sqlc.arg(created_by_type), sqlc.arg(created_by_id)
)
RETURNING *;

-- name: MarkExecutionRunning :execrows
UPDATE executions
SET status = 'running', started_at = COALESCE(started_at, sqlc.arg(started_at))
WHERE id = sqlc.arg(id)
  AND delivery_id = sqlc.arg(delivery_id)
  AND device_id = sqlc.arg(device_id)
  AND status IN ('scheduled', 'pending');

-- name: CompleteExecutionFromAgent :execrows
UPDATE executions
SET status = sqlc.arg(status),
    error = sqlc.narg(error),
    output = sqlc.narg(output),
    detection_output = sqlc.narg(detection_output),
    changed = sqlc.arg(changed),
    compliant = sqlc.arg(compliant),
    completed_at = sqlc.arg(completed_at),
    duration_ms = sqlc.arg(duration_ms)
WHERE id = sqlc.arg(id)
  AND delivery_id = sqlc.arg(delivery_id)
  AND device_id = sqlc.arg(device_id)
  AND status IN ('scheduled', 'pending', 'running');

-- name: InsertExecutionOutputChunk :one
INSERT INTO execution_output_chunks (
    execution_id, stream, sequence, data, received_at
) VALUES (
    sqlc.arg(execution_id), sqlc.arg(stream), sqlc.arg(sequence),
    sqlc.arg(data), sqlc.arg(received_at)
)
ON CONFLICT (execution_id, stream, sequence) DO NOTHING
RETURNING execution_id;

-- name: GetExecutionOutputChunk :one
SELECT * FROM execution_output_chunks
WHERE execution_id = sqlc.arg(execution_id)
  AND stream = sqlc.arg(stream)
  AND sequence = sqlc.arg(sequence);

-- name: ListExecutionViews :many
SELECT e.*, COALESCE(a.name, '') AS action_name
FROM executions e
JOIN devices d ON d.id = e.device_id AND d.is_deleted = FALSE
LEFT JOIN actions a ON a.id = e.action_id AND a.is_deleted = FALSE
WHERE (sqlc.arg(after_id) = '' OR e.id < sqlc.arg(after_id))
  AND (sqlc.arg(device_id) = '' OR e.device_id = sqlc.arg(device_id))
  AND (sqlc.arg(status) = '' OR e.status = sqlc.arg(status))
  AND (sqlc.arg(action_type) = 0 OR e.action_type = sqlc.arg(action_type))
  AND (
      sqlc.arg(search) = ''
      OR instr(lower(COALESCE(a.name, '')), lower(sqlc.arg(search))) > 0
      OR instr(lower(d.hostname), lower(sqlc.arg(search))) > 0
  )
  AND (
      NOT sqlc.arg(scope_restricted)
      OR EXISTS (
          SELECT 1 FROM device_group_members dgm
          WHERE dgm.device_id = e.device_id
            AND dgm.group_id IN (SELECT CAST(value AS TEXT) FROM json_each(sqlc.arg(scope_group_ids_json)))
      )
  )
  AND (
      sqlc.narg(assigned_user_id) IS NULL
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
WHERE (sqlc.arg(device_id) = '' OR e.device_id = sqlc.arg(device_id))
  AND (sqlc.arg(status) = '' OR e.status = sqlc.arg(status))
  AND (sqlc.arg(action_type) = 0 OR e.action_type = sqlc.arg(action_type))
  AND (
      sqlc.arg(search) = ''
      OR instr(lower(COALESCE(a.name, '')), lower(sqlc.arg(search))) > 0
      OR instr(lower(d.hostname), lower(sqlc.arg(search))) > 0
  )
  AND (
      NOT sqlc.arg(scope_restricted)
      OR EXISTS (
          SELECT 1 FROM device_group_members dgm
          WHERE dgm.device_id = e.device_id
            AND dgm.group_id IN (SELECT CAST(value AS TEXT) FROM json_each(sqlc.arg(scope_group_ids_json)))
      )
  )
  AND (
      sqlc.narg(assigned_user_id) IS NULL
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

-- name: ListExecutionIDsForAction :many
SELECT id FROM executions WHERE action_id = ? ORDER BY id;

-- name: ListExecutionIDsForDevice :many
SELECT id FROM executions WHERE device_id = ? ORDER BY id;
