-- name: GetDeviceGroupID :one
SELECT id FROM device_groups WHERE id = ? AND is_deleted = FALSE;

-- name: GetAssignmentByID :one
SELECT a.*,
       COALESCE(sa.name, ss.name, sd.name, sp.name, '') AS resolved_source_name,
       COALESCE(td.hostname, tdg.name, tu.display_name, tug.name, '') AS resolved_target_name
FROM assignments a
LEFT JOIN actions sa ON a.source_type = 'action' AND sa.id = a.source_id AND sa.is_deleted = FALSE
LEFT JOIN action_sets ss ON a.source_type = 'action_set' AND ss.id = a.source_id AND ss.is_deleted = FALSE
LEFT JOIN definitions sd ON a.source_type = 'definition' AND sd.id = a.source_id AND sd.is_deleted = FALSE
LEFT JOIN compliance_policies sp ON a.source_type = 'compliance_policy' AND sp.id = a.source_id AND sp.is_deleted = FALSE
LEFT JOIN devices td ON a.target_type = 'device' AND td.id = a.target_id AND td.is_deleted = FALSE
LEFT JOIN device_groups tdg ON a.target_type = 'device_group' AND tdg.id = a.target_id AND tdg.is_deleted = FALSE
LEFT JOIN users tu ON a.target_type = 'user' AND tu.id = a.target_id AND tu.is_deleted = FALSE
LEFT JOIN user_groups tug ON a.target_type = 'user_group' AND tug.id = a.target_id AND tug.is_deleted = FALSE
WHERE a.id = ? AND a.is_deleted = FALSE
  AND COALESCE(sa.id, ss.id, sd.id, sp.id) IS NOT NULL
  AND COALESCE(td.id, tdg.id, tu.id, tug.id) IS NOT NULL;

-- name: GetAssignmentByTuple :one
SELECT a.*,
       COALESCE(sa.name, ss.name, sd.name, sp.name, '') AS source_name,
       COALESCE(td.hostname, tdg.name, tu.display_name, tug.name, '') AS target_name
FROM assignments a
LEFT JOIN actions sa ON a.source_type = 'action' AND sa.id = a.source_id AND sa.is_deleted = FALSE
LEFT JOIN action_sets ss ON a.source_type = 'action_set' AND ss.id = a.source_id AND ss.is_deleted = FALSE
LEFT JOIN definitions sd ON a.source_type = 'definition' AND sd.id = a.source_id AND sd.is_deleted = FALSE
LEFT JOIN compliance_policies sp ON a.source_type = 'compliance_policy' AND sp.id = a.source_id AND sp.is_deleted = FALSE
LEFT JOIN devices td ON a.target_type = 'device' AND td.id = a.target_id AND td.is_deleted = FALSE
LEFT JOIN device_groups tdg ON a.target_type = 'device_group' AND tdg.id = a.target_id AND tdg.is_deleted = FALSE
LEFT JOIN users tu ON a.target_type = 'user' AND tu.id = a.target_id AND tu.is_deleted = FALSE
LEFT JOIN user_groups tug ON a.target_type = 'user_group' AND tug.id = a.target_id AND tug.is_deleted = FALSE
WHERE a.source_type = sqlc.arg(source_type)
  AND a.source_id = sqlc.arg(source_id)
  AND a.target_type = sqlc.arg(target_type)
  AND a.target_id = sqlc.arg(target_id)
  AND a.is_deleted = FALSE
  AND COALESCE(sa.id, ss.id, sd.id, sp.id) IS NOT NULL
  AND COALESCE(td.id, tdg.id, tu.id, tug.id) IS NOT NULL;

-- name: ListAssignmentViews :many
SELECT a.*,
       COALESCE(sa.name, ss.name, sd.name, sp.name, '') AS resolved_source_name,
       COALESCE(td.hostname, tdg.name, tu.display_name, tug.name, '') AS resolved_target_name
FROM assignments a
LEFT JOIN actions sa ON a.source_type = 'action' AND sa.id = a.source_id AND sa.is_deleted = FALSE
LEFT JOIN action_sets ss ON a.source_type = 'action_set' AND ss.id = a.source_id AND ss.is_deleted = FALSE
LEFT JOIN definitions sd ON a.source_type = 'definition' AND sd.id = a.source_id AND sd.is_deleted = FALSE
LEFT JOIN compliance_policies sp ON a.source_type = 'compliance_policy' AND sp.id = a.source_id AND sp.is_deleted = FALSE
LEFT JOIN devices td ON a.target_type = 'device' AND td.id = a.target_id AND td.is_deleted = FALSE
LEFT JOIN device_groups tdg ON a.target_type = 'device_group' AND tdg.id = a.target_id AND tdg.is_deleted = FALSE
LEFT JOIN users tu ON a.target_type = 'user' AND tu.id = a.target_id AND tu.is_deleted = FALSE
LEFT JOIN user_groups tug ON a.target_type = 'user_group' AND tug.id = a.target_id AND tug.is_deleted = FALSE
WHERE a.is_deleted = FALSE
  AND a.id > sqlc.arg(after_id)
  AND (sqlc.arg(source_type) = '' OR a.source_type = sqlc.arg(source_type))
  AND (sqlc.arg(source_id) = '' OR a.source_id = sqlc.arg(source_id))
  AND (sqlc.arg(target_type) = '' OR a.target_type = sqlc.arg(target_type))
  AND (sqlc.arg(target_id) = '' OR a.target_id = sqlc.arg(target_id))
  AND COALESCE(sa.id, ss.id, sd.id, sp.id) IS NOT NULL
  AND COALESCE(td.id, tdg.id, tu.id, tug.id) IS NOT NULL
ORDER BY a.id
LIMIT sqlc.arg(row_limit);

-- name: CountAssignmentViews :one
SELECT COUNT(*)
FROM assignments a
LEFT JOIN actions sa ON a.source_type = 'action' AND sa.id = a.source_id AND sa.is_deleted = FALSE
LEFT JOIN action_sets ss ON a.source_type = 'action_set' AND ss.id = a.source_id AND ss.is_deleted = FALSE
LEFT JOIN definitions sd ON a.source_type = 'definition' AND sd.id = a.source_id AND sd.is_deleted = FALSE
LEFT JOIN compliance_policies sp ON a.source_type = 'compliance_policy' AND sp.id = a.source_id AND sp.is_deleted = FALSE
LEFT JOIN devices td ON a.target_type = 'device' AND td.id = a.target_id AND td.is_deleted = FALSE
LEFT JOIN device_groups tdg ON a.target_type = 'device_group' AND tdg.id = a.target_id AND tdg.is_deleted = FALSE
LEFT JOIN users tu ON a.target_type = 'user' AND tu.id = a.target_id AND tu.is_deleted = FALSE
LEFT JOIN user_groups tug ON a.target_type = 'user_group' AND tug.id = a.target_id AND tug.is_deleted = FALSE
WHERE a.is_deleted = FALSE
  AND (sqlc.arg(source_type) = '' OR a.source_type = sqlc.arg(source_type))
  AND (sqlc.arg(source_id) = '' OR a.source_id = sqlc.arg(source_id))
  AND (sqlc.arg(target_type) = '' OR a.target_type = sqlc.arg(target_type))
  AND (sqlc.arg(target_id) = '' OR a.target_id = sqlc.arg(target_id))
  AND COALESCE(sa.id, ss.id, sd.id, sp.id) IS NOT NULL
  AND COALESCE(td.id, tdg.id, tu.id, tug.id) IS NOT NULL;

-- name: ListAssignmentViewsForUser :many
-- User-targeted assignments resolve through the current materialized group
-- memberships. Dynamic group evaluation updates the same membership table, so
-- this read needs no second query language or compatibility path.
SELECT a.*,
       COALESCE(sa.name, ss.name, sd.name, sp.name, '') AS resolved_source_name,
       COALESCE(tu.display_name, tug.name, '') AS resolved_target_name
FROM assignments a
LEFT JOIN actions sa ON a.source_type = 'action' AND sa.id = a.source_id AND sa.is_deleted = FALSE
LEFT JOIN action_sets ss ON a.source_type = 'action_set' AND ss.id = a.source_id AND ss.is_deleted = FALSE
LEFT JOIN definitions sd ON a.source_type = 'definition' AND sd.id = a.source_id AND sd.is_deleted = FALSE
LEFT JOIN compliance_policies sp ON a.source_type = 'compliance_policy' AND sp.id = a.source_id AND sp.is_deleted = FALSE
LEFT JOIN users tu ON a.target_type = 'user' AND tu.id = a.target_id AND tu.is_deleted = FALSE
LEFT JOIN user_groups tug ON a.target_type = 'user_group' AND tug.id = a.target_id AND tug.is_deleted = FALSE
WHERE a.is_deleted = FALSE
  AND (
      (a.target_type = 'user' AND a.target_id = sqlc.arg(user_id))
      OR (
          a.target_type = 'user_group'
          AND EXISTS (
              SELECT 1
              FROM user_group_members ugm
              WHERE ugm.group_id = a.target_id AND ugm.user_id = sqlc.arg(user_id)
          )
      )
  )
  AND COALESCE(sa.id, ss.id, sd.id, sp.id) IS NOT NULL
  AND COALESCE(tu.id, tug.id) IS NOT NULL
ORDER BY a.id;

-- name: AvailableAssignmentExistsForDevice :one
SELECT EXISTS (
    SELECT 1
    FROM assignments a
    JOIN devices d ON d.id = sqlc.arg(device_id) AND d.is_deleted = FALSE
    WHERE a.is_deleted = FALSE
      AND a.mode = 1
      AND a.source_type = sqlc.arg(source_type)
      AND a.source_id = sqlc.arg(source_id)
      AND (
          (a.source_type = 'action' AND EXISTS (SELECT 1 FROM actions s WHERE s.id = a.source_id AND s.is_deleted = FALSE))
          OR (a.source_type = 'action_set' AND EXISTS (SELECT 1 FROM action_sets s WHERE s.id = a.source_id AND s.is_deleted = FALSE))
          OR (a.source_type = 'definition' AND EXISTS (SELECT 1 FROM definitions s WHERE s.id = a.source_id AND s.is_deleted = FALSE))
          OR (a.source_type = 'compliance_policy' AND EXISTS (SELECT 1 FROM compliance_policies s WHERE s.id = a.source_id AND s.is_deleted = FALSE))
      )
      AND (
          (a.target_type = 'device' AND a.target_id = d.id)
          OR (a.target_type = 'device_group' AND EXISTS (
              SELECT 1 FROM device_group_members dgm
              JOIN device_groups dg ON dg.id = dgm.group_id AND dg.is_deleted = FALSE
              WHERE dgm.device_id = d.id AND dgm.group_id = a.target_id
          ))
          OR (a.target_type = 'user' AND (
              EXISTS (SELECT 1 FROM device_assigned_users dau
                      JOIN users u ON u.id = dau.user_id AND u.is_deleted = FALSE
                      WHERE dau.device_id = d.id AND dau.user_id = a.target_id)
              OR EXISTS (SELECT 1 FROM device_assigned_groups dag
                         JOIN user_groups ug ON ug.id = dag.group_id AND ug.is_deleted = FALSE
                         JOIN user_group_members ugm ON ugm.group_id = dag.group_id
                         WHERE dag.device_id = d.id AND ugm.user_id = a.target_id)
          ))
          OR (a.target_type = 'user_group' AND (
              EXISTS (SELECT 1 FROM device_assigned_groups dag
                      JOIN user_groups ug ON ug.id = dag.group_id AND ug.is_deleted = FALSE
                      WHERE dag.device_id = d.id AND dag.group_id = a.target_id)
              OR EXISTS (SELECT 1 FROM device_assigned_users dau
                         JOIN users u ON u.id = dau.user_id AND u.is_deleted = FALSE
                         JOIN user_group_members ugm ON ugm.user_id = dau.user_id
                         JOIN user_groups ug ON ug.id = ugm.group_id AND ug.is_deleted = FALSE
                         WHERE dau.device_id = d.id AND ugm.group_id = a.target_id)
          ))
      )
);

-- name: ListResolvedAssignmentSourcesForDevice :many
WITH resolved_sources AS (
    SELECT DISTINCT a.source_type, a.source_id, a.mode
    FROM assignments a
    JOIN devices d ON d.id = sqlc.arg(device_id) AND d.is_deleted = FALSE
    WHERE a.is_deleted = FALSE
      AND (
          (a.target_type = 'device' AND a.target_id = d.id)
          OR (a.target_type = 'device_group' AND EXISTS (
              SELECT 1 FROM device_group_members dgm
              JOIN device_groups dg ON dg.id = dgm.group_id AND dg.is_deleted = FALSE
              WHERE dgm.device_id = d.id AND dgm.group_id = a.target_id
          ))
          OR (a.target_type = 'user' AND (
              EXISTS (SELECT 1 FROM device_assigned_users dau
                      JOIN users u ON u.id = dau.user_id AND u.is_deleted = FALSE
                      WHERE dau.device_id = d.id AND dau.user_id = a.target_id)
              OR EXISTS (SELECT 1 FROM device_assigned_groups dag
                         JOIN user_groups ug ON ug.id = dag.group_id AND ug.is_deleted = FALSE
                         JOIN user_group_members ugm ON ugm.group_id = dag.group_id
                         WHERE dag.device_id = d.id AND ugm.user_id = a.target_id)
          ))
          OR (a.target_type = 'user_group' AND (
              EXISTS (SELECT 1 FROM device_assigned_groups dag
                      JOIN user_groups ug ON ug.id = dag.group_id AND ug.is_deleted = FALSE
                      WHERE dag.device_id = d.id AND dag.group_id = a.target_id)
              OR EXISTS (SELECT 1 FROM device_assigned_users dau
                         JOIN users u ON u.id = dau.user_id AND u.is_deleted = FALSE
                         JOIN user_group_members ugm ON ugm.user_id = dau.user_id
                         JOIN user_groups ug ON ug.id = ugm.group_id AND ug.is_deleted = FALSE
                         WHERE dau.device_id = d.id AND ugm.group_id = a.target_id)
          ))
      )
)
SELECT resolved_sources.source_type,
       resolved_sources.source_id,
       resolved_sources.mode,
       COALESCE(sa.name, ss.name, sd.name, sp.name, '') AS source_name,
       COALESCE(sa.description, ss.description, sd.description, sp.description, '') AS source_description,
       COALESCE(us.selected, FALSE) AS selected
FROM resolved_sources
LEFT JOIN actions sa ON resolved_sources.source_type = 'action' AND sa.id = resolved_sources.source_id AND sa.is_deleted = FALSE
LEFT JOIN action_sets ss ON resolved_sources.source_type = 'action_set' AND ss.id = resolved_sources.source_id AND ss.is_deleted = FALSE
LEFT JOIN definitions sd ON resolved_sources.source_type = 'definition' AND sd.id = resolved_sources.source_id AND sd.is_deleted = FALSE
LEFT JOIN compliance_policies sp ON resolved_sources.source_type = 'compliance_policy' AND sp.id = resolved_sources.source_id AND sp.is_deleted = FALSE
LEFT JOIN user_selections us ON us.device_id = sqlc.arg(device_id)
    AND us.source_type = resolved_sources.source_type AND us.source_id = resolved_sources.source_id
WHERE COALESCE(sa.id, ss.id, sd.id, sp.id) IS NOT NULL
ORDER BY resolved_sources.source_type, resolved_sources.source_id, resolved_sources.mode;

-- name: UpsertUserSelection :one
INSERT INTO user_selections (
    id, device_id, source_type, source_id, selected, updated_at, created_by
) VALUES (
    sqlc.arg(id), sqlc.arg(device_id), sqlc.arg(source_type), sqlc.arg(source_id),
    sqlc.arg(selected), sqlc.arg(updated_at), sqlc.arg(created_by)
)
ON CONFLICT (device_id, source_type, source_id) DO UPDATE
SET selected = EXCLUDED.selected,
    updated_at = EXCLUDED.updated_at,
    created_by = EXCLUDED.created_by
RETURNING *;

-- name: UpsertAssignment :one
INSERT INTO assignments (
    id, source_type, source_id, target_type, target_id, mode, created_at, created_by
)
VALUES (
    sqlc.arg(id), sqlc.arg(source_type), sqlc.arg(source_id),
    sqlc.arg(target_type), sqlc.arg(target_id), sqlc.arg(mode),
    sqlc.arg(created_at), sqlc.arg(created_by)
)
ON CONFLICT (source_type, source_id, target_type, target_id) DO UPDATE
SET is_deleted = FALSE,
    mode = EXCLUDED.mode,
    created_at = EXCLUDED.created_at,
    created_by = EXCLUDED.created_by
WHERE assignments.is_deleted = TRUE
RETURNING *;

-- name: SoftDeleteAssignment :one
UPDATE assignments SET is_deleted = TRUE
WHERE id = ? AND is_deleted = FALSE
RETURNING *;
