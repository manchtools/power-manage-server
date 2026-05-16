-- name: GetDeviceByID :one
SELECT * FROM devices_projection
WHERE id = $1 AND is_deleted = FALSE
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL
    OR EXISTS (SELECT 1 FROM device_assigned_users_projection dau WHERE dau.device_id = devices_projection.id AND dau.user_id = sqlc.narg('filter_user_id'))
    OR EXISTS (SELECT 1 FROM device_assigned_groups_projection dag JOIN user_group_members_projection ugm ON ugm.group_id = dag.group_id WHERE dag.device_id = devices_projection.id AND ugm.user_id = sqlc.narg('filter_user_id'))
  );

-- name: IsDeviceDeleted :one
SELECT is_deleted FROM devices_projection WHERE id = $1;

-- name: GetDeviceByFingerprint :one
SELECT * FROM devices_projection
WHERE cert_fingerprint = $1 AND is_deleted = FALSE;

-- name: ListDevices :many
SELECT * FROM devices_projection
WHERE is_deleted = FALSE
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL
    OR EXISTS (SELECT 1 FROM device_assigned_users_projection dau WHERE dau.device_id = devices_projection.id AND dau.user_id = sqlc.narg('filter_user_id'))
    OR EXISTS (SELECT 1 FROM device_assigned_groups_projection dag JOIN user_group_members_projection ugm ON ugm.group_id = dag.group_id WHERE dag.device_id = devices_projection.id AND ugm.user_id = sqlc.narg('filter_user_id'))
  )
ORDER BY last_seen_at DESC
LIMIT $1 OFFSET $2;

-- name: ListDevicesOnline :many
SELECT * FROM devices_projection
WHERE is_deleted = FALSE
  AND last_seen_at > NOW() - INTERVAL '5 minutes'
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL
    OR EXISTS (SELECT 1 FROM device_assigned_users_projection dau WHERE dau.device_id = devices_projection.id AND dau.user_id = sqlc.narg('filter_user_id'))
    OR EXISTS (SELECT 1 FROM device_assigned_groups_projection dag JOIN user_group_members_projection ugm ON ugm.group_id = dag.group_id WHERE dag.device_id = devices_projection.id AND ugm.user_id = sqlc.narg('filter_user_id'))
  )
ORDER BY last_seen_at DESC
LIMIT $1 OFFSET $2;

-- name: ListDevicesOffline :many
SELECT * FROM devices_projection
WHERE is_deleted = FALSE
  AND last_seen_at <= NOW() - INTERVAL '5 minutes'
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL
    OR EXISTS (SELECT 1 FROM device_assigned_users_projection dau WHERE dau.device_id = devices_projection.id AND dau.user_id = sqlc.narg('filter_user_id'))
    OR EXISTS (SELECT 1 FROM device_assigned_groups_projection dag JOIN user_group_members_projection ugm ON ugm.group_id = dag.group_id WHERE dag.device_id = devices_projection.id AND ugm.user_id = sqlc.narg('filter_user_id'))
  )
ORDER BY last_seen_at DESC
LIMIT $1 OFFSET $2;

-- name: CountDevices :one
SELECT COUNT(*) FROM devices_projection
WHERE is_deleted = FALSE
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL
    OR EXISTS (SELECT 1 FROM device_assigned_users_projection dau WHERE dau.device_id = devices_projection.id AND dau.user_id = sqlc.narg('filter_user_id'))
    OR EXISTS (SELECT 1 FROM device_assigned_groups_projection dag JOIN user_group_members_projection ugm ON ugm.group_id = dag.group_id WHERE dag.device_id = devices_projection.id AND ugm.user_id = sqlc.narg('filter_user_id'))
  );

-- name: CountDevicesOnline :one
SELECT COUNT(*) FROM devices_projection
WHERE is_deleted = FALSE
  AND last_seen_at > NOW() - INTERVAL '5 minutes'
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL
    OR EXISTS (SELECT 1 FROM device_assigned_users_projection dau WHERE dau.device_id = devices_projection.id AND dau.user_id = sqlc.narg('filter_user_id'))
    OR EXISTS (SELECT 1 FROM device_assigned_groups_projection dag JOIN user_group_members_projection ugm ON ugm.group_id = dag.group_id WHERE dag.device_id = devices_projection.id AND ugm.user_id = sqlc.narg('filter_user_id'))
  );

-- name: CountDevicesOffline :one
SELECT COUNT(*) FROM devices_projection
WHERE is_deleted = FALSE
  AND last_seen_at <= NOW() - INTERVAL '5 minutes'
  AND (sqlc.narg('filter_user_id')::TEXT IS NULL
    OR EXISTS (SELECT 1 FROM device_assigned_users_projection dau WHERE dau.device_id = devices_projection.id AND dau.user_id = sqlc.narg('filter_user_id'))
    OR EXISTS (SELECT 1 FROM device_assigned_groups_projection dag JOIN user_group_members_projection ugm ON ugm.group_id = dag.group_id WHERE dag.device_id = devices_projection.id AND ugm.user_id = sqlc.narg('filter_user_id'))
  );

-- name: ListDeviceAssignedUserIDsBatch :many
SELECT device_id, user_id FROM device_assigned_users_projection WHERE device_id = ANY(@device_ids::text[]);

-- name: ListDeviceAssignedGroupIDsBatch :many
SELECT device_id, group_id FROM device_assigned_groups_projection WHERE device_id = ANY(@device_ids::text[]);

-- name: GetDevicesWithLabel :many
-- Wave E.4: labels live in the device_labels child table now. The JOIN
-- against (key, value) hits idx_device_labels_key_value for a direct
-- lookup; no more JSONB operator.
SELECT d.* FROM devices_projection d
JOIN device_labels l ON l.device_id = d.id
WHERE d.is_deleted = FALSE
  AND l.key = $1
  AND l.value = $2
ORDER BY d.last_seen_at DESC
LIMIT $3 OFFSET $4;

-- name: ListDeviceLabels :many
-- Wave E.4: returns the (key, value) pairs for a single device.
-- Powers the in-process evaluator's per-device DeviceContext.Labels
-- map and any single-device repo callers that need the typed slice.
SELECT key, value FROM device_labels
WHERE device_id = $1
ORDER BY key;

-- name: ListDeviceLabelsBatch :many
-- Wave E.4: batched per-device label fetch for repo.List and the
-- in-process group evaluator. Single round-trip across the slice of
-- device IDs avoids the N+1 the per-device ListDeviceLabels would
-- have at population time.
SELECT device_id, key, value FROM device_labels
WHERE device_id = ANY(sqlc.arg(device_ids)::TEXT[])
ORDER BY device_id, key;

-- name: ListAllDeviceLabels :many
-- Wave E.4: load every label row in one query for the dyngroupeval
-- queue-drain hot path. Replaces the labels JSONB column that used
-- to come back with each device row.
SELECT device_id, key, value FROM device_labels
ORDER BY device_id, key;

-- name: GetDeviceSyncInterval :one
-- Effective sync interval for a device, in minutes.
--
-- Resolution order matches the previous PL/pgSQL implementation
-- (#95):
--   1. Device-level override (devices_projection.sync_interval_minutes
--      > 0) takes precedence.
--   2. Otherwise, the smallest non-zero sync_interval_minutes across
--      every device-group the device belongs to. The MIN selects the
--      tightest group cadence — operators expect "join two groups,
--      get the more frequent sync".
--   3. If neither sets a value, returns 0 so callers fall back to
--      their default cadence.
--
-- COALESCE chain instead of CASE because both sides can be NULL when
-- a device has no override and is in no group with a sync setting,
-- and the original PL/pgSQL function returned 0 in that case.
WITH device_override AS (
    SELECT CASE WHEN sync_interval_minutes > 0 THEN sync_interval_minutes END AS interval
    FROM devices_projection
    WHERE id = $1::TEXT AND is_deleted = FALSE
),
group_min AS (
    SELECT MIN(CASE WHEN dg.sync_interval_minutes > 0 THEN dg.sync_interval_minutes END) AS interval
    FROM device_groups_projection dg
    JOIN device_group_members_projection dgm ON dgm.group_id = dg.id
    WHERE dgm.device_id = $1::TEXT
      AND dg.is_deleted = FALSE
)
SELECT COALESCE(
    (SELECT interval FROM device_override),
    (SELECT interval FROM group_min),
    0
)::INTEGER AS sync_interval_minutes;

-- name: ListDeviceAssignedUsers :many
SELECT dau.user_id, u.email AS user_email, dau.assigned_at
FROM device_assigned_users_projection dau
JOIN users_projection u ON u.id = dau.user_id AND u.is_deleted = FALSE
WHERE dau.device_id = $1
ORDER BY dau.assigned_at;

-- name: ListDeviceAssignedGroups :many
SELECT dag.group_id, ug.name AS group_name, dag.assigned_at
FROM device_assigned_groups_projection dag
JOIN user_groups_projection ug ON ug.id = dag.group_id AND ug.is_deleted = FALSE
WHERE dag.device_id = $1
ORDER BY dag.assigned_at;

-- name: ListDeviceAssignedUserIDs :many
SELECT user_id FROM device_assigned_users_projection WHERE device_id = $1;

-- name: ListDeviceAssignedGroupIDs :many
SELECT group_id FROM device_assigned_groups_projection WHERE device_id = $1;

-- name: GetDeviceHostnamesByIDs :many
-- Bulk-load hostname for a set of device IDs. Used by handler
-- response loops (e.g. GetDeviceLpsPasswords / GetDeviceLuksKeys)
-- that previously made one GetDeviceByID round-trip per row —
-- audit F008 flagged the resulting N+1 (50 LUKS keys × 2 lookups
-- ≈ 100 sequential round-trips per RPC).
SELECT id, hostname FROM devices_projection
WHERE id = ANY($1::TEXT[]) AND is_deleted = FALSE;

-- ============================================================================
-- Projector listener writes (manchtools/power-manage-server#136).
-- ============================================================================
--
-- Mirrors the deleted PL/pgSQL project_device_event(): every event handler
-- the projector dispatched on (DeviceRegistered, DeviceSeen,
-- DeviceHeartbeat, DeviceCertRenewed, DeviceLabelsUpdated, DeviceLabelSet,
-- DeviceLabelRemoved, DeviceDeleted, DeviceAssigned, DeviceUnassigned,
-- DeviceGroupAssigned, DeviceGroupUnassigned, DeviceSyncIntervalSet) gets a
-- typed sqlc query here so the listener can compose them in Go.
--
-- Tightening vs the PL/pgSQL projector: every UPDATE carries an explicit
-- `WHERE projection_version < $N` guard and uses :execrows so the listener
-- can short-circuit cascades on stale-replay (asymmetric-guard discipline;
-- see role_listener / action_set_listener / device_group_listener for the
-- canonical shape). The PL/pgSQL projector stamped projection_version
-- without a guard — an out-of-order event re-applied later would silently
-- rewind row state.
--
-- DELETEs on the assignment tables (DeviceUnassigned / DeviceGroupUnassigned)
-- carry a `WHERE projection_version <= $N` guard via :execrows so a stale
-- Unassigned replayed after a re-Assign cannot wipe the live row (CR catch
-- on PR #179).

-- name: UpsertDeviceProjection :exec
-- DeviceRegistered handler. ON CONFLICT (id) DO UPDATE re-activates a
-- soft-deleted row by flipping is_deleted=FALSE — mirrors the PL/pgSQL
-- projector's revival semantic (an operator re-enrolling a previously
-- deleted device id gets the row back, preserving the event-sourced
-- timeline). projection_version is unconditionally bumped here because
-- DeviceRegistered is the stream's birthing event; replay safety for
-- subsequent events lives on their per-event guarded UPDATEs.
--
-- Wave E.4: labels moved out of devices_projection into device_labels.
-- Initial-labels writes happen via InsertDeviceLabel in the listener
-- after this upsert, inside the same WithTx.
INSERT INTO devices_projection (
    id, hostname, cert_fingerprint, cert_not_after,
    registered_at, last_seen_at, registration_token_id,
    projection_version
) VALUES ($1, $2, $3, $4, $5, $5, $6, $7)
ON CONFLICT (id) DO UPDATE SET
    hostname              = EXCLUDED.hostname,
    cert_fingerprint      = EXCLUDED.cert_fingerprint,
    cert_not_after        = EXCLUDED.cert_not_after,
    registered_at         = EXCLUDED.registered_at,
    last_seen_at          = EXCLUDED.last_seen_at,
    registration_token_id = EXCLUDED.registration_token_id,
    projection_version    = EXCLUDED.projection_version,
    is_deleted            = FALSE;

-- name: InsertDeviceAssignedUserOnRegister :exec
-- DeviceRegistered cascade — auto-assign the device to the token owner
-- when the payload carries `assigned_user_id`. ON CONFLICT DO NOTHING
-- mirrors the PL/pgSQL projector's idempotency. Wrapped with
-- UpsertDeviceProjection in store.WithTx for cascade atomicity.
INSERT INTO device_assigned_users_projection (
    device_id, user_id, assigned_at, assigned_by, projection_version
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (device_id, user_id) DO NOTHING;

-- name: UpdateDeviceSeenProjection :execrows
-- DeviceSeen handler. COALESCE preserves the existing column value when
-- the payload omits the key (matches PL/pgSQL's
-- `COALESCE(payload, agent_version)` and
-- `COALESCE(NULLIF(payload, ''), hostname)` collapses). The decoder
-- leaves a missing/empty hostname as nil so the SQL COALESCE picks the
-- existing value; same for agent_version. is_deleted=FALSE revives a
-- soft-deleted row when the agent comes back online — mirrors the
-- PL/pgSQL projector. Stale-replay guard via projection_version.
UPDATE devices_projection
SET last_seen_at        = $2,
    agent_version       = COALESCE(sqlc.narg('agent_version')::TEXT, agent_version),
    hostname            = COALESCE(sqlc.narg('hostname')::TEXT, hostname),
    projection_version  = $3,
    is_deleted          = FALSE
WHERE id = $1
  AND projection_version < $3;

-- name: UpdateDeviceHeartbeatProjection :execrows
-- DeviceHeartbeat handler. agent_version preserved when the payload
-- omits the key. Stale-replay guard via projection_version.
UPDATE devices_projection
SET last_seen_at       = $2,
    agent_version      = COALESCE(sqlc.narg('agent_version')::TEXT, agent_version),
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: UpdateDeviceCertRenewedProjection :execrows
-- DeviceCertRenewed handler. cert_not_after preserved when the payload
-- omits the key (mirrors PL/pgSQL `COALESCE(payload, cert_not_after)`).
-- Stale-replay guard via projection_version.
UPDATE devices_projection
SET cert_fingerprint   = $2,
    cert_not_after     = COALESCE(sqlc.narg('cert_not_after')::TIMESTAMPTZ, cert_not_after),
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: AdvanceDeviceProjectionVersion :execrows
-- Wave E.4: parent-row stale-replay guard for the device_labels child
-- table writes. The PL/pgSQL projector folded the version bump into
-- the JSONB UPDATE in one statement; with the column gone, the listener
-- runs this query first, checks the rows-affected, and only proceeds
-- with the child-table change when the bump succeeded.
UPDATE devices_projection
SET projection_version = sqlc.arg(projection_version)
WHERE id = sqlc.arg(id)
  AND projection_version < sqlc.arg(projection_version);

-- name: SetDeviceLabel :exec
-- DeviceLabelSet handler against the device_labels child table (Wave E.4).
-- ON CONFLICT DO UPDATE preserves replay-safety: re-applying the same
-- event lands the same (key, value); a stale event would have already
-- been intercepted by AdvanceDeviceProjectionVersion above.
INSERT INTO device_labels (device_id, key, value)
VALUES (sqlc.arg(device_id), sqlc.arg(key)::TEXT, sqlc.arg(value)::TEXT)
ON CONFLICT (device_id, key) DO UPDATE SET value = EXCLUDED.value;

-- name: RemoveDeviceLabel :exec
-- DeviceLabelRemoved handler. DELETE-with-no-match is silently fine
-- (matches the PL/pgSQL JSONB minus-operator behaviour on a missing key).
DELETE FROM device_labels
WHERE device_id = sqlc.arg(device_id)
  AND key = sqlc.arg(key)::TEXT;

-- name: ClearDeviceLabels :exec
-- Bulk-replace half of DeviceLabelsUpdated. Listener follows this with
-- a series of SetDeviceLabel writes for the new label set, all under
-- the AdvanceDeviceProjectionVersion guard.
DELETE FROM device_labels WHERE device_id = $1;

-- name: SoftDeleteDeviceProjection :execrows
-- DeviceDeleted handler — first half. Returns rows-affected so the
-- listener can SKIP the cascade (assigned-user wipe + assigned-group
-- wipe) when the projection_version guard rejects a stale replay.
-- Otherwise an old DeviceDeleted re-applied by the reconciler would
-- silently nuke a freshly-restored device's assignments.
UPDATE devices_projection
SET is_deleted         = TRUE,
    projection_version = $2
WHERE id = $1
  AND projection_version < $2;

-- name: DeleteDeviceAssignedUsersByDevice :exec
-- DeviceDeleted handler — second half. Wipes every assigned-user row
-- for the deleted device. Wrapped with SoftDeleteDeviceProjection +
-- DeleteDeviceAssignedGroupsByDevice inside store.WithTx for
-- inter-write atomicity.
DELETE FROM device_assigned_users_projection WHERE device_id = $1;

-- name: DeleteDeviceAssignedGroupsByDevice :exec
-- DeviceDeleted handler — third half. Same shape as the assigned-user
-- wipe, scoped to the assigned-groups junction table.
DELETE FROM device_assigned_groups_projection WHERE device_id = $1;

-- name: InsertDeviceAssignedUser :exec
-- DeviceAssigned handler. ON CONFLICT DO NOTHING matches the PL/pgSQL
-- projector's idempotency.
INSERT INTO device_assigned_users_projection (
    device_id, user_id, assigned_at, assigned_by, projection_version
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (device_id, user_id) DO NOTHING;

-- name: DeleteDeviceAssignedUser :execrows
-- DeviceUnassigned handler. Stale-replay DELETE protection: the guard
-- `WHERE projection_version <= $N` ensures a stale Unassigned replayed
-- after a re-Assign cannot wipe the live row — the live row's
-- projection_version was bumped by the re-Assign INSERT, so the
-- stale Unassigned's older sequence_num fails the guard. The :execrows
-- count gives the listener a hook to log/observe stale rejections
-- (CR catch on PR #179 pattern, applied to assignment-table DELETEs).
DELETE FROM device_assigned_users_projection
WHERE device_id = $1
  AND user_id = $2
  AND projection_version <= $3;

-- name: InsertDeviceAssignedGroup :exec
-- DeviceGroupAssigned handler. ON CONFLICT DO NOTHING matches the
-- PL/pgSQL projector's idempotency.
INSERT INTO device_assigned_groups_projection (
    device_id, group_id, assigned_at, assigned_by, projection_version
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (device_id, group_id) DO NOTHING;

-- name: DeleteDeviceAssignedGroup :execrows
-- DeviceGroupUnassigned handler. Same stale-replay guard as
-- DeleteDeviceAssignedUser.
DELETE FROM device_assigned_groups_projection
WHERE device_id = $1
  AND group_id = $2
  AND projection_version <= $3;

-- name: UpdateDeviceSyncIntervalProjection :execrows
-- DeviceSyncIntervalSet handler. The decoder defaults a missing
-- sync_interval_minutes key to 0 (matches the PL/pgSQL COALESCE).
-- Stale-replay guard via projection_version.
UPDATE devices_projection
SET sync_interval_minutes = $2,
    projection_version    = $3
WHERE id = $1
  AND projection_version < $3;
