-- Device Groups queries

-- name: GetDeviceGroupByID :one
SELECT * FROM device_groups_projection
WHERE id = $1 AND is_deleted = FALSE;

-- name: GetDeviceGroupByName :one
SELECT * FROM device_groups_projection
WHERE name = $1 AND is_deleted = FALSE;

-- name: ListDeviceGroups :many
SELECT * FROM device_groups_projection
WHERE is_deleted = FALSE
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountDeviceGroups :one
SELECT COUNT(*) FROM device_groups_projection
WHERE is_deleted = FALSE;

-- Device Group Members queries

-- name: ListDeviceGroupMembers :many
SELECT m.group_id, m.device_id, m.added_at, m.projection_version,
       d.hostname, d.agent_version, d.last_seen_at
FROM device_group_members_projection m
JOIN devices_projection d ON d.id = m.device_id AND d.is_deleted = FALSE
WHERE m.group_id = $1
ORDER BY m.added_at ASC;

-- name: GetDeviceGroupMember :one
SELECT * FROM device_group_members_projection
WHERE group_id = $1 AND device_id = $2;

-- name: ListDevicesInGroup :many
SELECT d.* FROM devices_projection d
JOIN device_group_members_projection m ON d.id = m.device_id
WHERE m.group_id = $1 AND d.is_deleted = FALSE
ORDER BY d.hostname ASC;

-- name: ListGroupsForDevice :many
SELECT g.* FROM device_groups_projection g
JOIN device_group_members_projection m ON g.id = m.group_id
WHERE m.device_id = $1 AND g.is_deleted = FALSE
ORDER BY g.name ASC;

-- Dynamic Group queries

-- name: ListDynamicDeviceGroups :many
SELECT * FROM device_groups_projection
WHERE is_dynamic = TRUE AND is_deleted = FALSE
ORDER BY created_at DESC;

-- name: GetDynamicGroupsNeedingEvaluation :many
SELECT g.* FROM device_groups_projection g
JOIN dynamic_group_evaluation_queue q ON g.id = q.group_id
WHERE g.is_deleted = FALSE
ORDER BY q.queued_at ASC
LIMIT $1;

-- name: ValidateDynamicQuery :one
SELECT COALESCE(validate_dynamic_query($1), '')::TEXT AS error_message;

-- name: EvaluateDynamicGroup :exec
SELECT evaluate_dynamic_group($1);

-- name: EvaluateQueuedDynamicGroups :one
SELECT evaluate_queued_dynamic_groups() AS evaluated_count;

-- name: QueueAllDynamicGroups :exec
SELECT queue_all_dynamic_groups();

-- name: CountMatchingDevicesForQuery :one
SELECT COUNT(*) FROM devices_projection
WHERE is_deleted = FALSE
AND evaluate_dynamic_query_v2(id, labels, $1) = TRUE;

-- ============================================================================
-- Projector listener writes (manchtools/power-manage-server#136).
-- ============================================================================
--
-- Mirrors the deleted PL/pgSQL project_device_group_event(): every event
-- handler the projector dispatched on (DeviceGroupCreated,
-- DeviceGroupRenamed, DeviceGroupDescriptionUpdated,
-- DeviceGroupQueryUpdated, DeviceGroupSyncIntervalSet,
-- DeviceGroupMaintenanceWindowSet, DeviceGroupMemberAdded /
-- DeviceAddedToGroup, DeviceGroupMemberRemoved / DeviceRemovedFromGroup,
-- DeviceGroupDeleted) gets a typed sqlc query here so the listener can
-- compose them in Go.
--
-- Tightening vs the PL/pgSQL projector: every UPDATE carries an explicit
-- `WHERE projection_version < $N` guard and uses :execrows so the listener
-- can short-circuit cascades on stale-replay (asymmetric-guard discipline;
-- see role_listener / action_set_listener for the canonical shape).
--
-- Dynamic-query engine scope: the dynamic-query evaluator
-- (evaluate_dynamic_group, validate_dynamic_query) STAYS in PL/pgSQL
-- until a later phase. The listener only persists the query column +
-- (re-)enqueues the group via EnqueueDynamicDeviceGroupEvaluation when
-- is_dynamic flips on; the evaluator runs unchanged inside Postgres.

-- name: InsertDeviceGroupProjection :exec
-- DeviceGroupCreated handler. ON CONFLICT DO NOTHING for replay safety —
-- the unique constraint is the primary key (id), so a re-application of
-- DeviceGroupCreated for the same stream lands as a no-op. The PL/pgSQL
-- projector raised on the second insert; we soften that to the same
-- replay-safe shape every other ported projector uses.
INSERT INTO device_groups_projection (
    id, name, description, is_dynamic, dynamic_query,
    created_at, created_by, projection_version
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO NOTHING;

-- name: RenameDeviceGroupProjection :execrows
-- DeviceGroupRenamed handler. Stale-replay guard via projection_version.
UPDATE device_groups_projection
SET name              = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: UpdateDeviceGroupDescriptionProjection :execrows
-- DeviceGroupDescriptionUpdated handler. Empty-string description is a
-- valid value (matches the PL/pgSQL `COALESCE(payload, '')` collapse —
-- the listener decoder substitutes '' when the payload key is missing).
UPDATE device_groups_projection
SET description       = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: UpdateDeviceGroupQueryProjection :one
-- DeviceGroupQueryUpdated handler — first half. Persists the dynamic-
-- query toggle + query string. Stale-replay guard via projection_version.
-- Returns the previous is_dynamic value so the listener can tell a
-- true static→dynamic flip from a steady-state dynamic-query edit.
-- Only the flip should trigger the cascade (member wipe + count reset
-- + re-enqueue); editing the query of an already-dynamic group must
-- preserve the live evaluator-owned member set (sibling fix to the
-- CR catch on the user_group port, PR #174).
--
-- A stale event (projection_version >= current) returns sql.ErrNoRows
-- via pgx — the listener treats that as "skip cascade".
WITH prev AS (
    SELECT dg.id AS prev_id, dg.is_dynamic AS prev_is_dynamic
    FROM device_groups_projection dg
    WHERE dg.id = $1
), bumped AS (
    UPDATE device_groups_projection dg
    SET is_dynamic         = $2,
        dynamic_query      = $3,
        projection_version = $4
    WHERE dg.id = $1
      AND dg.projection_version < $4
    RETURNING dg.id AS bumped_id
)
SELECT prev.prev_is_dynamic FROM prev JOIN bumped ON bumped.bumped_id = prev.prev_id;

-- name: UpdateDeviceGroupSyncIntervalProjection :execrows
-- DeviceGroupSyncIntervalSet handler. The decoder defaults a missing
-- sync_interval_minutes key to 0 (matches the PL/pgSQL COALESCE).
UPDATE device_groups_projection
SET sync_interval_minutes = $2,
    projection_version    = $3
WHERE id = $1
  AND projection_version < $3;

-- name: UpdateDeviceGroupMaintenanceWindowProjection :execrows
-- DeviceGroupMaintenanceWindowSet handler. Mirrors the PL/pgSQL
-- `COALESCE(payload, '{}'::JSONB)`: the listener decoder substitutes
-- '{}' when the payload key is missing so this query always receives a
-- non-NULL JSONB blob. Stale-replay guard via projection_version.
UPDATE device_groups_projection
SET maintenance_window = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: ResetDeviceGroupMemberCount :exec
-- DeviceGroupQueryUpdated handler — flip-to-dynamic cascade half. Mirrors
-- the PL/pgSQL `UPDATE device_groups_projection SET member_count = 0
-- WHERE id = ...` that runs after wiping the static-member rows. No
-- projection_version guard here: the gate lives upstream on
-- UpdateDeviceGroupQueryProjection's :execrows, so a stale event can't
-- reach this statement.
UPDATE device_groups_projection
SET member_count = 0
WHERE id = $1;

-- name: WipeDeviceGroupMembers :exec
-- DeviceGroupQueryUpdated (flip-to-dynamic) handler. The dynamic-query
-- evaluator owns the member set after the flip, so any static rows
-- left behind would surface as ghost members.
DELETE FROM device_group_members_projection WHERE group_id = $1;

-- name: EnqueueDynamicDeviceGroupEvaluation :exec
-- DeviceGroupCreated (when is_dynamic) and DeviceGroupQueryUpdated
-- (when flip-to-dynamic) handler. Mirrors the PL/pgSQL `INSERT INTO
-- dynamic_group_evaluation_queue ... ON CONFLICT (group_id) DO UPDATE
-- SET queued_at = clock_timestamp()` so a re-queue refreshes the
-- queued_at timestamp. The reason text is the caller-provided trigger
-- ('group_created' or 'query_updated') for operator visibility into
-- evaluator-queue churn.
INSERT INTO dynamic_group_evaluation_queue (group_id, queued_at, reason)
VALUES ($1, clock_timestamp(), $2)
ON CONFLICT (group_id) DO UPDATE SET queued_at = clock_timestamp();

-- name: SoftDeleteDeviceGroupProjection :execrows
-- DeviceGroupDeleted handler — first half. Returns rows-affected so the
-- listener can SKIP the cascade (member wipe + dynamic-queue cleanup)
-- when the projection_version guard rejects a stale replay; otherwise
-- an old DeviceGroupDeleted re-applied by the reconciler would silently
-- nuke a freshly-restored group's members.
UPDATE device_groups_projection
SET is_deleted        = TRUE,
    projection_version = $2
WHERE id = $1
  AND projection_version < $2;

-- name: DeleteDeviceGroupMembersByGroup :exec
-- DeviceGroupDeleted handler — second half. Wipes every member row for
-- the deleted group. Wrapped with SoftDeleteDeviceGroupProjection +
-- DeleteDynamicDeviceGroupEvaluationQueueRow inside store.WithTx for
-- inter-write atomicity.
DELETE FROM device_group_members_projection WHERE group_id = $1;

-- name: DeleteDynamicDeviceGroupEvaluationQueueRow :exec
-- DeviceGroupDeleted handler — third half. Removes the queue entry so
-- the next dynamic-evaluation pass doesn't try to reconcile a deleted
-- group.
DELETE FROM dynamic_group_evaluation_queue WHERE group_id = $1;

-- name: ClaimDeviceGroupForMembership :execrows
-- Atomic guard for the four member-mutation events
-- (DeviceGroupMemberAdded, DeviceAddedToGroup, DeviceGroupMemberRemoved,
-- DeviceRemovedFromGroup). Bumps projection_version only when ALL of:
--
--   1. The group exists.
--   2. The group is NOT soft-deleted (a member event replayed after
--      a Deleted must not bring rows back).
--   3. The group is NOT dynamic (the dynamic-query evaluator owns
--      the member set; explicit member events are no-ops there —
--      mirrors the PL/pgSQL `IF NOT EXISTS (... is_dynamic = TRUE)`
--      early-out).
--   4. The event is newer than the current projection_version.
--
-- Returns n=1 when the listener may proceed with the membership
-- mutation, n=0 when the event must be skipped. Doing the version
-- check BEFORE any child-row mutation prevents the stale-replay
-- holes CR caught on the user_group port (PR #174 / fingerprint
-- "Guard stale member replays before touching..."): without this
-- guard a stale MemberAdded after a Removed would recreate the
-- deleted membership row, and a stale MemberRemoved would delete
-- a live one.
UPDATE device_groups_projection
SET projection_version = $2
WHERE id = $1
  AND projection_version < $2
  AND is_deleted = FALSE
  AND is_dynamic = FALSE;

-- name: InsertDeviceGroupMember :exec
-- DeviceGroupMemberAdded / DeviceAddedToGroup handler — second half.
-- ON CONFLICT DO NOTHING preserves the PL/pgSQL projector's idempotency
-- under reconciler replays. The composite PK (group_id, device_id)
-- makes this safe.
INSERT INTO device_group_members_projection (
    group_id, device_id, added_at, projection_version
) VALUES ($1, $2, $3, $4)
ON CONFLICT (group_id, device_id) DO NOTHING;

-- name: DeleteDeviceGroupMember :exec
-- DeviceGroupMemberRemoved / DeviceRemovedFromGroup handler — second
-- half. Plain DELETE — silently no-op on a miss matches the PL/pgSQL
-- projector's behaviour.
DELETE FROM device_group_members_projection
WHERE group_id = $1
  AND device_id = $2;

-- name: RecountDeviceGroupMembers :exec
-- Recompute member_count from the live row count after the listener
-- has applied a membership mutation. Run in the same transaction as
-- ClaimDeviceGroupForMembership + the INSERT/DELETE so the parent
-- row is never observed with a stale count. No projection_version
-- guard here: the Claim above already stamped the version.
UPDATE device_groups_projection
SET member_count = (SELECT COUNT(*) FROM device_group_members_projection WHERE group_id = $1)
WHERE id = $1;
