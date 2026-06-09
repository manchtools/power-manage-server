-- name: GetUserGroupByID :one
SELECT * FROM user_groups_projection WHERE id = $1 AND is_deleted = FALSE;

-- name: GetUserGroupByName :one
SELECT * FROM user_groups_projection WHERE name = $1 AND is_deleted = FALSE;

-- name: ListUserGroups :many
SELECT * FROM user_groups_projection WHERE is_deleted = FALSE ORDER BY name LIMIT $1 OFFSET $2;

-- name: CountUserGroups :one
SELECT count(*) FROM user_groups_projection WHERE is_deleted = FALSE;

-- name: ListUserGroupMembers :many
SELECT ugm.user_id, u.email, ugm.added_at
FROM user_group_members_projection ugm
JOIN users_projection u ON u.id = ugm.user_id AND u.is_deleted = FALSE
WHERE ugm.group_id = $1
ORDER BY ugm.added_at;

-- name: IsUserInGroup :one
SELECT EXISTS(
    SELECT 1 FROM user_group_members_projection
    WHERE group_id = $1 AND user_id = $2
) AS is_member;

-- name: GetUserGroupRoles :many
SELECT r.* FROM roles_projection r
JOIN user_group_roles_projection ugr ON ugr.role_id = r.id
WHERE ugr.group_id = $1 AND r.is_deleted = FALSE
ORDER BY r.name;

-- name: UserGroupHasRole :one
SELECT EXISTS(
    SELECT 1 FROM user_group_roles_projection
    WHERE group_id = $1 AND role_id = $2
) AS has_role;

-- name: ListUserGroupsForUser :many
SELECT ug.* FROM user_groups_projection ug
JOIN user_group_members_projection ugm ON ugm.group_id = ug.id
WHERE ugm.user_id = $1 AND ug.is_deleted = FALSE
ORDER BY ug.name;

-- name: ListUserGroupMemberIDs :many
SELECT user_id FROM user_group_members_projection WHERE group_id = $1;

-- name: CountGroupsWithRole :one
SELECT count(*) FROM user_group_roles_projection WHERE role_id = $1;

-- name: ListUserIDsWithGroupRole :many
SELECT DISTINCT ugm.user_id
FROM user_group_members_projection ugm
JOIN user_group_roles_projection ugr ON ugr.group_id = ugm.group_id
WHERE ugr.role_id = $1;

-- name: GetUserPermissionsWithGroups :many
SELECT DISTINCT unnest(r.permissions)::TEXT AS permission
FROM roles_projection r
WHERE r.is_deleted = FALSE AND (
    r.id IN (SELECT ur.role_id FROM user_roles_projection ur WHERE ur.user_id = $1)
    OR
    r.id IN (
        SELECT ugr.role_id FROM user_group_roles_projection ugr
        JOIN user_group_members_projection ugm ON ugm.group_id = ugr.group_id
        WHERE ugm.user_id = $1
    )
);

-- name: ListInheritedRolesByUserIDs :many
-- Inherited roles for a specific set of user IDs (typically a
-- single page from the user list). Always pass the IDs you actually
-- need — there is no unscoped variant on purpose, because scanning
-- every user_group_members_projection row is wasteful at scale and
-- previously caused linear-with-system-membership-count cost on
-- every paginated ListUsers call.
SELECT ugm.user_id, r.id AS role_id, r.name AS role_name,
       ug.id AS group_id, ug.name AS group_name
FROM user_group_members_projection ugm
JOIN user_group_roles_projection ugr ON ugr.group_id = ugm.group_id
JOIN roles_projection r ON r.id = ugr.role_id AND r.is_deleted = FALSE
JOIN user_groups_projection ug ON ug.id = ugm.group_id AND ug.is_deleted = FALSE
WHERE ugm.user_id = ANY($1::TEXT[])
ORDER BY ugm.user_id, ug.name, r.name;


-- ============================================================================
-- Projector listener writes (manchtools/power-manage-server#138).
-- ============================================================================
--
-- Mirrors the deleted PL/pgSQL project_user_group_event(): every event
-- handler the projector dispatched on (UserGroupCreated, UserGroupUpdated,
-- UserGroupQueryUpdated, UserGroupMaintenanceWindowSet, UserGroupDeleted,
-- UserGroupMemberAdded, UserGroupMemberRemoved, UserGroupRoleAssigned,
-- UserGroupRoleRevoked, UserGroupMembersRebuilt) gets a typed sqlc query
-- here so the listener can compose them in Go.
--
-- Tightening vs the PL/pgSQL projector: every UPDATE carries an explicit
-- `WHERE projection_version < $N` guard and uses :execrows so the listener
-- can short-circuit cascades on stale-replay (asymmetric-guard discipline;
-- see role_listener for the canonical shape).
--
-- Dynamic-query engine scope: the dynamic-query evaluator
-- (evaluate_dynamic_user_group, validate_user_group_query) STAYS in
-- PL/pgSQL until a later phase. The listener only persists the query
-- column + (re-)enqueues the group via EnqueueDynamicUserGroupEvaluation
-- when is_dynamic flips on; the evaluator runs unchanged inside Postgres.

-- name: InsertUserGroupProjection :exec
-- UserGroupCreated handler. ON CONFLICT DO NOTHING for replay safety —
-- the unique constraint is the primary key (id), so a re-application of
-- UserGroupCreated for the same stream lands as a no-op. The PL/pgSQL
-- projector raised on the second insert; we soften that to the same
-- replay-safe shape every other ported projector uses.
INSERT INTO user_groups_projection (
    id, name, description, member_count,
    created_at, created_by, updated_at, projection_version,
    is_dynamic, dynamic_query
) VALUES ($1, $2, $3, 0, $4, $5, $4, $6, $7, $8)
ON CONFLICT (id) DO NOTHING;

-- name: UpdateUserGroupProjection :execrows
-- UserGroupUpdated handler. Description is COALESCE-preserved when the
-- payload omits it (matches the PL/pgSQL `COALESCE(payload, description)`
-- semantics — pass NULL for description to preserve, the empty string to
-- explicitly blank it). Stale-replay guard via projection_version.
UPDATE user_groups_projection
SET name              = sqlc.arg('name'),
    description       = COALESCE(sqlc.narg('description')::TEXT, description),
    updated_at        = sqlc.arg('updated_at'),
    projection_version = sqlc.arg('projection_version')
WHERE id = sqlc.arg('id')
  AND projection_version < sqlc.arg('projection_version');

-- name: UpdateUserGroupQueryProjection :one
-- UserGroupQueryUpdated handler — first half. Persists the dynamic-
-- query toggle + query string. Stale-replay guard via projection_version.
-- Returns the previous is_dynamic value so the listener can tell a
-- true static→dynamic flip from a steady-state dynamic-query edit.
-- Only the flip should trigger the cascade (member wipe + count reset
-- + re-enqueue); editing the query of an already-dynamic group must
-- preserve the live member set (CR catch on PR #174).
--
-- A stale event (projection_version >= current) returns sql.ErrNoRows
-- — the listener treats that as "skip cascade" via :one's no-row
-- error.
WITH prev AS (
    SELECT ug.id AS prev_id, ug.is_dynamic AS prev_is_dynamic
    FROM user_groups_projection ug
    WHERE ug.id = $1
), bumped AS (
    UPDATE user_groups_projection ug
    SET is_dynamic         = $2,
        dynamic_query      = $3,
        updated_at         = $4,
        projection_version = $5
    WHERE ug.id = $1
      AND ug.projection_version < $5
    RETURNING ug.id AS bumped_id
)
SELECT prev.prev_is_dynamic FROM prev JOIN bumped ON bumped.bumped_id = prev.prev_id;

-- name: ClaimUserGroupForRoleMutation :execrows
-- Atomic guard for UserGroupRoleAssigned / UserGroupRoleRevoked.
-- Bumps projection_version only when the parent group exists, is not
-- soft-deleted, and the event is newer than the current version.
-- Roles can be assigned to BOTH static and dynamic groups, so unlike
-- ClaimUserGroupForMembership this guard does not check is_dynamic.
--
-- Returns n=1 when the listener may proceed with the role-table
-- mutation, n=0 when the event must be skipped. Doing the version
-- check BEFORE the role INSERT/DELETE prevents stale replays from
-- silently granting or revoking inherited permissions (CR catch on
-- PR #174).
UPDATE user_groups_projection
SET updated_at         = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3
  AND is_deleted = FALSE;

-- name: ResetUserGroupMemberCount :exec
-- UserGroupQueryUpdated handler — flip-to-dynamic cascade half. Mirrors
-- the PL/pgSQL `UPDATE user_groups_projection SET member_count = 0 WHERE
-- id = ...` that runs after wiping the static-member rows. No
-- projection_version guard here: the gate lives upstream on
-- UpdateUserGroupQueryProjection's :execrows, so a stale event can't
-- reach this statement.
UPDATE user_groups_projection
SET member_count = 0
WHERE id = $1;

-- name: WipeUserGroupMembers :exec
-- UserGroupQueryUpdated (flip-to-dynamic) and UserGroupMembersRebuilt
-- handler. The dynamic-query evaluator owns the member set after the
-- flip, so any static rows left behind would surface as ghost members.
DELETE FROM user_group_members_projection WHERE group_id = $1;

-- name: EnqueueDynamicUserGroupEvaluation :exec
-- UserGroupCreated (when is_dynamic) and UserGroupQueryUpdated (when
-- flip-to-dynamic) handler. Mirrors the PL/pgSQL `INSERT INTO
-- dynamic_user_group_evaluation_queue ... ON CONFLICT (group_id) DO
-- UPDATE SET queued_at = clock_timestamp()` so a re-queue refreshes the
-- queued_at timestamp. The reason text is the caller-provided trigger
-- ('group_created' or 'query_updated') for operator visibility into
-- evaluator-queue churn.
INSERT INTO dynamic_user_group_evaluation_queue (group_id, reason)
VALUES ($1, $2)
ON CONFLICT (group_id) DO UPDATE SET queued_at = clock_timestamp();

-- name: EnqueueAllDynamicUserGroups :exec
-- Wave F: enqueues every non-deleted dynamic user group for re-eval.
-- Used by user-attribute projector listeners after a column change
-- (reason='user_<id>_changed') and by the periodic safety-net sweep
-- (reason='periodic_full_evaluation'). Replaces the PL/pgSQL
-- queue_dynamic_user_groups_on_user_change + queue_all_dynamic_groups
-- helpers.
INSERT INTO dynamic_user_group_evaluation_queue (group_id, queued_at, reason)
SELECT id, clock_timestamp(), sqlc.arg(reason)::TEXT
FROM user_groups_projection
WHERE is_dynamic = TRUE AND is_deleted = FALSE
ON CONFLICT (group_id) DO UPDATE SET
    queued_at = clock_timestamp(),
    reason = EXCLUDED.reason;

-- name: UpdateUserGroupMaintenanceWindowProjection :execrows
-- UserGroupMaintenanceWindowSet handler. Mirrors the PL/pgSQL
-- `COALESCE(payload, '{}'::JSONB)`: the listener decoder substitutes
-- '{}' when the payload key is missing so this query always receives a
-- non-NULL JSONB blob. Stale-replay guard via projection_version.
UPDATE user_groups_projection
SET maintenance_window = $2,
    updated_at         = $3,
    projection_version = $4
WHERE id = $1
  AND projection_version < $4;

-- name: SoftDeleteUserGroupProjection :execrows
-- UserGroupDeleted handler — first half. Returns rows-affected so the
-- listener can SKIP the cascade (scim_group_mapping cleanup, member
-- wipe, role-assignment wipe, dynamic-queue cleanup) when the
-- projection_version guard rejects a stale replay; otherwise an old
-- UserGroupDeleted re-applied by the reconciler would silently nuke a
-- freshly-restored group's members + role assignments + downstream
-- SCIM mapping.
UPDATE user_groups_projection
SET is_deleted         = TRUE,
    updated_at         = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: DeleteScimGroupMappingsByUserGroup :exec
-- UserGroupDeleted handler — second half. Mirrors the PL/pgSQL
-- `DELETE FROM scim_group_mapping_projection WHERE user_group_id = ...`
-- that ran BEFORE the soft-delete UPDATE in the projector. Order in the
-- listener is reversed (soft-delete first, gated cleanup second) so the
-- :execrows short-circuit can skip the unguarded DELETE on stale
-- replay. scim_group_mapping_projection is owned by the SCIM-group-
-- mapping projector (already ported); no projection_version guard is
-- viable across the two listeners.
DELETE FROM scim_group_mapping_projection WHERE user_group_id = $1;

-- name: DeleteUserGroupMembersByGroup :exec
-- UserGroupDeleted handler — third half. Wipes every static member row
-- for the deleted group. Wrapped with SoftDeleteUserGroupProjection +
-- the other cascade halves inside store.WithTx for inter-write
-- atomicity.
DELETE FROM user_group_members_projection WHERE group_id = $1;

-- name: DeleteUserGroupRolesByGroup :exec
-- UserGroupDeleted handler — fourth half. Wipes every role assignment
-- for the deleted group so future ListUserGroupRoles calls don't
-- surface ghosts.
DELETE FROM user_group_roles_projection WHERE group_id = $1;

-- name: DeleteDynamicUserGroupEvaluationQueueRow :exec
-- UserGroupDeleted handler — fifth half. Removes the queue entry so the
-- next dynamic-evaluation pass doesn't try to reconcile a deleted
-- group.
DELETE FROM dynamic_user_group_evaluation_queue WHERE group_id = $1;

-- name: DeleteDynamicUserGroupQueueBefore :exec
-- Wave C.3: clear queue entries queued before `before_ts`. Same race
-- guard as DeleteDynamicDeviceGroupQueueBefore — re-queue during eval
-- survives so the next drain pass re-evaluates.
DELETE FROM dynamic_user_group_evaluation_queue
WHERE group_id = sqlc.arg(group_id)::TEXT
  AND queued_at <= sqlc.arg(before_ts)::TIMESTAMPTZ;

-- name: ListDynamicUserGroupQueueBatch :many
-- Wave C.4: returns the next batch of queued user-group IDs for the
-- in-process drain loop, oldest first. Replaces the SELECT inside the
-- PL/pgSQL evaluate_queued_dynamic_user_groups function.
SELECT group_id FROM dynamic_user_group_evaluation_queue
ORDER BY queued_at
LIMIT $1;

-- name: HasDynamicUserGroupQueueEntries :one
-- Wave C.4: cheap EXISTS probe for the `more` flag — same semantic as
-- HasDynamicDeviceGroupQueueEntries.
SELECT EXISTS (SELECT 1 FROM dynamic_user_group_evaluation_queue LIMIT 1)::BOOLEAN AS has_more;

-- name: ListUsersForDynamicEvaluation :many
-- All non-deleted users' fields the user-group evaluator reads (matches
-- the 7 parameters evaluate_user_condition takes plus id for membership
-- writes).
SELECT id, email, disabled, totp_enabled, has_password,
       display_name, preferred_username, locale
FROM users_projection
WHERE is_deleted = FALSE;

-- name: ClaimUserGroupForMembership :execrows
-- Atomic guard for the three member-mutation events
-- (UserGroupMemberAdded, UserGroupMemberRemoved, UserGroupMembersRebuilt).
-- The UPDATE bumps updated_at + projection_version only when ALL of:
--
--   1. The group exists (id matches).
--   2. The group is NOT soft-deleted (a member event replayed after a
--      Deleted must not bring rows back).
--   3. The group is NOT dynamic (the dynamic-query evaluator owns the
--      member set; explicit member events are no-ops there — mirrors
--      the PL/pgSQL `IF NOT EXISTS (... is_dynamic = TRUE)` early-out).
--   4. The event is newer than the current projection_version
--      (asymmetric-guard discipline; CR catch on PR #174).
--
-- Returns n=1 when the listener may proceed with the membership-table
-- mutation, n=0 when the event must be skipped. Encoding all four
-- short-circuit reasons in one query keeps the listener side
-- branch-free and — crucially — makes the version check happen
-- BEFORE any child-row mutation, so a stale event cannot recreate a
-- deleted membership row or wipe a live one.
UPDATE user_groups_projection
SET updated_at         = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3
  AND is_deleted = FALSE
  AND is_dynamic = FALSE;

-- name: RecountUserGroupMembers :exec
-- Recompute member_count from the live row count after the listener
-- has applied a membership mutation. Run in the same transaction as
-- ClaimUserGroupForMembership + the INSERT/DELETE so the parent row
-- is never observed with a stale count. No projection_version guard
-- here: the Claim above already stamped the version, so a recount
-- without re-stamping cannot regress.
UPDATE user_groups_projection
SET member_count = (
    SELECT COUNT(*) FROM user_group_members_projection WHERE group_id = $1
)
WHERE id = $1;

-- name: InsertUserGroupMember :exec
-- UserGroupMemberAdded handler — first half. ON CONFLICT DO NOTHING
-- preserves the PL/pgSQL projector's idempotency under reconciler
-- replays. The composite PK (group_id, user_id) makes this safe.
INSERT INTO user_group_members_projection (
    group_id, user_id, added_at, added_by, projection_version
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (group_id, user_id) DO NOTHING;

-- name: DeleteUserGroupMember :exec
-- UserGroupMemberRemoved handler — first half. Plain DELETE — silently
-- no-op on a miss matches the PL/pgSQL projector's behaviour.
DELETE FROM user_group_members_projection
WHERE group_id = $1
  AND user_id = $2;

-- name: InsertUserGroupRole :exec
-- UserGroupRoleAssigned handler. Scope-aware shape symmetric with
-- InsertUserRoleProjection — see that query for the paired-or-
-- neither + ON CONFLICT semantics. server #7 S2.
INSERT INTO user_group_roles_projection (
    group_id, role_id, scope_kind, scope_id,
    assigned_at, assigned_by, projection_version
) VALUES (
    $1, $2,
    sqlc.narg('scope_kind')::TEXT,
    sqlc.narg('scope_id')::TEXT,
    $3, $4, $5
)
ON CONFLICT DO NOTHING;

-- name: DeleteUserGroupRole :exec
-- UserGroupRoleRevoked handler — 4-tuple revoke grammar.
-- IS NOT DISTINCT FROM gives NULL-aware equality. See
-- DeleteUserRoleProjection for the dispatch contract.
DELETE FROM user_group_roles_projection
WHERE group_id = $1
  AND role_id = $2
  AND scope_kind IS NOT DISTINCT FROM sqlc.narg('scope_kind')::TEXT
  AND scope_id   IS NOT DISTINCT FROM sqlc.narg('scope_id')::TEXT;
