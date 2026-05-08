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

-- name: ValidateUserGroupQuery :one
SELECT COALESCE(validate_user_group_query($1), '')::TEXT AS error_message;

-- name: EvaluateDynamicUserGroup :exec
SELECT evaluate_dynamic_user_group($1);

-- name: EvaluateQueuedDynamicUserGroups :one
SELECT evaluate_queued_dynamic_user_groups() AS evaluated_count;

-- name: CountMatchingUsersForQuery :one
SELECT COUNT(*) FROM users_projection
WHERE is_deleted = FALSE
AND evaluate_dynamic_user_query(email, disabled, totp_enabled, has_password, display_name, preferred_username, locale, $1) = TRUE;

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

-- name: UpdateUserGroupQueryProjection :execrows
-- UserGroupQueryUpdated handler — first half. Persists the dynamic-
-- query toggle + query string. Stale-replay guard via projection_version.
-- The listener follows up with WipeUserGroupMembersOnDynamicFlip +
-- ResetUserGroupMemberCount + EnqueueDynamicUserGroupEvaluation when the
-- group flips to dynamic, gated by this UPDATE's :execrows count.
UPDATE user_groups_projection
SET is_dynamic         = $2,
    dynamic_query      = $3,
    updated_at         = $4,
    projection_version = $5
WHERE id = $1
  AND projection_version < $5;

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
-- UserGroupRoleAssigned handler. ON CONFLICT DO NOTHING preserves the
-- PL/pgSQL projector's idempotency under reconciler replays. The
-- composite PK (group_id, role_id) makes this safe. No parent-row
-- update — role assignments are independent of member_count.
INSERT INTO user_group_roles_projection (
    group_id, role_id, assigned_at, assigned_by, projection_version
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (group_id, role_id) DO NOTHING;

-- name: DeleteUserGroupRole :exec
-- UserGroupRoleRevoked handler. Plain DELETE — silently no-op on a
-- miss matches the PL/pgSQL projector's behaviour.
DELETE FROM user_group_roles_projection
WHERE group_id = $1
  AND role_id = $2;
