-- Action Sets queries

-- name: GetActionSetByID :one
SELECT * FROM action_sets_projection
WHERE id = $1 AND is_deleted = FALSE;

-- name: GetActionSetByName :one
SELECT * FROM action_sets_projection
WHERE name = $1 AND is_deleted = FALSE;

-- name: ListActionSets :many
SELECT * FROM action_sets_projection
WHERE is_deleted = FALSE
  AND (sqlc.arg(unassigned_only)::BOOLEAN = FALSE OR NOT EXISTS (
    SELECT 1 FROM definition_members_projection dm WHERE dm.action_set_id = id
  ))
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountActionSets :one
SELECT COUNT(*) FROM action_sets_projection
WHERE is_deleted = FALSE
  AND (sqlc.arg(unassigned_only)::BOOLEAN = FALSE OR NOT EXISTS (
    SELECT 1 FROM definition_members_projection dm WHERE dm.action_set_id = id
  ));

-- Action Set Members queries

-- name: ListActionSetMembers :many
SELECT m.set_id, m.action_id, m.sort_order, m.added_at, m.projection_version,
       a.name AS action_name, a.action_type
FROM action_set_members_projection m
JOIN actions_projection a ON a.id = m.action_id AND a.is_deleted = FALSE
WHERE m.set_id = $1
ORDER BY m.sort_order ASC;

-- name: GetActionSetMember :one
SELECT * FROM action_set_members_projection
WHERE set_id = $1 AND action_id = $2;

-- name: ListActionsInSet :many
SELECT a.* FROM actions_projection a
JOIN action_set_members_projection m ON a.id = m.action_id
WHERE m.set_id = $1 AND a.is_deleted = FALSE
ORDER BY m.sort_order ASC;

-- Projector writes (manchtools/power-manage-server#136). Replaces the
-- deleted PL/pgSQL project_action_set_event() function; called from
-- projectors.ApplyActionSet via projectors.ActionSetListener.
--
-- Tightening vs the PL/pgSQL projector: every UPDATE carries an
-- explicit `WHERE projection_version < $N` guard and uses :execrows
-- so the listener can short-circuit cascades on stale-replay
-- (asymmetric-guard discipline; see role_listener for the canonical
-- shape).

-- name: InsertActionSetProjection :exec
-- ActionSetCreated handler. ON CONFLICT DO NOTHING for replay safety.
-- Schedule defaults to '{"interval_hours": 8}' (the column default
-- mirrors the PL/pgSQL COALESCE fallback for the missing payload key).
INSERT INTO action_sets_projection (
    id, name, description, schedule,
    created_at, updated_at, created_by, projection_version
) VALUES ($1, $2, $3, $4, $5, $5, $6, $7)
ON CONFLICT (id) DO NOTHING;

-- name: RenameActionSetProjection :execrows
-- ActionSetRenamed handler. Stale-replay guard via projection_version.
UPDATE action_sets_projection
SET name              = $2,
    updated_at        = $3,
    projection_version = $4
WHERE id = $1
  AND projection_version < $4;

-- name: UpdateActionSetDescriptionProjection :execrows
-- ActionSetDescriptionUpdated handler. Empty-string description is a
-- valid value (matches the PL/pgSQL `COALESCE(payload, '')` collapse —
-- the listener decoder substitutes '' when the payload key is missing).
UPDATE action_sets_projection
SET description       = $2,
    updated_at        = $3,
    projection_version = $4
WHERE id = $1
  AND projection_version < $4;

-- name: UpdateActionSetScheduleProjection :execrows
-- ActionSetScheduleUpdated handler. The decoder defaults a missing
-- schedule key to the column default '{"interval_hours": 8}' so this
-- query always receives a non-NULL JSONB blob.
UPDATE action_sets_projection
SET schedule          = $2,
    updated_at        = $3,
    projection_version = $4
WHERE id = $1
  AND projection_version < $4;

-- name: InsertActionSetMember :exec
-- ActionSetMemberAdded handler — first half. ON CONFLICT DO NOTHING
-- preserves the PL/pgSQL projector's idempotency under reconciler
-- replays. The composite PK (set_id, action_id) makes this safe.
INSERT INTO action_set_members_projection (
    set_id, action_id, sort_order, added_at, projection_version
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (set_id, action_id) DO NOTHING;

-- name: DeleteActionSetMember :exec
-- ActionSetMemberRemoved handler — first half. Plain DELETE — silently
-- no-op on a miss matches the PL/pgSQL projector's behaviour.
DELETE FROM action_set_members_projection
WHERE set_id = $1
  AND action_id = $2;

-- name: UpdateActionSetMemberSortOrder :execrows
-- ActionSetMemberReordered handler — first half. Per-member
-- projection_version guards the row so a stale reorder cannot clobber
-- a fresher position.
UPDATE action_set_members_projection
SET sort_order        = $3,
    projection_version = $4
WHERE set_id = $1
  AND action_id = $2
  AND projection_version < $4;

-- name: RecountActionSetMembers :execrows
-- ActionSetMemberAdded / ActionSetMemberRemoved handler — second half.
-- Recomputes member_count from the live row count, mirroring the
-- PL/pgSQL `(SELECT COUNT(*) ...)` subquery. Guarded so a stale replay
-- doesn't roll member_count backwards or stamp an old version.
UPDATE action_sets_projection
SET member_count      = (SELECT COUNT(*) FROM action_set_members_projection WHERE set_id = $1),
    updated_at        = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: TouchActionSetUpdatedAt :execrows
-- ActionSetMemberReordered handler — second half. Bumps updated_at +
-- projection_version on the parent set so listing/cache invalidation
-- sees the change. Guarded for stale-replay safety.
UPDATE action_sets_projection
SET updated_at        = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: SoftDeleteActionSetProjection :execrows
-- ActionSetDeleted handler — first half. Returns rows-affected so the
-- listener can SKIP the cascade (members + parent-definition recount +
-- definition_members cleanup) when the projection_version guard
-- rejects a stale replay; otherwise an old ActionSetDeleted re-applied
-- by the reconciler would silently nuke a freshly-restored set's
-- members and decrement live definitions' member_count.
UPDATE action_sets_projection
SET is_deleted        = TRUE,
    updated_at        = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: DeleteActionSetMembersBySet :exec
-- ActionSetDeleted handler — second half. Wipes every member row for
-- the deleted set. Wrapped with SoftDeleteActionSetProjection +
-- DecrementDefinitionMemberCountByActionSet +
-- DeleteDefinitionMembersByActionSet inside store.WithTx for inter-
-- write atomicity.
DELETE FROM action_set_members_projection WHERE set_id = $1;

-- name: DecrementDefinitionMemberCountByActionSet :exec
-- ActionSetDeleted handler — third half. Mirrors the PL/pgSQL
-- subquery `UPDATE definitions_projection SET member_count = member_count - 1
-- WHERE id IN (SELECT definition_id FROM definition_members_projection
-- WHERE action_set_id = ...)`. Runs BEFORE
-- DeleteDefinitionMembersByActionSet — once we delete those member
-- rows the subquery would return empty and the recount would no-op.
-- definitions_projection is still owned by the PL/pgSQL projector
-- (project_definition_event), so no projection_version guard here:
-- doing one would require coordinating versioning across two
-- projector codebases. The cascade itself is gated by
-- SoftDeleteActionSetProjection's :execrows short-circuit upstream.
UPDATE definitions_projection
SET member_count = member_count - 1
WHERE id IN (
    SELECT definition_id FROM definition_members_projection WHERE action_set_id = $1
);

-- name: DeleteDefinitionMembersByActionSet :exec
-- ActionSetDeleted handler — fourth half. Removes every
-- definition_members_projection row that referenced the deleted set
-- so the parent definition's member list no longer surfaces the
-- ghost.
DELETE FROM definition_members_projection WHERE action_set_id = $1;
