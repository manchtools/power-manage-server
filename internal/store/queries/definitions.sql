-- Definitions queries (collection of action sets)

-- name: GetDefinitionByID :one
SELECT * FROM definitions_projection
WHERE id = $1 AND is_deleted = FALSE;

-- name: GetDefinitionByName :one
SELECT * FROM definitions_projection
WHERE name = $1 AND is_deleted = FALSE;

-- name: ListDefinitions :many
SELECT * FROM definitions_projection
WHERE is_deleted = FALSE
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountDefinitions :one
SELECT COUNT(*) FROM definitions_projection
WHERE is_deleted = FALSE;

-- Definition Members queries

-- name: ListDefinitionMembers :many
SELECT m.definition_id, m.action_set_id, m.sort_order, m.added_at, m.projection_version,
       s.name AS action_set_name
FROM definition_members_projection m
JOIN action_sets_projection s ON s.id = m.action_set_id AND s.is_deleted = FALSE
WHERE m.definition_id = $1
ORDER BY m.sort_order ASC;

-- name: GetDefinitionMember :one
SELECT * FROM definition_members_projection
WHERE definition_id = $1 AND action_set_id = $2;

-- name: ListActionSetsInDefinition :many
SELECT s.* FROM action_sets_projection s
JOIN definition_members_projection m ON s.id = m.action_set_id
WHERE m.definition_id = $1 AND s.is_deleted = FALSE
ORDER BY m.sort_order ASC;

-- ============================================================================
-- Projector listener writes (manchtools/power-manage-server#136).
-- ============================================================================
--
-- Mirrors the deleted PL/pgSQL project_definition_event(). Eight event
-- types: Created, Renamed, DescriptionUpdated, ScheduleUpdated,
-- MemberAdded, MemberRemoved, MemberReordered, Deleted. The Created
-- event is shared with project_action_event — when the payload carries
-- `action_type` the action projector synthesises an actions_projection
-- row and the definition projector no-ops; otherwise the definition
-- projector inserts a definitions_projection row and the action
-- projector no-ops. The Go listener (action_listener.go) owns BOTH
-- stream types so the dispatch is single-pass.
--
-- Tightening vs the PL/pgSQL projector: every UPDATE on
-- definitions_projection carries an explicit `WHERE projection_version < $N`
-- guard and uses :execrows so the listener can short-circuit cascades
-- on stale-replay (asymmetric-guard discipline; see role_listener /
-- action_set_listener for the canonical shape).
--
-- Claim-first guard: the three member-mutation events
-- (DefinitionMemberAdded, DefinitionMemberRemoved, DefinitionMemberReordered)
-- all run ClaimDefinitionForMembership BEFORE touching
-- definition_members_projection. The Claim guard bumps
-- definitions_projection.projection_version only when the definition
-- exists, is alive, and the event is newer; the listener short-circuits
-- on n == 0. Doing the version check BEFORE the membership INSERT/
-- DELETE/UPDATE prevents stale replays from silently resurrecting
-- removed members or rolling back fresher reorders — the same hazard
-- the user_group port (PR #174) had to fix retroactively.

-- name: InsertDefinitionProjection :exec
-- DefinitionCreated handler — definitions_projection branch (taken
-- when the payload OMITS action_type). ON CONFLICT DO NOTHING for
-- replay safety. Schedule defaults to '{"interval_hours": 8}' (column
-- default mirrors the PL/pgSQL COALESCE fallback for the missing
-- payload key).
INSERT INTO definitions_projection (
    id, name, description, schedule,
    created_at, updated_at, created_by, projection_version
) VALUES (
    sqlc.arg('id'),
    sqlc.arg('name'),
    sqlc.arg('description'),
    sqlc.arg('schedule'),
    sqlc.arg('created_at'),
    sqlc.arg('updated_at'),
    sqlc.arg('created_by'),
    sqlc.arg('projection_version')
)
ON CONFLICT (id) DO NOTHING;

-- name: RenameDefinitionProjection :execrows
-- DefinitionRenamed handler. Stale-replay guard via projection_version.
UPDATE definitions_projection
SET name              = $2,
    updated_at        = $3,
    projection_version = $4
WHERE id = $1
  AND projection_version < $4;

-- name: UpdateDefinitionDescriptionProjection :execrows
-- DefinitionDescriptionUpdated handler. Empty-string description is a
-- valid value (matches the PL/pgSQL `COALESCE(payload, '')` collapse —
-- the listener decoder substitutes '' when the payload key is missing).
UPDATE definitions_projection
SET description       = $2,
    updated_at        = $3,
    projection_version = $4
WHERE id = $1
  AND projection_version < $4;

-- name: UpdateDefinitionScheduleProjection :execrows
-- DefinitionScheduleUpdated handler. Decoder defaults a missing
-- schedule key to the column default '{"interval_hours": 8}' so this
-- query always receives a non-NULL JSONB blob.
UPDATE definitions_projection
SET schedule          = $2,
    updated_at        = $3,
    projection_version = $4
WHERE id = $1
  AND projection_version < $4;

-- name: ClaimDefinitionForMembership :execrows
-- Atomic guard for the three member-mutation events
-- (DefinitionMemberAdded, DefinitionMemberRemoved, DefinitionMemberReordered).
-- Bumps updated_at + projection_version only when the parent
-- definition exists, is not soft-deleted, and the event is newer than
-- the current projection_version.
--
-- Returns n=1 when the listener may proceed with the membership
-- mutation, n=0 when the event must be skipped. Doing the version
-- check BEFORE any child-row mutation prevents the stale-replay holes
-- CR caught on the user_group port (PR #174): without this guard a
-- stale DefinitionMemberAdded after a Removed would recreate the
-- removed membership row, and a stale Removed would delete a live
-- one.
UPDATE definitions_projection
SET updated_at         = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3
  AND is_deleted = FALSE;

-- name: InsertDefinitionMember :exec
-- DefinitionMemberAdded handler — second half. ON CONFLICT DO NOTHING
-- preserves the PL/pgSQL projector's idempotency under reconciler
-- replays. The composite PK (definition_id, action_set_id) makes this
-- safe.
INSERT INTO definition_members_projection (
    definition_id, action_set_id, sort_order, added_at, projection_version
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (definition_id, action_set_id) DO NOTHING;

-- name: DeleteDefinitionMember :exec
-- DefinitionMemberRemoved handler — second half. Plain DELETE —
-- silently no-op on a miss matches the PL/pgSQL projector's behaviour.
DELETE FROM definition_members_projection
WHERE definition_id = $1
  AND action_set_id = $2;

-- name: UpdateDefinitionMemberSortOrder :execrows
-- DefinitionMemberReordered handler — second half. Per-member
-- projection_version guards the row so a stale reorder cannot clobber
-- a fresher position.
UPDATE definition_members_projection
SET sort_order        = $3,
    projection_version = $4
WHERE definition_id = $1
  AND action_set_id = $2
  AND projection_version < $4;

-- name: RecountDefinitionMembers :exec
-- DefinitionMemberAdded / DefinitionMemberRemoved handler — third half.
-- Recomputes member_count from the live row count after the listener
-- has applied a membership mutation. Run in the same transaction as
-- ClaimDefinitionForMembership + the INSERT/DELETE so the parent row
-- is never observed with a stale count. No projection_version guard
-- here: the Claim above already stamped the version.
UPDATE definitions_projection
SET member_count = (SELECT COUNT(*) FROM definition_members_projection WHERE definition_id = $1)
WHERE id = $1;

-- name: SoftDeleteDefinitionProjection :execrows
-- DefinitionDeleted handler — definitions_projection branch (taken on
-- the definition stream). Stale-replay guard via projection_version;
-- :execrows lets the listener detect and skip downstream cascades —
-- though there is no cross-table cascade for DefinitionDeleted today
-- (the PL/pgSQL projector left definition_members orphaned by
-- design), so n==0 just short-circuits to a no-op.
UPDATE definitions_projection
SET is_deleted        = TRUE,
    updated_at        = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;
