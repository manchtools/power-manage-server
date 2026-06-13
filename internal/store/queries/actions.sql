-- Actions queries (renamed from definitions)

-- name: GetActionByID :one
SELECT * FROM actions_projection
WHERE id = $1 AND is_deleted = FALSE;

-- name: GetActionByName :one
SELECT * FROM actions_projection
WHERE name = $1 AND is_deleted = FALSE;

-- name: ListActions :many
SELECT * FROM actions_projection
WHERE is_deleted = FALSE AND is_system = FALSE
  AND ($1::INTEGER = 0 OR action_type = $1)
  AND (sqlc.arg(unassigned_only)::BOOLEAN = FALSE OR NOT EXISTS (
    SELECT 1 FROM action_set_members_projection asm WHERE asm.action_id = id
  ))
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountActions :one
SELECT COUNT(*) FROM actions_projection
WHERE is_deleted = FALSE AND is_system = FALSE
  AND ($1::INTEGER = 0 OR action_type = $1)
  AND (sqlc.arg(unassigned_only)::BOOLEAN = FALSE OR NOT EXISTS (
    SELECT 1 FROM action_set_members_projection asm WHERE asm.action_id = id
  ));

-- name: GetActionNamesByIDs :many
SELECT id, name FROM actions_projection
WHERE id = ANY($1::TEXT[]);

-- name: UpdateActionSignature :exec
UPDATE actions_projection
SET signature = $2, params_canonical = $3
WHERE id = $1;

-- ============================================================================
-- Projector listener writes (manchtools/power-manage-server#136).
-- ============================================================================
--
-- Mirrors the deleted PL/pgSQL project_action_event(). The projector
-- handled both action-stream events (ActionCreated, ActionRenamed,
-- ActionDescriptionUpdated, ActionParamsUpdated, ActionDeleted) AND
-- definition-stream events that synthesise actions_projection rows
-- (DefinitionCreated/Renamed/DescriptionUpdated/Deleted IFF the
-- payload carries `action_type` — compliance-policy bootstrap path).
--
-- Tightening vs the PL/pgSQL projector: every UPDATE on
-- actions_projection carries an explicit `WHERE projection_version < $N`
-- guard and uses :execrows so the listener can short-circuit cascades
-- on stale-replay (asymmetric-guard discipline; see role_listener /
-- action_set_listener for the canonical shape).
--
-- The ActionDeleted cascade is the most complex of any Phase 2 port:
-- the SoftDelete is :execrows and gates FOUR downstream writes
-- (action_set_member decrement, compliance_policy_rules delete with
-- per-policy rule_count decrement, compliance_policy_evaluation
-- delete, compliance_results delete) PLUS a per-affected-device
-- reevaluate loop. Skipping every step on n==0 is mandatory — see the
-- listener for the discipline narrative.

-- name: InsertActionProjection :exec
-- ActionCreated handler. ON CONFLICT DO NOTHING for replay safety.
INSERT INTO actions_projection (
    id, name, description, action_type, desired_state,
    params, timeout_seconds, created_at, updated_at, created_by, projection_version,
    is_system, schedule
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (id) DO NOTHING;

-- name: InsertSynthesisedActionProjection :exec
-- DefinitionCreated handler — actions_projection branch (compliance-
-- policy synthesised action). Mirrors the PL/pgSQL projector's
-- INSERT into actions_projection that omits is_system + schedule (those
-- columns are left at their column defaults: is_system=FALSE,
-- schedule=NULL). ON CONFLICT DO NOTHING for replay safety.
INSERT INTO actions_projection (
    id, name, description, action_type, desired_state,
    params, timeout_seconds, created_at, updated_at, created_by, projection_version
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (id) DO NOTHING;

-- name: RenameActionProjection :execrows
-- ActionRenamed handler — first half. Stale-replay guard via
-- projection_version. Returns rows-affected so the listener can
-- short-circuit the cross-stream rename cascade
-- (RenameComplianceRuleActionName) when the guard rejects a stale
-- replay.
UPDATE actions_projection
SET name              = $2,
    updated_at        = $3,
    projection_version = $4
WHERE id = $1
  AND projection_version < $4;

-- name: RenameComplianceRuleActionName :exec
-- ActionRenamed handler — second half. Cross-stream cascade into the
-- compliance_policy_rules_projection. Mirrors the PL/pgSQL projector's
-- `UPDATE compliance_policy_rules_projection SET action_name = ...
-- WHERE action_id = ...`. No projection_version guard here: the rules
-- table's projection_version is owned by the compliance_policy
-- projector, and this denormalised name column is updated unconditionally
-- by the action projector (legacy behaviour preserved). The cascade is
-- gated upstream by RenameActionProjection's :execrows short-circuit.
UPDATE compliance_policy_rules_projection
SET action_name = $2
WHERE action_id = $1;

-- name: UpdateActionDescriptionProjection :execrows
-- ActionDescriptionUpdated handler. NULL-able description column: the
-- PL/pgSQL projector wrote `event.data->>'description'` directly, so
-- absence becomes NULL and explicit empty string becomes "". The
-- listener decoder preserves that distinction via *string.
UPDATE actions_projection
SET description       = $2,
    updated_at        = $3,
    projection_version = $4
WHERE id = $1
  AND projection_version < $4;

-- name: UpdateActionParamsProjection :execrows
-- ActionParamsUpdated handler. Mirrors the PL/pgSQL projector's
-- `COALESCE(event.data->'params', params)` per-field preservation:
-- every NULL parameter preserves the existing column value via
-- COALESCE, every non-NULL parameter overwrites. The decoder surfaces
-- absence as NULL and presence as the new value, so this query is the
-- direct PL/pgSQL translation.
UPDATE actions_projection
SET params            = COALESCE(sqlc.narg('params')::JSONB, params),
    timeout_seconds   = COALESCE(sqlc.narg('timeout_seconds')::INTEGER, timeout_seconds),
    desired_state     = COALESCE(sqlc.narg('desired_state')::INTEGER, desired_state),
    schedule          = COALESCE(sqlc.narg('schedule')::JSONB, schedule),
    updated_at        = sqlc.arg('updated_at'),
    projection_version = sqlc.arg('projection_version')
WHERE id = sqlc.arg('id')
  AND projection_version < sqlc.arg('projection_version');

-- name: SoftDeleteActionProjection :execrows
-- ActionDeleted handler — first half. Returns rows-affected so the
-- listener can SKIP the cascade (action_set_member decrement +
-- compliance_policy_rules delete + compliance_policy_evaluation delete
-- + compliance_results delete + per-device reevaluate loop) when the
-- projection_version guard rejects a stale replay; otherwise an old
-- ActionDeleted re-applied by the reconciler against a freshly-restored
-- action would silently nuke its compliance footprint and trigger a
-- needless device re-evaluation pass.
UPDATE actions_projection
SET is_deleted        = TRUE,
    updated_at        = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: DecrementActionSetMemberCountByAction :exec
-- ActionDeleted handler — second half. Mirrors the PL/pgSQL subquery
-- `UPDATE action_sets_projection SET member_count = member_count - 1
-- WHERE id IN (SELECT set_id FROM action_set_members_projection WHERE
-- action_id = ...)`. Runs BEFORE DeleteActionSetMembersByAction —
-- once those member rows are gone the subquery returns empty and the
-- recount no-ops.
UPDATE action_sets_projection
SET member_count = member_count - 1
WHERE id IN (
    SELECT set_id FROM action_set_members_projection WHERE action_id = $1
);

-- name: DeleteActionSetMembersByAction :exec
-- ActionDeleted handler — third half. Removes every action_set member
-- row for the deleted action.
DELETE FROM action_set_members_projection WHERE action_id = $1;

-- name: ListCompliancePolicyIDsByAction :many
-- ActionDeleted handler — fourth half (preflight for the compliance
-- cascade). Mirrors the PL/pgSQL `SELECT ARRAY_AGG(DISTINCT policy_id)
-- ... INTO v_affected_policies FROM compliance_policy_rules_projection
-- WHERE action_id = ...`. Listener short-circuits the rest of the
-- cascade when this returns empty (matches the PL/pgSQL `IF
-- v_affected_policies IS NOT NULL THEN ... END IF;` guard).
SELECT DISTINCT policy_id
FROM compliance_policy_rules_projection
WHERE action_id = $1;

-- name: DecrementCompliancePolicyRuleCountByPolicies :exec
-- ActionDeleted handler — fifth half. Decrements rule_count on every
-- policy whose rule set referenced the deleted action. Runs BEFORE
-- DeleteCompliancePolicyRulesByAction so the row count drops by
-- exactly one per matching rule (mirrors PL/pgSQL `UPDATE ... SET
-- rule_count = rule_count - 1 WHERE id = ANY(v_affected_policies)`).
UPDATE compliance_policies_projection
SET rule_count = rule_count - 1
WHERE id = ANY($1::TEXT[]);

-- name: DeleteCompliancePolicyRulesByAction :exec
-- ActionDeleted handler — sixth half. Wipes every rule row referencing
-- the deleted action across every policy.
DELETE FROM compliance_policy_rules_projection WHERE action_id = $1;

-- name: DeleteCompliancePolicyEvaluationsByAction :exec
-- ActionDeleted handler — seventh half. Wipes every evaluation row
-- referencing the deleted action across every policy.
DELETE FROM compliance_policy_evaluation_projection WHERE action_id = $1;

-- name: DeleteComplianceResultsByAction :exec
-- ActionDeleted handler — eighth half. Wipes every per-device
-- compliance result for the deleted action.
DELETE FROM compliance_results_projection WHERE action_id = $1;

-- name: ListDeviceIDsForCompliancePolicies :many
-- ActionDeleted handler — final cascade preflight. Mirrors the
-- PL/pgSQL `FOR v_device_id IN SELECT DISTINCT a.target_id ... UNION
-- SELECT DISTINCT dgm.device_id ... LOOP PERFORM
-- evaluate_device_compliance_policies(v_device_id); END LOOP`. Returns
-- every device that was assigned at least one of the affected policies
-- either directly or through a device_group. The listener iterates
-- the returned ids and calls EvaluateDeviceCompliancePolicies (the
-- existing shim from assignments.sql) for each so device-level
-- compliance status reflects the action's deletion.
SELECT DISTINCT a.target_id AS device_id
FROM assignments_projection a
WHERE a.source_type = 'compliance_policy'
  AND a.source_id = ANY($1::TEXT[])
  AND a.target_type = 'device'
  AND a.is_deleted = FALSE
UNION
SELECT DISTINCT dgm.device_id
FROM assignments_projection a
JOIN device_group_members_projection dgm ON dgm.group_id = a.target_id
WHERE a.source_type = 'compliance_policy'
  AND a.source_id = ANY($1::TEXT[])
  AND a.target_type = 'device_group'
  AND a.is_deleted = FALSE;

-- Executions queries

-- name: GetExecutionByID :one
SELECT * FROM executions_projection
WHERE id = $1;

-- name: ListExecutions :many
SELECT * FROM executions_projection
WHERE ($1::TEXT = '' OR device_id = $1)
  AND ($2::TEXT = '' OR status = $2)
  AND ($3::INTEGER = 0 OR action_type = $3)
  AND ($4::TEXT = '' OR EXISTS (
    SELECT 1 FROM actions_projection a WHERE a.id = executions_projection.action_id AND a.name ILIKE '%' || $4 || '%'
  ) OR EXISTS (
    SELECT 1 FROM devices_projection d WHERE d.id = executions_projection.device_id AND d.hostname ILIKE '%' || $4 || '%'
  ))
  -- Device-group scope (#3): when @scope_restricted, the execution's device must
  -- be a member of a group in @scope_group_ids. Empty array restricts to nothing.
  AND (NOT @scope_restricted::boolean
    OR EXISTS (SELECT 1 FROM device_group_members_projection dgm WHERE dgm.device_id = executions_projection.device_id AND dgm.group_id = ANY(@scope_group_ids::text[]))
  )
ORDER BY created_at DESC
LIMIT $5 OFFSET $6;

-- name: CountExecutions :one
SELECT COUNT(*) FROM executions_projection
WHERE ($1::TEXT = '' OR device_id = $1)
  AND ($2::TEXT = '' OR status = $2)
  AND ($3::INTEGER = 0 OR action_type = $3)
  AND ($4::TEXT = '' OR EXISTS (
    SELECT 1 FROM actions_projection a WHERE a.id = executions_projection.action_id AND a.name ILIKE '%' || $4 || '%'
  ) OR EXISTS (
    SELECT 1 FROM devices_projection d WHERE d.id = executions_projection.device_id AND d.hostname ILIKE '%' || $4 || '%'
  ))
  -- Device-group scope (#3): when @scope_restricted, the execution's device must
  -- be a member of a group in @scope_group_ids. Empty array restricts to nothing.
  AND (NOT @scope_restricted::boolean
    OR EXISTS (SELECT 1 FROM device_group_members_projection dgm WHERE dgm.device_id = executions_projection.device_id AND dgm.group_id = ANY(@scope_group_ids::text[]))
  );

-- name: ListPendingExecutionsForDevice :many
-- Include both 'pending' and 'dispatched' statuses, since dispatched executions
-- may need to be re-sent if the agent disconnected before receiving them.
-- Skip executions older than the 24h max-age: a long-offline device must NOT
-- run its entire stale backlog (possibly destructive) on reconnect. Stale ones
-- are timed out by ListStaleExecutions instead — keep the 24h here in sync with
-- the pending branch there (audit).
SELECT * FROM executions_projection
WHERE device_id = $1 AND status IN ('pending', 'dispatched')
  AND created_at > NOW() - INTERVAL '24 hours'
ORDER BY created_at ASC;

-- name: ListStaleExecutions :many
-- Find executions that must be timed out:
--   - 'dispatched' rows past their per-action timeout + grace (agent didn't
--     respond), and
--   - 'pending' rows older than the 24h max-age — assigned to a device that
--     never came online in time. Without this they wait forever and run as a
--     stale, possibly destructive action when the device finally reconnects
--     (audit). Keep the 24h in sync with ListPendingExecutionsForDevice.
SELECT id, device_id, timeout_seconds, status, created_at, dispatched_at
FROM executions_projection
WHERE (status = 'dispatched'
       AND dispatched_at < NOW() - make_interval(secs => GREATEST(timeout_seconds, 300) + 300))
   OR (status = 'pending'
       AND created_at <= NOW() - INTERVAL '24 hours')
LIMIT 100;

-- name: ListRecentExecutionsForDevice :many
SELECT * FROM executions_projection
WHERE device_id = $1
ORDER BY created_at DESC
LIMIT $2;

-- name: ListExecutionsForWarm :many
SELECT * FROM executions_projection
WHERE created_at >= NOW() - INTERVAL '90 days'
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountExecutionsForWarm :one
SELECT COUNT(*) FROM executions_projection
WHERE created_at >= NOW() - INTERVAL '90 days';
