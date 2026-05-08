-- Compliance policy queries

-- name: GetCompliancePolicyByID :one
SELECT * FROM compliance_policies_projection
WHERE id = $1 AND is_deleted = FALSE;

-- name: GetCompliancePolicyByName :one
SELECT * FROM compliance_policies_projection
WHERE name = $1 AND is_deleted = FALSE;

-- name: ListCompliancePolicies :many
SELECT * FROM compliance_policies_projection
WHERE is_deleted = FALSE
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountCompliancePolicies :one
SELECT COUNT(*) FROM compliance_policies_projection
WHERE is_deleted = FALSE;

-- name: ListCompliancePolicyRules :many
SELECT * FROM compliance_policy_rules_projection
WHERE policy_id = $1
ORDER BY action_name;

-- name: GetDeviceCompliancePolicyEvaluations :many
SELECT
    e.device_id,
    e.policy_id,
    e.action_id,
    e.compliant,
    e.first_failed_at,
    e.status,
    e.checked_at,
    e.projection_version,
    r.grace_period_hours,
    r.action_name,
    p.name as policy_name
FROM compliance_policy_evaluation_projection e
JOIN compliance_policy_rules_projection r
  ON r.policy_id = e.policy_id AND r.action_id = e.action_id
JOIN compliance_policies_projection p
  ON p.id = e.policy_id AND p.is_deleted = FALSE
WHERE e.device_id = $1
ORDER BY p.name, r.action_name;

-- ============================================================================
-- Projector listener writes (manchtools/power-manage-server#136).
-- ============================================================================
--
-- Mirrors the deleted PL/pgSQL project_compliance_policy_event(): every
-- event handler the projector dispatched on (CompliancePolicyCreated,
-- CompliancePolicyRenamed, CompliancePolicyDescriptionUpdated,
-- CompliancePolicyDeleted, CompliancePolicyRuleAdded,
-- CompliancePolicyRuleRemoved, CompliancePolicyRuleUpdated) gets a typed
-- sqlc query here so the listener can compose them in Go.
--
-- Tightening vs the PL/pgSQL projector: every UPDATE on
-- compliance_policies_projection carries an explicit
-- `WHERE projection_version < $N` guard and uses :execrows so the
-- listener can short-circuit cascades on stale-replay (asymmetric-
-- guard discipline; see action_set_listener / user_group_listener for
-- the canonical shape).
--
-- Claim-first guard: the three rule-mutation events
-- (CompliancePolicyRuleAdded, CompliancePolicyRuleRemoved,
-- CompliancePolicyRuleUpdated) all run ClaimCompliancePolicyForRuleMutation
-- BEFORE touching compliance_policy_rules_projection. The Claim guard
-- bumps the parent's projection_version only when the policy exists,
-- is alive, and the event is newer; the listener short-circuits on
-- n == 0. Doing the version check BEFORE the rule INSERT/DELETE/UPDATE
-- prevents stale replays from silently resurrecting removed rules or
-- rolling back fresher edits — the same hazard the user_group port
-- (PR #174) had to fix retroactively.

-- name: InsertCompliancePolicyProjection :exec
-- CompliancePolicyCreated handler. ON CONFLICT DO NOTHING for replay
-- safety — the unique constraint is the primary key (id), so a re-
-- application of CompliancePolicyCreated for the same stream lands as
-- a no-op. The PL/pgSQL projector raised on the second insert; we
-- soften that to the same replay-safe shape every other ported
-- projector uses. rule_count starts at 0 (matches the PL/pgSQL
-- INSERT's literal `0`).
INSERT INTO compliance_policies_projection (
    id, name, description, rule_count,
    created_at, created_by, projection_version
) VALUES ($1, $2, $3, 0, $4, $5, $6)
ON CONFLICT (id) DO NOTHING;

-- name: RenameCompliancePolicyProjection :execrows
-- CompliancePolicyRenamed handler. Stale-replay guard via
-- projection_version. compliance_policies_projection has no
-- updated_at column (deliberate omission since 001_initial_tables.sql),
-- so the UPDATE only touches name + projection_version.
UPDATE compliance_policies_projection
SET name              = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: UpdateCompliancePolicyDescriptionProjection :execrows
-- CompliancePolicyDescriptionUpdated handler. Empty-string description
-- is a valid value (matches the PL/pgSQL `COALESCE(payload, '')` collapse
-- — the listener decoder substitutes '' when the payload key is missing).
UPDATE compliance_policies_projection
SET description       = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: SoftDeleteCompliancePolicyProjection :execrows
-- CompliancePolicyDeleted handler — first half. Returns rows-affected
-- so the listener can SKIP the cascade (rule wipe, evaluation wipe,
-- reevaluate_compliance_policy_devices) when the projection_version
-- guard rejects a stale replay; otherwise an old CompliancePolicyDeleted
-- re-applied by the reconciler against a freshly-restored policy
-- would silently nuke its rules + evaluations and trigger a needless
-- device re-evaluation pass.
UPDATE compliance_policies_projection
SET is_deleted        = TRUE,
    projection_version = $2
WHERE id = $1
  AND projection_version < $2;

-- name: DeleteCompliancePolicyRulesByPolicy :exec
-- CompliancePolicyDeleted handler — second half. Wipes every rule row
-- for the deleted policy. Wrapped with SoftDeleteCompliancePolicyProjection
-- + DeleteCompliancePolicyEvaluationsByPolicy + the reevaluate shim
-- inside store.WithTx for inter-write atomicity.
DELETE FROM compliance_policy_rules_projection WHERE policy_id = $1;

-- name: DeleteCompliancePolicyEvaluationsByPolicy :exec
-- CompliancePolicyDeleted handler — third half. Wipes every evaluation
-- row for the deleted policy so the device-status query no longer
-- joins through a deleted policy.
DELETE FROM compliance_policy_evaluation_projection WHERE policy_id = $1;

-- name: ClaimCompliancePolicyForRuleMutation :execrows
-- Atomic guard for the three rule-mutation events
-- (CompliancePolicyRuleAdded, CompliancePolicyRuleRemoved,
-- CompliancePolicyRuleUpdated). Bumps projection_version only when ALL of:
--
--   1. The policy exists (id matches).
--   2. The policy is NOT soft-deleted (a rule event replayed after a
--      Deleted must not bring rows back).
--   3. The event is newer than the current projection_version
--      (asymmetric-guard discipline; mirrors PR #174's CR catch).
--
-- Returns n=1 when the listener may proceed with the rule-table
-- mutation, n=0 when the event must be skipped. Encoding all three
-- short-circuit reasons in one query keeps the listener side
-- branch-free and — crucially — makes the version check happen
-- BEFORE any child-row mutation, so a stale event cannot resurrect
-- a removed rule or rewind a fresher RuleUpdated.
UPDATE compliance_policies_projection
SET projection_version = $2
WHERE id = $1
  AND projection_version < $2
  AND is_deleted = FALSE;

-- name: UpsertCompliancePolicyRule :exec
-- CompliancePolicyRuleAdded handler — second half. Mirrors the PL/pgSQL
-- projector's `ON CONFLICT (policy_id, action_id) DO UPDATE SET
-- action_name = COALESCE(payload->>'action_name', existing.action_name),
-- grace_period_hours = ..., projection_version = ...` so re-emitting
-- RuleAdded for the same (policy, action) pair upgrades the row in
-- place rather than failing on the composite-PK conflict.
--
-- action_name preserves the existing value when EXCLUDED is empty:
-- the decoder collapses a missing/null action_name to "" (the column
-- is NOT NULL), so a duplicate RuleAdded that omits action_name
-- arrives here as EXCLUDED.action_name = ''. Without the
-- NULLIF/COALESCE pair below, the UPSERT would erase a previously-
-- set name. CR caught this on PR #178.
--
-- The Claim guard upstream gates this call on parent-version freshness.
INSERT INTO compliance_policy_rules_projection (
    policy_id, action_id, action_name, grace_period_hours,
    added_at, projection_version
) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (policy_id, action_id) DO UPDATE SET
    action_name        = COALESCE(NULLIF(EXCLUDED.action_name, ''), compliance_policy_rules_projection.action_name),
    grace_period_hours = EXCLUDED.grace_period_hours,
    projection_version = EXCLUDED.projection_version;

-- name: DeleteCompliancePolicyRule :exec
-- CompliancePolicyRuleRemoved handler — second half. Plain DELETE
-- scoped to the (policy, action) pair — silently no-op on a miss
-- matches the PL/pgSQL projector's behaviour.
DELETE FROM compliance_policy_rules_projection
WHERE policy_id = $1
  AND action_id = $2;

-- name: DeleteCompliancePolicyEvaluationsByRule :exec
-- CompliancePolicyRuleRemoved handler — third half. Wipes evaluation
-- rows for the removed (policy, action) pair so the device-status
-- query stops surfacing a stale verdict for a rule that no longer
-- exists. Other rules in the same policy keep their evaluations.
DELETE FROM compliance_policy_evaluation_projection
WHERE policy_id = $1
  AND action_id = $2;

-- name: UpdateCompliancePolicyRuleGracePeriod :exec
-- CompliancePolicyRuleUpdated handler — second half. Composite-PK
-- targeted UPDATE. No per-row projection_version guard here: the
-- Claim guard upstream already gated this call on parent-version
-- freshness, so a stale event cannot reach this statement. Mirrors
-- the PL/pgSQL projector's `UPDATE ... WHERE policy_id = X AND
-- action_id = Y` shape.
UPDATE compliance_policy_rules_projection
SET grace_period_hours = $3,
    projection_version = $4
WHERE policy_id = $1
  AND action_id = $2;

-- name: RecountCompliancePolicyRules :exec
-- CompliancePolicyRuleAdded / CompliancePolicyRuleRemoved handler —
-- second-stage write after the rule-table mutation lands. Recomputes
-- rule_count from the live row count, mirroring the PL/pgSQL
-- `(SELECT COUNT(*) ...)` subquery. No projection_version guard:
-- the Claim above already stamped the version, so a recount without
-- re-stamping cannot regress.
UPDATE compliance_policies_projection
SET rule_count = (
    SELECT COUNT(*) FROM compliance_policy_rules_projection
    WHERE policy_id = $1
)
WHERE id = $1;

-- name: ReevaluateCompliancePolicyDevices :exec
-- CompliancePolicyDeleted / CompliancePolicyRuleRemoved handler —
-- final cascade step. Thin shim around the still-PL/pgSQL
-- reevaluate_compliance_policy_devices(p_policy_id) function defined
-- in migration 003. Per #136 the eval engine itself stays in PL/pgSQL
-- until a later phase; the listener just calls into it so the per-
-- device compliance status reflects the rule mutation.
SELECT reevaluate_compliance_policy_devices($1);
