-- Compliance queries

-- name: GetDeviceComplianceResults :many
SELECT * FROM compliance_results_projection
WHERE device_id = $1
ORDER BY action_name;

-- name: GetDeviceComplianceSummary :one
SELECT compliance_status, compliance_total, compliance_passing, compliance_checked_at
FROM devices_projection WHERE id = $1;

-- ============================================================================
-- Projector listener writes (manchtools/power-manage-server#136).
-- ============================================================================
--
-- Mirrors the deleted PL/pgSQL project_compliance_event(): two event
-- types (ComplianceResultUpdated, ComplianceResultRemoved) get typed
-- sqlc queries here so the listener can compose them in Go.
--
-- compliance_results_projection has a composite PK (device_id,
-- action_id) and no parent table to Claim against — there is no
-- compliance_results "header" row. The asymmetric-guard discipline
-- still applies: the UPSERT's UPDATE branch carries an explicit
-- `WHERE projection_version < EXCLUDED.projection_version` predicate
-- so a stale ComplianceResultUpdated cannot rewind a fresher row.
--
-- Reevaluation engine scope: per #136 the
-- evaluate_device_compliance_policies(p_device_id) function — and the
-- per-policy evaluator family it dispatches to — STAY in PL/pgSQL
-- until a later phase. The Go listener calls into the existing shim
-- (EvaluateDeviceCompliancePolicies, defined in assignments.sql for
-- the assignment port) so device compliance status reflects every
-- result mutation; the eval engine itself runs unchanged inside
-- Postgres.

-- name: UpsertComplianceResultProjection :exec
-- ComplianceResultUpdated handler. Mirrors the PL/pgSQL projector's
-- `INSERT … ON CONFLICT (device_id, action_id) DO UPDATE SET …` shape.
--
-- action_name preserves the existing value when EXCLUDED is empty:
-- the decoder collapses a missing/null action_name to "" (the column
-- is NOT NULL), so a duplicate ComplianceResultUpdated that omits
-- action_name arrives here as EXCLUDED.action_name = "". Without the
-- NULLIF/COALESCE pair below, the UPSERT would erase a previously-
-- set name. CR caught this same shape on PR #178 for the
-- compliance_policy rule UPSERT; applying it from the start here.
--
-- compliant and detection_output always overwrite — matches the
-- PL/pgSQL `compliant = COALESCE(..., false)` and
-- `detection_output = event.data->'detection_output'` (which collapses
-- a missing key to NULL). Preserving them on omission would change
-- semantics: a compliance check that intentionally clears its prior
-- detection_output by sending NULL must be honoured.
--
-- Stale-replay guard: the UPDATE branch's
-- `WHERE projection_version < EXCLUDED.projection_version` predicate
-- rejects re-applications of an older event against a fresher row.
-- The INSERT branch can't be guarded the same way — there's no row
-- to compare against — but a "stale" event that arrives before the
-- row exists is just a normal first INSERT, indistinguishable from a
-- fresh first emission. Once the row exists, every subsequent UPSERT
-- routes through the guarded UPDATE branch.
INSERT INTO compliance_results_projection (
    device_id, action_id, action_name, compliant, detection_output,
    checked_at, projection_version
) VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (device_id, action_id) DO UPDATE SET
    action_name        = COALESCE(NULLIF(EXCLUDED.action_name, ''), compliance_results_projection.action_name),
    compliant          = EXCLUDED.compliant,
    detection_output   = EXCLUDED.detection_output,
    checked_at         = EXCLUDED.checked_at,
    projection_version = EXCLUDED.projection_version
WHERE compliance_results_projection.projection_version < EXCLUDED.projection_version;

-- name: DeleteComplianceResultProjection :exec
-- ComplianceResultRemoved handler. Plain DELETE scoped to the
-- composite PK — silently no-op on a miss matches the PL/pgSQL
-- projector's behaviour. No projection_version guard: the PL/pgSQL
-- projector unconditionally DELETEd the row on every Removed event,
-- and a stale Removed re-applied later is safe because the row is
-- already gone (the listener still calls the reevaluate shim, which
-- is idempotent on the device-policy state).
DELETE FROM compliance_results_projection
WHERE device_id = $1
  AND action_id = $2;
