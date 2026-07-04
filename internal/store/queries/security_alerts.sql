-- Phase 1 read queries for the security_alerts_projection (added in
-- migration 010). The RPC surface (ControlService.ListSecurityAlerts,
-- AcknowledgeSecurityAlert) and the web UI wiring land in a follow-up
-- PR because they need proto changes; the queries below are the
-- Go-side primitives those handlers will call.
--
-- Keeping them in this PR means the projection is not a dead table —
-- internal callers and tests can already exercise it, and future
-- handler work only needs to wire the proto envelope.

-- name: ListSecurityAlertsForDevice :many
SELECT event_id, device_id, alert_type, message, details, raised_at,
       acknowledged, acknowledged_at, acknowledged_by
FROM security_alerts_projection
WHERE device_id = $1
  AND (sqlc.arg(include_acknowledged)::bool OR NOT acknowledged)
ORDER BY raised_at DESC
LIMIT sqlc.arg(page_size)::int
OFFSET sqlc.arg(page_offset)::int;

-- name: ListUnacknowledgedSecurityAlerts :many
SELECT event_id, device_id, alert_type, message, details, raised_at,
       acknowledged, acknowledged_at, acknowledged_by
FROM security_alerts_projection
WHERE NOT acknowledged
ORDER BY raised_at DESC
LIMIT sqlc.arg(page_size)::int
OFFSET sqlc.arg(page_offset)::int;

-- name: GetSecurityAlert :one
SELECT event_id, device_id, alert_type, message, details, raised_at,
       acknowledged, acknowledged_at, acknowledged_by
FROM security_alerts_projection
WHERE event_id = $1;

-- COUNT(*) in PostgreSQL is bigint; keep the full precision so
-- buildNextPageToken (which works in int64) doesn't see a silently
-- truncated int32 once device counts climb past 2.1B aggregate
-- alerts across all time. Matches the pagination helper contract.
-- name: CountUnacknowledgedSecurityAlerts :one
SELECT COUNT(*)::bigint FROM security_alerts_projection WHERE NOT acknowledged;

-- Companion count for ListSecurityAlertsForDevice. Needed by
-- buildNextPageToken to compute totalCount and emit a correct
-- next-page token; mirrors the same include_acknowledged filter
-- semantics as the list query so the two stay in lockstep.
-- name: CountSecurityAlertsForDevice :one
SELECT COUNT(*)::bigint
FROM security_alerts_projection
WHERE device_id = $1
  AND (sqlc.arg(include_acknowledged)::bool OR NOT acknowledged);

-- Write-side queries for the Go projector that replaced
-- project_security_alert_event() in #96. ON CONFLICT DO NOTHING on
-- insert keeps replay-from-events idempotent (the same event_id
-- inserted twice is a no-op); the projector listener can re-fire on
-- crash recovery without polluting the projection.
--
-- name: InsertSecurityAlertProjection :exec
INSERT INTO security_alerts_projection (
    event_id, device_id, alert_type, message, details, raised_at, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (event_id) DO NOTHING;

-- AcknowledgeSecurityAlertProjection updates the ack columns. Returns
-- the affected row count so the projector listener can detect the
-- "acknowledged before alert exists" race (out-of-order replay) and
-- log it for operator visibility — matching the RAISE EXCEPTION
-- contract the deleted PL/pgSQL projector had.
--
-- name: AcknowledgeSecurityAlertProjection :execrows
UPDATE security_alerts_projection
SET acknowledged = TRUE,
    acknowledged_at = $2,
    acknowledged_by = $3
WHERE event_id = $1;
