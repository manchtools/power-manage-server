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

-- name: CountUnacknowledgedSecurityAlerts :one
SELECT COUNT(*)::int FROM security_alerts_projection WHERE NOT acknowledged;
