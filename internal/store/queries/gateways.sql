-- Queries for gateways_projection (spec 31). Write-side queries feed the Go
-- GatewayListener; read-side queries back the revoke handler, the CRL, and the
-- operator Gateways view. Every write carries a projection_version guard so an
-- out-of-order replay cannot clobber newer state.

-- Idempotent upsert for GatewayEnrolled. gateway_id is a fresh ULID per
-- enrollment, so ON CONFLICT effectively only fires on a replay of the same
-- event, where the version guard makes it a no-op.
-- name: UpsertGatewayEnrolledProjection :exec
INSERT INTO gateways_projection (
    gateway_id, fingerprint, hostname, not_after, enrolled_at, projection_version
) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (gateway_id) DO UPDATE SET
    fingerprint = EXCLUDED.fingerprint,
    hostname = EXCLUDED.hostname,
    not_after = EXCLUDED.not_after,
    enrolled_at = EXCLUDED.enrolled_at,
    projection_version = EXCLUDED.projection_version
WHERE gateways_projection.projection_version < EXCLUDED.projection_version;

-- Advance fingerprint + expiry on renewal. :execrows so the listener can
-- short-circuit a stale replay (n == 0).
-- name: UpdateGatewayCertRenewedProjection :execrows
UPDATE gateways_projection
SET fingerprint = $2,
    not_after = $3,
    projection_version = $4
WHERE gateway_id = $1 AND projection_version < $4;

-- Mark a gateway revoked. :execrows for stale-replay short-circuit.
-- name: MarkGatewayRevokedProjection :execrows
UPDATE gateways_projection
SET revoked_at = $2,
    projection_version = $3
WHERE gateway_id = $1 AND projection_version < $3;

-- Look up the current fingerprint + expiry for a gateway. RevokeGatewayCertificate
-- reads this to know which fingerprint to add to the CRL and until when.
-- name: GetGatewayFingerprint :one
SELECT fingerprint, not_after, revoked_at
FROM gateways_projection
WHERE gateway_id = $1;

-- Operator view: currently-live gateways (not yet expired), newest first.
-- Includes revoked-but-unexpired rows so the operator sees revoked state.
-- name: ListGateways :many
SELECT gateway_id, fingerprint, hostname, not_after, enrolled_at, revoked_at
FROM gateways_projection
WHERE not_after > now()
ORDER BY enrolled_at DESC;
