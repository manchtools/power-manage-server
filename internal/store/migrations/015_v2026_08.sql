-- 2026.08 — spec 31 (gateway self-enrollment): gateways_projection.
--
-- One row per enrolled gateway, keyed by the gateway_id (the issued
-- cert CN). Projected by the Go GatewayListener from the gateway stream
-- (GatewayEnrolled / GatewayCertRenewed / GatewayRevoked). Rows are
-- ephemeral-per-boot: a restart re-enrolls under a fresh gateway_id, so
-- rows accumulate one per enrollment. A row is "live" until its
-- not_after passes or revoked_at is set; ListGateways filters on read
-- (WHERE not_after > now()) so the operator view stays bounded without a
-- separate prune. fingerprint and hostname are public material — no key
-- or token is ever stored here.

-- +goose Up

CREATE TABLE gateways_projection (
    gateway_id         text PRIMARY KEY,
    -- hex(sha256(cert DER)) of the gateway's current cert; the value
    -- revocation adds to the CRL, and what RevokeGatewayCertificate
    -- looks up by gateway_id.
    fingerprint        text NOT NULL,
    hostname           text NOT NULL DEFAULT '',
    -- NOT NULL: every issued gateway cert carries a 45-day expiry, and
    -- ListGateways filters `WHERE not_after > now()` — a NULL would never match,
    -- leaving an enrolled-but-invisible (un-revocable) live gateway. The
    -- projector requires not_after on GatewayEnrolled so this can never be NULL.
    not_after          timestamp with time zone NOT NULL,
    enrolled_at        timestamp with time zone NOT NULL,
    -- Set when the gateway is revoked (NULL = active).
    revoked_at         timestamp with time zone,
    -- Monotonic sequence_num of the last applied event — the standard
    -- projection guard against out-of-order replay.
    projection_version bigint NOT NULL DEFAULT 0
);

-- ListGateways filters `WHERE not_after > now()` and orders by enrolled_at.
-- The table is small (filter-on-read bounds it to live gateways), but the
-- index keeps the operator view O(live) rather than O(all-ever-enrolled) as
-- ephemeral-per-boot rows accumulate under churn.
CREATE INDEX gateways_projection_not_after_idx ON gateways_projection (not_after DESC);

-- +goose Down

DROP TABLE gateways_projection;
