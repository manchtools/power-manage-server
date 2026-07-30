-- +goose Up

-- Certificate revocation moves out of Valkey and into control's own database
-- (spec 41). It lived in a Valkey sorted set because control and the gateway
-- both needed to read it; with no gateway there is one reader, in-process, and
-- the check is an indexed lookup during the mTLS handshake.
--
-- This table holds AGENT certificate revocations. The gateway direction is gone:
-- the agent-facing CRL existed so an agent could check the gateway server-cert
-- it was connecting to, and re-scoping that to control's own certificate is
-- circular — the list would be fetched over a connection authenticated by the
-- certificate it judges. Server-side revocation belongs in the trust anchor
-- (short-lived control certs), not in a list control publishes about itself.
CREATE TABLE revoked_certificates (
    -- hex(sha256(cert DER)), matching ca.FingerprintFromCert and the
    -- fingerprint the mTLS gate computes from the presented peer certificate.
    -- PRIMARY KEY makes re-revoking idempotent via ON CONFLICT DO NOTHING: a
    -- renewal that retries must not fail because the old cert is already
    -- revoked.
    fingerprint text PRIMARY KEY,
    revoked_at  timestamp with time zone NOT NULL DEFAULT now(),
    -- The revoked certificate's own expiry. Once it passes, the row is
    -- retention-eligible: an expired certificate is refused by TLS itself, so
    -- keeping it on the revocation list buys nothing. Retaining it forever would
    -- grow the table without bound under normal renewal churn — every agent
    -- renews at 80% of lifetime, so every agent produces a revocation row on
    -- each rotation.
    not_after   timestamp with time zone NOT NULL,
    -- Why it was revoked, for the audit trail. Free-form rather than an enum:
    -- the set of reasons is operational, not a wire contract.
    reason      text NOT NULL DEFAULT ''
);

-- The handshake asks exactly one question — "is this fingerprint revoked and
-- still within its validity window" — and the primary key answers the
-- fingerprint half. This index serves the retention sweep, which deletes rows
-- whose certificate has expired.
CREATE INDEX revoked_certificates_not_after_idx ON revoked_certificates (not_after);

-- +goose Down

DROP TABLE revoked_certificates;
