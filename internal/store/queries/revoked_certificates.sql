-- Agent certificate revocation: an indexed lookup on every mTLS
-- handshake.

-- name: RevokeCertificate :execrows
-- ON CONFLICT DO NOTHING keeps re-revocation idempotent. A renewal that
-- retries after a partial failure must not error because the
-- superseded fingerprint is already listed, and the FIRST revocation's
-- reason and timestamp are the truthful ones, so a later attempt must
-- not overwrite them.
INSERT INTO revoked_certificates (fingerprint, not_after, reason)
VALUES ($1, $2, $3)
ON CONFLICT (fingerprint) DO NOTHING;

-- name: IsCertificateRevoked :one
-- The handshake question: is this fingerprint listed. Presence alone,
-- deliberately NOT bounded by not_after.
--
-- Bounding it on `not_after > now()` would put a second clock in the
-- decision. TLS validity is judged by the control host; this predicate
-- would be judged by the database. A database clock running ahead
-- declares the row expired while control still accepts the
-- certificate, and the handshake is admitted — the exact outcome
-- revocation exists to prevent, produced by nothing worse than clock
-- drift between two machines.
--
-- The cost is that a revoked-and-expired certificate is reported as
-- "revoked" rather than "expired", which is a labelling question.
SELECT EXISTS (
  SELECT 1 FROM revoked_certificates
  WHERE fingerprint = $1
);

-- name: DeleteExpiredRevocations :execrows
-- Retention sweep. An expired certificate is refused by TLS on its own
-- validity, so its revocation row buys nothing; every agent renews at
-- 80% of lifetime and each rotation writes a row, so without this the
-- table grows with fleet size times renewals forever.
--
-- The grace period is the same clock-skew argument applied to a
-- DESTRUCTIVE operation: deleting on `not_after <= now()` lets a
-- database clock running ahead drop a revocation for a certificate
-- control still treats as valid, and the row does not come back. A
-- week is far beyond any plausible drift and costs a handful of inert
-- rows.
DELETE FROM revoked_certificates WHERE not_after <= now() - INTERVAL '7 days';
