-- Agent certificate revocation (spec 41). Replaces the Valkey-backed CRL: with
-- no gateway there is a single in-process reader, so the check is an indexed
-- lookup during the mTLS handshake rather than a published, distributed list.

-- name: RevokeCertificate :execrows
-- ON CONFLICT DO NOTHING keeps re-revocation idempotent. A certificate renewal
-- that retries after a partial failure must not error because the superseded
-- fingerprint is already listed — and the first revocation's reason and
-- timestamp are the truthful ones, so a later attempt must not overwrite them.
INSERT INTO revoked_certificates (fingerprint, not_after, reason)
VALUES ($1, $2, $3)
ON CONFLICT (fingerprint) DO NOTHING;

-- name: IsCertificateRevoked :one
-- The handshake question: is this fingerprint listed. Presence alone — NOT
-- bounded by not_after.
--
-- The bound was `AND not_after > now()`, reasoning that TLS refuses an expired
-- certificate on validity alone so the row buys nothing. That is true only if
-- both judgements use the same clock, and they do not: TLS validity is decided
-- by the CONTROL host, this predicate by the DATABASE. A database clock running
-- ahead declares the row expired while control still considers the certificate
-- valid, and the handshake is admitted — the one outcome revocation exists to
-- prevent, produced by nothing more than clock drift between two machines.
--
-- Presence-only removes the second clock from the decision entirely. The cost
-- is that a revoked-and-expired certificate is reported "revoked" rather than
-- "expired" in the logs, which is a labelling question, not a security one.
SELECT EXISTS (
  SELECT 1 FROM revoked_certificates
  WHERE fingerprint = $1
);

-- name: DeleteExpiredRevocations :execrows
-- Retention sweep. An expired certificate is refused by TLS itself, so its
-- revocation row buys nothing; every agent renews at 80% of lifetime and each
-- rotation writes a row, so without this the table grows with fleet size times
-- renewals forever.
--
-- The grace period is the same clock-skew argument as the lookup above, applied
-- to a DESTRUCTIVE operation: deleting on `not_after <= now()` lets a database
-- clock running ahead drop a revocation for a certificate control still treats
-- as valid, and the row does not come back. A week is far beyond any plausible
-- NTP drift and costs a handful of inert rows.
DELETE FROM revoked_certificates WHERE not_after <= now() - INTERVAL '7 days';
