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
-- The handshake question. Bounded by not_after so an expired certificate is not
-- reported revoked: TLS refuses it on validity alone, and answering "revoked"
-- for something already refused conflates two distinct rejection reasons in the
-- logs.
SELECT EXISTS (
  SELECT 1 FROM revoked_certificates
  WHERE fingerprint = $1 AND not_after > now()
);

-- name: ListActiveRevokedFingerprints :many
-- Every fingerprint still inside its validity window. Used to warm the
-- in-process checker at boot and on refresh, so the handshake path stays a map
-- lookup rather than a query per connection.
SELECT fingerprint FROM revoked_certificates WHERE not_after > now();

-- name: DeleteExpiredRevocations :execrows
-- Retention sweep. An expired certificate is refused by TLS itself, so its
-- revocation row buys nothing; every agent renews at 80% of lifetime and each
-- rotation writes a row, so without this the table grows with fleet size times
-- renewals forever.
DELETE FROM revoked_certificates WHERE not_after <= now();
