-- 010_lps_keypair.sql — control-owned X25519 keypair for sealed LPS
-- password transport (spec 18, manchtools/power-manage-agent#62).
--
-- The agent seals each rotated LPS password to this public key so the
-- relaying gateway can never read it; control unseals at receipt with the
-- private key, then re-encrypts with the existing at-rest path. This is
-- infrastructure state, NOT domain state: it is generated once at control
-- boot (EnsureLpsKeypair, advisory-locked) and never mutated, so it does
-- not go through the event store / projector machinery. A single-row table
-- (id = 'global') shared via Postgres lets every control replica load the
-- same key. The private key is stored ONLY in the app-level encrypted
-- (enc:v2) form — never plaintext.

-- +goose Up
CREATE TABLE lps_keypair (
    id              TEXT PRIMARY KEY DEFAULT 'global' CHECK (id = 'global'),
    -- X25519 public key, 32 raw bytes (ecdh PublicKey.Bytes()).
    public_key      BYTEA NOT NULL,
    -- X25519 private key sealed by internal/crypto EncryptWithContext
    -- (enc:v2 string, AAD-bound). Never stored or logged in cleartext.
    private_key_enc TEXT  NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS lps_keypair;
