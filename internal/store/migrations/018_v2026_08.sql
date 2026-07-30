-- +goose Up

-- Drop the LPS sealing keypair (spec 41).
--
-- The keypair existed for exactly one purpose: agents sealed rotated LPS
-- passwords and LUKS passphrases to control's public key so the RELAYING
-- GATEWAY — the least-trusted server-side actor — could not read them in
-- flight. With the gateway deleted the agent talks to control directly over
-- mTLS, so there is no intermediary to withhold the plaintext from, and nothing
-- seals or unseals any more.
--
-- This is not a reduction in secrecy. The at-rest encryption is untouched:
-- passwords and passphrases are still AES-GCM encrypted under the KEK with a
-- device|action|type AAD, and a ciphertext relocated to another device or
-- action still fails to decrypt. Only the transport envelope, and the keypair
-- that served it, are removed.
--
-- Dropping the table also removes the last copy of private key material that no
-- longer has a reader — a stored private key with no consumer is a liability
-- that survives only because nobody checked.
DROP TABLE IF EXISTS lps_keypair;

-- +goose Down

-- Deliberately irreversible. Recreating the table would produce an EMPTY
-- keypair row, not the original key: the key is gone with the table, and every
-- secret ever sealed to it has already been unsealed and re-encrypted at rest
-- under the KEK. A down migration that restored the schema but not the key
-- would be a lie about what it recovers, so it restores nothing and says so.
SELECT 1;
