-- 2026.08 — spec 19 (audit retention & crypto-shred erasure), stage A:
-- per-user PII envelope encryption.
--
-- user_encryption_keys holds one KEK-wrapped data-encryption key (DEK)
-- per user. Every PII field in any event payload is encrypted under
-- the subject user's DEK before append, so deleting the user is
-- satisfied by destroying this one row ("crypto-shred") — the
-- append-only event log is never mutated, yet every copy of the
-- person's PII (live log, cold archives, future rebuilds) becomes
-- permanently unreadable at once.
--
-- THE sole durable, NON-RECOVERABLE, non-event-sourced Postgres state
-- (ADR 0030 amends ADR 0029): it cannot be event-sourced (that would
-- make it un-destroyable) and cannot be regenerated (random key
-- material). It is jointly authoritative with the events table and
-- must be in every backup/restore set — losing it is unintended mass
-- erasure (all PII projects as the redaction sentinel).

-- +goose Up

CREATE TABLE user_encryption_keys (
    -- The owning user's ULID. No FK to users_projection: the
    -- projection is TRUNCATEd during rebuilds and this table must
    -- survive them untouched.
    user_id     text PRIMARY KEY,
    -- AAD-bound enc:v1 ciphertext of the 32-byte DEK, wrapped under
    -- the process KEK (CONTROL_ENCRYPTION_KEY).
    wrapped_dek text NOT NULL,
    created_at  timestamp with time zone NOT NULL DEFAULT now()
);

-- +goose Down

-- Deliberately NOT reversible: dropping this table is a mass
-- crypto-shred of every user's PII. Restore from backup instead.
SELECT 1;
