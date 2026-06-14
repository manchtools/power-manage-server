-- 013_luks_token_hash.sql
--
-- WS10 #3: LUKS one-time tokens are now stored as a SHA-256 hash at rest
-- (consistent with registration/terminal tokens), so the plaintext token
-- no longer persists in luks_tokens.token. The column shape is unchanged
-- (still text) — only the value written by the handler changed
-- (device_handler.CreateLuksToken stores hashLuksToken(token);
-- ProxyValidateLuksToken hashes the presented token before lookup).
--
-- Any rows written before this change hold PLAINTEXT tokens that would
-- (a) never match the now-hashed lookup and (b) leave a usable secret at
-- rest. They are one-time and expire after 15 minutes, so clearing them
-- is safe — an operator simply re-creates the token. No schema or
-- PL/pgSQL change is needed.

-- +goose Up
DELETE FROM public.luks_tokens;

-- +goose Down
-- No-op: deleted one-time tokens cannot be restored, and the column
-- shape is unchanged.
SELECT 1;
