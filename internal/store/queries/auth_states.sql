-- name: CreateAuthState :exec
INSERT INTO auth_states (state, provider_id, nonce, code_verifier, redirect_uri, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, now(), $6);

-- name: ConsumeAuthState :one
DELETE FROM auth_states
WHERE state = $1 AND expires_at > now()
RETURNING *;

-- name: CleanupExpiredAuthStates :exec
DELETE FROM auth_states WHERE expires_at < now();
