-- name: CreateAuthState :exec
INSERT INTO auth_states (state, provider_id, flow_kind, nonce, code_verifier, redirect_uri, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?);

-- name: ConsumeAuthState :one
DELETE FROM auth_states
WHERE state = ? AND expires_at > CURRENT_TIMESTAMP
RETURNING *;

-- name: CleanupExpiredAuthStates :execrows
DELETE FROM auth_states WHERE expires_at < CURRENT_TIMESTAMP;
