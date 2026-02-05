-- name: ListProjectionErrors :many
SELECT * FROM projection_errors
ORDER BY occurred_at DESC
LIMIT $1 OFFSET $2;

-- name: CountProjectionErrors :one
SELECT COUNT(*) FROM projection_errors;
