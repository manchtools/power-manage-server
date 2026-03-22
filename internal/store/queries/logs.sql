-- Device log query result queries

-- name: CreateLogQueryResult :exec
INSERT INTO log_query_results (query_id, device_id)
VALUES ($1, $2);

-- name: CompleteLogQueryResult :exec
UPDATE log_query_results
SET completed = TRUE, success = $2, error = $3, logs = $4, completed_at = NOW()
WHERE query_id = $1;

-- name: GetLogQueryResult :one
SELECT * FROM log_query_results
WHERE query_id = $1;

-- name: ExpirePendingLogQueryResult :exec
UPDATE log_query_results
SET completed = TRUE, success = FALSE, error = $2, completed_at = NOW()
WHERE query_id = $1 AND completed = FALSE;

-- name: DeleteOldLogQueryResults :exec
DELETE FROM log_query_results
WHERE created_at < NOW() - INTERVAL '1 hour';
