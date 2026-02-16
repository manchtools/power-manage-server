-- OSQuery on-demand result queries

-- name: CreateOSQueryResult :exec
INSERT INTO osquery_results (query_id, device_id, table_name)
VALUES ($1, $2, $3);

-- name: CompleteOSQueryResult :exec
UPDATE osquery_results
SET completed = TRUE, success = $2, error = $3, rows = $4, completed_at = NOW()
WHERE query_id = $1;

-- name: GetOSQueryResult :one
SELECT * FROM osquery_results
WHERE query_id = $1;

-- name: DeleteOldOSQueryResults :exec
DELETE FROM osquery_results
WHERE created_at < NOW() - INTERVAL '1 hour';
