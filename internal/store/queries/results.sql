-- name: GetOSQueryResult :one
SELECT query_id, device_id, completed, success, error, rows, created_at
FROM osquery_results
WHERE query_id = $1;
