-- name: GetOSQueryResult :one
SELECT query_id, device_id, completed, success, error, rows, created_at
FROM osquery_results
WHERE query_id = $1;

-- name: GetDeviceLogResult :one
SELECT query_id, device_id, completed, success, error, logs, created_at
FROM log_query_results
WHERE query_id = $1;
