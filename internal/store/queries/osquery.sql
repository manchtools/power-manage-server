-- OSQuery on-demand result queries

-- name: CreateOSQueryResult :exec
INSERT INTO osquery_results (query_id, device_id, table_name)
VALUES ($1, $2, $3);

-- name: CompleteOSQueryResult :execrows
-- device_id is matched so a compromised agent can't complete another device's
-- query result by supplying its (non-secret) query_id. :execrows lets the
-- caller detect a 0-row update (unknown query or wrong device) and drop it.
UPDATE osquery_results
SET completed = TRUE, success = $2, error = $3, rows = $4, completed_at = NOW()
WHERE query_id = $1 AND device_id = $5;

-- name: GetOSQueryResult :one
SELECT * FROM osquery_results
WHERE query_id = $1;

-- name: ExpirePendingOSQueryResult :exec
UPDATE osquery_results
SET completed = TRUE, success = FALSE, error = $2, completed_at = NOW()
WHERE query_id = $1 AND completed = FALSE;

-- name: DeleteOldOSQueryResults :exec
DELETE FROM osquery_results
WHERE created_at < NOW() - INTERVAL '1 hour';
