-- name: AppendEvent :one
INSERT INTO events (
    stream_type, stream_id, stream_version,
    event_type, data, metadata,
    actor_type, actor_id
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
)
RETURNING *;

-- name: GetStreamVersion :one
SELECT COALESCE(MAX(stream_version), 0)::INTEGER as version
FROM events
WHERE stream_type = $1 AND stream_id = $2;

-- name: LoadStream :many
SELECT * FROM events
WHERE stream_type = $1 AND stream_id = $2
ORDER BY stream_version;

-- name: LoadStreamFromVersion :many
SELECT * FROM events
WHERE stream_type = $1 AND stream_id = $2 AND stream_version > $3
ORDER BY stream_version;

-- name: LoadAllEvents :many
SELECT * FROM events
WHERE sequence_num > $1
ORDER BY sequence_num
LIMIT $2;

-- name: LoadEventsByType :many
SELECT * FROM events
WHERE event_type = $1
ORDER BY sequence_num DESC
LIMIT $2 OFFSET $3;

-- name: LoadEventsByActor :many
SELECT * FROM events
WHERE actor_type = $1 AND actor_id = $2
ORDER BY occurred_at DESC
LIMIT $3 OFFSET $4;

-- name: LoadEventsByStreamType :many
SELECT * FROM events
WHERE stream_type = $1
ORDER BY sequence_num DESC
LIMIT $2 OFFSET $3;

-- name: CountEventsByStreamType :one
SELECT COUNT(*) FROM events
WHERE stream_type = $1;

-- name: GetLatestSequence :one
SELECT COALESCE(MAX(sequence_num), 0)::BIGINT as sequence_num FROM events;

-- name: ListAuditEvents :many
SELECT * FROM events
WHERE ($1::TEXT = '' OR actor_id = $1)
  AND ($2::TEXT = '' OR stream_type = $2)
  AND ($3::TEXT = '' OR event_type = $3)
ORDER BY occurred_at DESC
LIMIT $4 OFFSET $5;

-- name: CountAuditEvents :one
SELECT COUNT(*) FROM events
WHERE ($1::TEXT = '' OR actor_id = $1)
  AND ($2::TEXT = '' OR stream_type = $2)
  AND ($3::TEXT = '' OR event_type = $3);

-- name: LoadOutputChunks :many
-- Load all output chunks for an execution, ordered by sequence
SELECT * FROM events
WHERE stream_type = 'execution'
  AND stream_id = $1
  AND event_type = 'OutputChunk'
ORDER BY stream_version;
