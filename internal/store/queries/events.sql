-- name: AppendEvent :one
-- id is a ULID minted in Go (F-15 / spec 20) — the DB never mints a
-- random identifier.
INSERT INTO events (
    id, stream_type, stream_id, stream_version,
    event_type, data, metadata,
    actor_type, actor_id
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
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
  AND ($3::TEXT = '' OR event_type ILIKE '%' || replace(replace(replace($3, '!', '!!'), '%', '!%'), '_', '!_') || '%' ESCAPE '!')
ORDER BY occurred_at DESC
LIMIT $4 OFFSET $5;

-- name: CountAuditEvents :one
SELECT COUNT(*) FROM events
WHERE ($1::TEXT = '' OR actor_id = $1)
  AND ($2::TEXT = '' OR stream_type = $2)
  AND ($3::TEXT = '' OR event_type ILIKE '%' || replace(replace(replace($3, '!', '!!'), '%', '!%'), '_', '!_') || '%' ESCAPE '!');

-- name: LoadOutputChunks :many
-- Load output chunks for an execution, ordered by sequence, bounded by $2 rows
-- so a chunk flood can't load an unbounded slice into control memory (spec 29 S6).
SELECT * FROM events
WHERE stream_type = 'execution'
  AND stream_id = $1
  AND event_type = 'OutputChunk'
ORDER BY stream_version
LIMIT $2;

-- name: ExportAuditEvents :many
-- Keyset export feed for the audit-log export (spec 26). Same filter
-- semantics as ListAuditEvents (exact actor, ILIKE-escaped event-type
-- substring) plus a stream-type set and an occurred_at range to match
-- what the audit view can express. Keyset on sequence_num — not
-- OFFSET — so events appended mid-export can't shift rows into a
-- later page and duplicate them in the artifact.
SELECT * FROM events
WHERE (@actor_id::TEXT = '' OR actor_id = @actor_id)
  AND (@stream_types::TEXT[] IS NULL OR cardinality(@stream_types::TEXT[]) = 0 OR stream_type = ANY(@stream_types))
  AND (@event_type::TEXT = '' OR event_type ILIKE '%' || replace(replace(replace(@event_type, '!', '!!'), '%', '!%'), '_', '!_') || '%' ESCAPE '!')
  AND (@occurred_from::TIMESTAMPTZ IS NULL OR occurred_at >= @occurred_from)
  AND (@occurred_to::TIMESTAMPTZ IS NULL OR occurred_at <= @occurred_to)
  AND (@before_seq::BIGINT = 0 OR sequence_num < @before_seq)
ORDER BY sequence_num DESC
LIMIT @page_size;

-- name: ListAuditEventsForWarm :many
SELECT * FROM events
WHERE occurred_at >= NOW() - INTERVAL '90 days'
ORDER BY occurred_at DESC
LIMIT $1 OFFSET $2;

-- name: CountAuditEventsForWarm :one
SELECT COUNT(*) FROM events
WHERE occurred_at >= NOW() - INTERVAL '90 days';

