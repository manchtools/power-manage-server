-- The append-only audit chain.
--
-- Every write here runs inside the transaction store.WithAudit opened,
-- after LockAuditChainHead has serialised the appenders. There is no
-- UPDATE or DELETE statement for the two chain tables in this file
-- other than the sanctioned retention delete: the database rejects
-- them anyway, and a query that exists is a query that gets called.

-- name: LockAuditChainHead :one
-- Take the stream's head under a row lock and return the tip. Every
-- appender starts here, which is what makes chain_seq gapless and the
-- chain a total order under concurrency.
SELECT stream, head_hash, height
FROM audit_chain_head
WHERE stream = ?
;

-- name: GetAuditChainHead :one
SELECT stream, head_hash, height
FROM audit_chain_head
WHERE stream = ?;

-- name: AdvanceAuditChainHead :exec
-- Move the tip to the last row this appender wrote. Only ever called
-- with a height strictly greater than the locked one.
UPDATE audit_chain_head
SET head_hash = ?, height = ?, updated_at = CURRENT_TIMESTAMP
WHERE stream = ?;

-- name: InsertAuditOperation :one
INSERT INTO audit_operations (
    operation_id, stream, chain_seq,
    operation_class, actor_type, actor_id, actor_fingerprint,
    origin, origin_fingerprint, request_descriptor,
    authorization_outcome, authorization_detail,
    result, result_code, occurred_at,
    sealed_detail, sealed_detail_subject,
    prev_hash, row_hash
) VALUES (
    ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?,
    ?, ?,
    ?, ?, ?,
    ?, ?,
    ?, ?
)
RETURNING operation_id, chain_seq, row_hash;

-- name: InsertAuditEffect :one
INSERT INTO audit_effects (
    effect_id, operation_id, stream, chain_seq, effect_seq,
    resource_type, resource_id, action, outcome,
    changed_fields,
    before_ref, after_ref, before_flag, after_flag, before_count, after_count,
    evidence_kind, evidence_fingerprint,
    sealed_detail, sealed_detail_subject,
    occurred_at, prev_hash, row_hash
) VALUES (
    ?, ?, ?, ?, ?,
    ?, ?, ?, ?,
    ?,
    ?, ?, ?, ?, ?, ?,
    ?, ?,
    ?, ?,
    ?, ?, ?
)
RETURNING effect_id, chain_seq, row_hash;

-- name: GetAuditOperation :one
SELECT * FROM audit_operations WHERE operation_id = ?;

-- name: CountAuditOperations :one
SELECT COUNT(*) FROM audit_operations WHERE stream = ?;

-- name: NextAuditEffectSeq :one
-- The next position within an operation. Late effects continue the
-- numbering the initial ones started.
SELECT CAST(COALESCE(MAX(effect_seq) + 1, 0) AS INTEGER)
FROM audit_effects
WHERE operation_id = ?;

-- name: ListAuditChainOperations :many
-- Operation rows of one chain segment, ordered by chain position.
-- Verification merges this with ListAuditChainEffects.
SELECT * FROM audit_operations
WHERE stream = ? AND chain_seq >= ? AND chain_seq <= ?
ORDER BY chain_seq;

-- name: ListAuditChainEffects :many
SELECT * FROM audit_effects
WHERE stream = ? AND chain_seq >= ? AND chain_seq <= ?
ORDER BY chain_seq;

-- name: ListAuditEffectsForOperation :many
SELECT * FROM audit_effects
WHERE operation_id = ?
ORDER BY effect_seq;

-- name: ListAuditEventRows :many
-- The retained AuditEvent wire shape represents each resource effect. An
-- operation with no effects is still evidence (most importantly a rejected
-- authentication attempt), so it contributes one operation-only row instead
-- of disappearing from the API. Operation rows that do have effects are not
-- duplicated in the result.
SELECT *
FROM audit_event_rows
WHERE (sqlc.arg(actor_id) = '' OR actor_id = sqlc.arg(actor_id))
  AND (sqlc.arg(event_type) = '' OR instr(lower(event_type), lower(sqlc.arg(event_type))) > 0)
  AND occurred_at >= sqlc.arg(filter_from_time)
  AND occurred_at <= sqlc.arg(filter_to_time)
  AND (sqlc.arg(before_seq) = 0 OR chain_seq < sqlc.arg(before_seq))
  AND (
      json_array_length(sqlc.arg(stream_types_json)) = 0
      OR stream_type IN (
          SELECT CAST(value AS TEXT) FROM json_each(sqlc.arg(stream_types_json))
      )
  )
ORDER BY chain_seq DESC
LIMIT sqlc.arg(row_limit);

-- name: CountAuditEventRows :one
SELECT COUNT(*)
FROM audit_event_rows
WHERE (sqlc.arg(actor_id) = '' OR actor_id = sqlc.arg(actor_id))
  AND (sqlc.arg(event_type) = '' OR instr(lower(event_type), lower(sqlc.arg(event_type))) > 0)
  AND (
      json_array_length(sqlc.arg(stream_types_json)) = 0
      OR stream_type IN (
          SELECT CAST(value AS TEXT) FROM json_each(sqlc.arg(stream_types_json))
      )
  );

-- ---------------------------------------------------------------------------
-- Anchors
-- ---------------------------------------------------------------------------

-- name: InsertAuditChainAnchor :one
INSERT INTO audit_chain_anchors (
    anchor_id, stream, chain_seq, row_hash, captured_at, external_ref
) VALUES (?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetLatestAuditChainAnchor :one
SELECT * FROM audit_chain_anchors
WHERE stream = ?
ORDER BY chain_seq DESC
LIMIT 1;

-- name: ListAuditChainAnchors :many
SELECT * FROM audit_chain_anchors
WHERE stream = ?
ORDER BY chain_seq;

-- The chain interleaves two tables, so "the row at position N" is one
-- lookup per table and a merge in Go. Expressing it as a UNION here
-- would only move the merge into SQL the query planner has to
-- re-derive on every call.

-- name: GetAuditOperationRowHashAt :one
SELECT row_hash FROM audit_operations WHERE stream = ? AND chain_seq = ?;

-- name: GetAuditEffectRowHashAt :one
SELECT row_hash FROM audit_effects WHERE stream = ? AND chain_seq = ?;

-- ---------------------------------------------------------------------------
-- Retention
-- ---------------------------------------------------------------------------

-- name: CountAuditOperationsAtOrBelow :one
SELECT COUNT(*) FROM audit_operations WHERE stream = ? AND chain_seq <= ?;

-- name: CountAuditEffectsAtOrBelow :one
SELECT COUNT(*) FROM audit_effects WHERE stream = ? AND chain_seq <= ?;

-- name: FirstAuditOperationSeqAbove :one
SELECT CAST(COALESCE(MIN(chain_seq), 0) AS INTEGER)
FROM audit_operations WHERE stream = ? AND chain_seq > ?;

-- name: FirstAuditEffectSeqAbove :one
SELECT CAST(COALESCE(MIN(chain_seq), 0) AS INTEGER)
FROM audit_effects WHERE stream = ? AND chain_seq > ?;

-- name: CountAuditEffectsStrandedByBoundary :one
-- Effects that would survive a deletion at this boundary while their
-- operation would not. A boundary that strands any effect splits an
-- operation from its evidence and must be refused.
SELECT COUNT(*)
FROM audit_effects e
JOIN audit_operations o ON o.operation_id = e.operation_id
WHERE e.stream = ? AND e.chain_seq > ? AND o.chain_seq <= ?;

-- name: FindClosedAuditRetentionBoundary :one
-- Pick the newest row older than the retention cutoff that would not strand a
-- later effect after deleting its operation. The primitive repeats this check
-- transactionally before deletion; this query only chooses a viable candidate.
WITH candidates AS (
    SELECT o.chain_seq FROM audit_operations o
    WHERE o.stream = sqlc.arg(stream) AND o.occurred_at < sqlc.arg(cutoff)
    UNION ALL
    SELECT e.chain_seq FROM audit_effects e
    WHERE e.stream = sqlc.arg(stream) AND e.occurred_at < sqlc.arg(cutoff)
)
SELECT CAST(COALESCE(MAX(c.chain_seq), 0) AS INTEGER)
FROM candidates c
WHERE NOT EXISTS (
    SELECT 1
    FROM audit_operations o
    JOIN audit_effects e ON e.operation_id = o.operation_id
    WHERE o.stream = sqlc.arg(stream) AND o.chain_seq <= c.chain_seq AND e.chain_seq > c.chain_seq
);

-- name: DeleteAuditEffectsAtOrBelow :execrows
-- Sanctioned retention delete. Only succeeds inside a transaction that
-- has set pm.audit_retention_active and pm.audit_retention_up_to_seq;
-- the append-only trigger rejects it otherwise. Effects go first so
-- the operations they reference still exist while they are removed.
DELETE FROM audit_effects WHERE stream = ? AND chain_seq <= ?;

-- name: DeleteAuditOperationsAtOrBelow :execrows
DELETE FROM audit_operations WHERE stream = ? AND chain_seq <= ?;

-- name: ArmAuditRetentionGuard :exec
INSERT INTO audit_retention_guard (stream, boundary_seq) VALUES (?, ?);

-- name: DisarmAuditRetentionGuard :exec
DELETE FROM audit_retention_guard WHERE stream = ?;

-- name: InsertAuditChainCheckpoint :one
INSERT INTO audit_chain_checkpoints (
    checkpoint_id, stream, boundary_seq, boundary_hash, resume_seq,
    deleted_rows, archive_digest, archive_ref, archived_at, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: ListAuditChainCheckpoints :many
SELECT * FROM audit_chain_checkpoints
WHERE stream = ?
ORDER BY boundary_seq;
