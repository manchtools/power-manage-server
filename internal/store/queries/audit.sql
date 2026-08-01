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
WHERE stream = $1
FOR UPDATE;

-- name: GetAuditChainHead :one
SELECT stream, head_hash, height
FROM audit_chain_head
WHERE stream = $1;

-- name: AdvanceAuditChainHead :exec
-- Move the tip to the last row this appender wrote. Only ever called
-- with a height strictly greater than the locked one.
UPDATE audit_chain_head
SET head_hash = $2, height = $3, updated_at = now()
WHERE stream = $1;

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
    $1, $2, $3,
    $4, $5, $6, $7,
    $8, $9, $10,
    $11, $12,
    $13, $14, $15,
    $16, $17,
    $18, $19
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
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9,
    $10,
    $11, $12, $13, $14, $15, $16,
    $17, $18,
    $19, $20,
    $21, $22, $23
)
RETURNING effect_id, chain_seq, row_hash;

-- name: GetAuditOperation :one
SELECT * FROM audit_operations WHERE operation_id = $1;

-- name: CountAuditOperations :one
SELECT COUNT(*) FROM audit_operations WHERE stream = $1;

-- name: NextAuditEffectSeq :one
-- The next position within an operation. Late effects continue the
-- numbering the initial ones started.
SELECT COALESCE(MAX(effect_seq) + 1, 0)::int
FROM audit_effects
WHERE operation_id = $1;

-- name: ListAuditChainOperations :many
-- Operation rows of one chain segment, ordered by chain position.
-- Verification merges this with ListAuditChainEffects.
SELECT * FROM audit_operations
WHERE stream = $1 AND chain_seq >= $2 AND chain_seq <= $3
ORDER BY chain_seq;

-- name: ListAuditChainEffects :many
SELECT * FROM audit_effects
WHERE stream = $1 AND chain_seq >= $2 AND chain_seq <= $3
ORDER BY chain_seq;

-- name: ListAuditEffectsForOperation :many
SELECT * FROM audit_effects
WHERE operation_id = $1
ORDER BY effect_seq;

-- name: ListAuditEventRows :many
-- The retained AuditEvent wire shape represents each resource effect. An
-- operation with no effects is still evidence (most importantly a rejected
-- authentication attempt), so it contributes one operation-only row instead
-- of disappearing from the API. Operation rows that do have effects are not
-- duplicated in the result.
WITH audit_event_rows AS (
    SELECT
        e.effect_id AS id,
        e.chain_seq,
        e.resource_type AS stream_type,
        e.resource_id AS stream_id,
        e.action AS event_type,
        o.operation_id,
        o.operation_class,
        o.actor_type,
        o.actor_id,
        o.actor_fingerprint,
        o.origin,
        o.origin_fingerprint,
        o.request_descriptor,
        o.authorization_outcome,
        o.authorization_detail,
        o.result,
        o.result_code,
        e.outcome AS effect_outcome,
        e.changed_fields,
        e.before_ref,
        e.after_ref,
        e.before_flag,
        e.after_flag,
        e.before_count,
        e.after_count,
        e.evidence_kind,
        e.evidence_fingerprint,
        e.occurred_at
    FROM audit_effects e
    JOIN audit_operations o ON o.operation_id = e.operation_id
    WHERE e.stream = 'control'

    UNION ALL

    SELECT
        o.operation_id AS id,
        o.chain_seq,
        CASE WHEN o.operation_class = 'REJECTED_AUTHENTICATION'
             THEN 'authentication' ELSE 'operation' END AS stream_type,
        o.operation_id AS stream_id,
        CASE WHEN o.operation_class = 'REJECTED_AUTHENTICATION'
             THEN 'AUTHENTICATION_REJECTED' ELSE o.operation_class END AS event_type,
        o.operation_id,
        o.operation_class,
        o.actor_type,
        o.actor_id,
        o.actor_fingerprint,
        o.origin,
        o.origin_fingerprint,
        o.request_descriptor,
        o.authorization_outcome,
        o.authorization_detail,
        o.result,
        o.result_code,
        ''::text AS effect_outcome,
        '{}'::text[] AS changed_fields,
        NULL::text AS before_ref,
        NULL::text AS after_ref,
        NULL::boolean AS before_flag,
        NULL::boolean AS after_flag,
        NULL::bigint AS before_count,
        NULL::bigint AS after_count,
        ''::text AS evidence_kind,
        ''::text AS evidence_fingerprint,
        o.occurred_at
    FROM audit_operations o
    WHERE o.stream = 'control'
      AND NOT EXISTS (
          SELECT 1 FROM audit_effects e WHERE e.operation_id = o.operation_id
      )
)
SELECT *
FROM audit_event_rows ev
WHERE (sqlc.arg(actor_id)::text = '' OR ev.actor_id = sqlc.arg(actor_id))
  AND (cardinality(sqlc.arg(stream_types)::text[]) = 0 OR ev.stream_type = ANY(sqlc.arg(stream_types)::text[]))
  AND (sqlc.arg(event_type)::text = '' OR strpos(lower(ev.event_type), lower(sqlc.arg(event_type))) > 0)
  AND ev.occurred_at >= sqlc.arg(occurred_from)::timestamptz
  AND ev.occurred_at <= sqlc.arg(occurred_to)::timestamptz
  AND (sqlc.arg(before_seq)::bigint = 0 OR ev.chain_seq < sqlc.arg(before_seq))
ORDER BY ev.chain_seq DESC
LIMIT sqlc.arg(row_limit);

-- name: CountAuditEventRows :one
WITH audit_event_rows AS (
    SELECT
        e.resource_type AS stream_type,
        e.action AS event_type,
        o.actor_id,
        e.occurred_at
    FROM audit_effects e
    JOIN audit_operations o ON o.operation_id = e.operation_id
    WHERE e.stream = 'control'

    UNION ALL

    SELECT
        CASE WHEN o.operation_class = 'REJECTED_AUTHENTICATION'
             THEN 'authentication' ELSE 'operation' END AS stream_type,
        CASE WHEN o.operation_class = 'REJECTED_AUTHENTICATION'
             THEN 'AUTHENTICATION_REJECTED' ELSE o.operation_class END AS event_type,
        o.actor_id,
        o.occurred_at
    FROM audit_operations o
    WHERE o.stream = 'control'
      AND NOT EXISTS (
          SELECT 1 FROM audit_effects e WHERE e.operation_id = o.operation_id
      )
)
SELECT COUNT(*)
FROM audit_event_rows ev
WHERE (sqlc.arg(actor_id)::text = '' OR ev.actor_id = sqlc.arg(actor_id))
  AND (cardinality(sqlc.arg(stream_types)::text[]) = 0 OR ev.stream_type = ANY(sqlc.arg(stream_types)::text[]))
  AND (sqlc.arg(event_type)::text = '' OR strpos(lower(ev.event_type), lower(sqlc.arg(event_type))) > 0);

-- ---------------------------------------------------------------------------
-- Anchors
-- ---------------------------------------------------------------------------

-- name: InsertAuditChainAnchor :one
INSERT INTO audit_chain_anchors (
    anchor_id, stream, chain_seq, row_hash, captured_at, external_ref
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetLatestAuditChainAnchor :one
SELECT * FROM audit_chain_anchors
WHERE stream = $1
ORDER BY chain_seq DESC
LIMIT 1;

-- name: ListAuditChainAnchors :many
SELECT * FROM audit_chain_anchors
WHERE stream = $1
ORDER BY chain_seq;

-- The chain interleaves two tables, so "the row at position N" is one
-- lookup per table and a merge in Go. Expressing it as a UNION here
-- would only move the merge into SQL the query planner has to
-- re-derive on every call.

-- name: GetAuditOperationRowHashAt :one
SELECT row_hash FROM audit_operations WHERE stream = $1 AND chain_seq = $2;

-- name: GetAuditEffectRowHashAt :one
SELECT row_hash FROM audit_effects WHERE stream = $1 AND chain_seq = $2;

-- ---------------------------------------------------------------------------
-- Retention
-- ---------------------------------------------------------------------------

-- name: CountAuditOperationsAtOrBelow :one
SELECT COUNT(*) FROM audit_operations WHERE stream = $1 AND chain_seq <= $2;

-- name: CountAuditEffectsAtOrBelow :one
SELECT COUNT(*) FROM audit_effects WHERE stream = $1 AND chain_seq <= $2;

-- name: FirstAuditOperationSeqAbove :one
SELECT COALESCE(MIN(chain_seq), 0)::bigint
FROM audit_operations WHERE stream = $1 AND chain_seq > $2;

-- name: FirstAuditEffectSeqAbove :one
SELECT COALESCE(MIN(chain_seq), 0)::bigint
FROM audit_effects WHERE stream = $1 AND chain_seq > $2;

-- name: CountAuditEffectsStrandedByBoundary :one
-- Effects that would survive a deletion at this boundary while their
-- operation would not. A boundary that strands any effect splits an
-- operation from its evidence and must be refused.
SELECT COUNT(*)
FROM audit_effects e
JOIN audit_operations o ON o.operation_id = e.operation_id
WHERE e.stream = $1 AND e.chain_seq > $2 AND o.chain_seq <= $2;

-- name: DeleteAuditEffectsAtOrBelow :execrows
-- Sanctioned retention delete. Only succeeds inside a transaction that
-- has set pm.audit_retention_active and pm.audit_retention_up_to_seq;
-- the append-only trigger rejects it otherwise. Effects go first so
-- the operations they reference still exist while they are removed.
DELETE FROM audit_effects WHERE stream = $1 AND chain_seq <= $2;

-- name: DeleteAuditOperationsAtOrBelow :execrows
DELETE FROM audit_operations WHERE stream = $1 AND chain_seq <= $2;

-- name: InsertAuditChainCheckpoint :one
INSERT INTO audit_chain_checkpoints (
    checkpoint_id, stream, boundary_seq, boundary_hash, resume_seq,
    deleted_rows, archive_digest, archive_ref, archived_at, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: ListAuditChainCheckpoints :many
SELECT * FROM audit_chain_checkpoints
WHERE stream = $1
ORDER BY boundary_seq;
