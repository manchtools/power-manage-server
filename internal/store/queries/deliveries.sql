-- Durable delivery rows.
--
-- Every state advance is a conditional UPDATE that names the state it
-- expects to find, so a stale connection or a duplicate result cannot
-- move a delivery backwards: the statement matches zero rows instead.

-- name: InsertDelivery :one
-- Commits the complete manifest before any send is attempted.
INSERT INTO deliveries (
    delivery_id, device_id, manifest_id, manifest,
    state, operation_id, available_at, expires_at
) VALUES ($1, $2, $3, $4, 'PENDING', $5, $6, $7)
RETURNING *;

-- name: GetDelivery :one
SELECT * FROM deliveries WHERE delivery_id = $1;

-- name: MarkDeliveryPushed :execrows
-- PENDING or a re-push of an already PUSHED row (a reconnect), never a
-- row that has already been received. push_epoch only moves forward,
-- so a stale connection cannot claim the push.
UPDATE deliveries
SET state = 'PUSHED',
    pushed_at = $2,
    push_epoch = $3,
    attempt_count = attempt_count + 1,
    available_at = $4
WHERE delivery_id = $1
  AND state IN ('PENDING', 'PUSHED')
  AND push_epoch <= $3;

-- name: MarkDeliveryAckedReceipt :execrows
-- The agent confirmed DURABLE receipt. Idempotent on replay: a second
-- ack for an already-acked row matches nothing and is not an error to
-- the caller, which is what makes reconnect retries safe.
UPDATE deliveries
SET state = 'ACKED_RECEIPT',
    acked_receipt_at = $2
WHERE delivery_id = $1
  AND state = 'PUSHED';

-- name: MarkDeliveryResult :execrows
-- A per-action and manifest result. Only reachable from a confirmed
-- receipt, which the schema also enforces.
UPDATE deliveries
SET state = $2,
    terminal_at = $3,
    result_code = $4
WHERE delivery_id = $1
  AND state = 'ACKED_RECEIPT';

-- name: MarkDeliveryTerminalWithoutReceipt :execrows
-- Expiry or cancellation of a delivery the device never received.
UPDATE deliveries
SET state = $2,
    terminal_at = $3,
    result_code = $4
WHERE delivery_id = $1
  AND state IN ('PENDING', 'PUSHED')
  AND $2 IN ('EXPIRED', 'CANCELLED');

-- name: ListDueDeliveries :many
-- The sweep's work list.
SELECT * FROM deliveries
WHERE state IN ('PENDING', 'PUSHED')
  AND available_at <= $1
ORDER BY available_at
LIMIT $2;

-- name: ListPendingDeliveriesForDevice :many
-- What one agent still owes, oldest first.
SELECT * FROM deliveries
WHERE device_id = $1
  AND state IN ('PENDING', 'PUSHED', 'ACKED_RECEIPT')
ORDER BY created_at
LIMIT $2;

-- name: ListExpiredDeliveries :many
SELECT * FROM deliveries
WHERE expires_at IS NOT NULL
  AND expires_at <= $1
  AND terminal_at IS NULL
ORDER BY expires_at
LIMIT $2;
