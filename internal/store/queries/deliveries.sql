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
) VALUES (?, ?, ?, ?, 'PENDING', ?, ?, ?)
RETURNING *;

-- name: GetDelivery :one
SELECT * FROM deliveries WHERE delivery_id = ?;

-- name: MarkDeliveryPushed :execrows
-- PENDING or a re-push of an already PUSHED row (a reconnect), never a
-- row that has already been received. push_epoch only moves forward,
-- so a stale connection cannot claim the push.
UPDATE deliveries
SET state = 'PUSHED',
    pushed_at = sqlc.arg(pushed_at),
    push_epoch = sqlc.arg(push_epoch),
    attempt_count = attempt_count + 1,
    available_at = sqlc.arg(available_at)
WHERE delivery_id = sqlc.arg(delivery_id)
  AND state IN ('PENDING', 'PUSHED')
  AND push_epoch <= sqlc.arg(push_epoch);

-- name: MarkDeliveryAckedReceipt :execrows
-- The agent confirmed DURABLE receipt. Idempotent on replay: a second
-- ack for an already-acked row matches nothing and is not an error to
-- the caller, which is what makes reconnect retries safe.
UPDATE deliveries
SET state = 'ACKED_RECEIPT',
    acked_receipt_at = ?
WHERE delivery_id = ?
  AND state = 'PUSHED';

-- name: MarkDeliveryResult :execrows
-- A per-action and manifest result. Only reachable from a confirmed
-- receipt, which the schema also enforces.
UPDATE deliveries
SET state = ?,
    terminal_at = ?,
    result_code = ?
WHERE delivery_id = ?
  AND state = 'ACKED_RECEIPT';

-- name: MarkDeliveryTerminalWithoutReceipt :execrows
-- Expiry or cancellation of a delivery the device never received.
UPDATE deliveries
SET state = sqlc.arg(new_state),
    terminal_at = sqlc.arg(terminal_at),
    result_code = sqlc.arg(result_code)
WHERE delivery_id = sqlc.arg(delivery_id)
  AND state IN ('PENDING', 'PUSHED');

-- name: ListDueDeliveriesForDevices :many
-- The sweep only considers live connections. Offline rows stay durable and a
-- reconnect queues them directly; excluding them here prevents a large offline
-- backlog from monopolising every bounded sweep page.
SELECT * FROM deliveries
WHERE device_id IN (sqlc.slice(device_ids))
  AND state IN ('PENDING', 'PUSHED')
  AND available_at <= sqlc.arg(available_at)
ORDER BY available_at
LIMIT sqlc.arg(page_size);

-- name: ListSendableDeliveriesForDevice :many
-- Manifest frames one connected agent can still receive, oldest first. A row
-- already acknowledged is awaiting results, not another manifest send.
SELECT * FROM deliveries
WHERE device_id = ?
  AND state IN ('PENDING', 'PUSHED')
ORDER BY created_at
LIMIT ?;

-- name: ListExpiredDeliveries :many
SELECT * FROM deliveries
WHERE expires_at IS NOT NULL
  AND expires_at <= ?
  AND terminal_at IS NULL
ORDER BY expires_at
LIMIT ?;
