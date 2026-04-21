-- Queries for the terminal_sessions table. See migration 008 for
-- the full rationale — in short, this table replaces the per-chunk
-- TerminalInputChunk events on the audit stream. Lifecycle events
-- still exist; only the bulk stdin payload moves here.
--
-- Invariants enforced across these queries:
--
--   1. Idempotent. Any upsert is safe to call on a row that
--      already exists; it preserves data it did not explicitly set.
--   2. Bounded. `input` is capped at 8 MiB (octet_length). Appends
--      past the cap clamp the written bytes and flip input_truncated.
--   3. Ordered. Chunk appends are guarded by last_sequence so
--      duplicate or out-of-order retries do not corrupt `input`
--      or stutter chunk_count.

-- name: UpsertTerminalSessionStart :exec
-- Called from the TerminalSessionStarted inbox handler. The INSERT
-- is idempotent per session_id because a TerminalAuditChunk task
-- can race ahead of the lifecycle event on a busy inbox — the chunk
-- handler has its own INSERT ... ON CONFLICT that creates a
-- placeholder row, and this upsert then fills in the real metadata
-- without clobbering any stdin already appended.
INSERT INTO terminal_sessions (
    session_id, device_id, user_id, tty_user,
    started_at, cols, rows
) VALUES (
    $1, $2, $3, $4,
    $5, $6, $7
)
ON CONFLICT (session_id) DO UPDATE SET
    device_id  = EXCLUDED.device_id,
    user_id    = EXCLUDED.user_id,
    tty_user   = EXCLUDED.tty_user,
    started_at = EXCLUDED.started_at,
    cols       = EXCLUDED.cols,
    rows       = EXCLUDED.rows;

-- name: AppendTerminalSessionChunk :exec
-- Called from the TerminalAuditChunk inbox handler.
--
-- Two safety guards layered into a single statement:
--
--   * Sequence idempotency. The gateway's audit batcher stamps
--     each chunk with a strictly-monotonic per-session sequence.
--     We only apply the append when the incoming sequence is
--     greater than the stored last_sequence, so a duplicate or
--     reordered retry from Asynq is a no-op rather than a
--     double-append that would corrupt `input` and inflate
--     chunk_count.
--
--   * 8 MiB cap on `input`. The appended payload is clamped to
--     the remaining capacity (LEFT(bytes, GREATEST(0, cap -
--     current))) so a single oversized chunk still produces a
--     well-formed row and flips input_truncated to mark the loss.
--     Subsequent chunks clamp to zero bytes until retention or
--     archive runs.
--
-- The INSERT branch creates a placeholder when a chunk outruns
-- the lifecycle Started event. device_id and user_id come from
-- the chunk payload, so the placeholder is well-formed.
--
-- Concurrency note: this query's last_sequence guard defends
-- against Asynq REDELIVERY of a single task (same sequence twice),
-- but a NAIVE deployment with two workers dequeuing different
-- sequences for the same session in parallel could still drop
-- bytes on the loser of the race (whichever commits last fails
-- the guard and no-ops). To close that window, the control server
-- processes TypeTerminalAuditChunk on a dedicated Asynq server
-- with Concurrency=1 (queue ControlTerminalAuditQueue, wired up
-- in cmd/control/main.go). As long as the operator does not flip
-- that concurrency or re-route the task type to the main inbox
-- queue, per-session chunks commit strictly in sequence order.
INSERT INTO terminal_sessions (
    session_id, device_id, user_id, tty_user,
    started_at,
    input,
    input_truncated,
    last_sequence,
    chunk_count
) VALUES (
    sqlc.arg(session_id), sqlc.arg(device_id), sqlc.arg(user_id), '',
    NOW(),
    -- Postgres has no LEFT(bytea, int); use substring for bytea
    -- clamping. `FROM 1 FOR n` is 1-indexed inclusive.
    substring(sqlc.arg(input)::bytea FROM 1 FOR 8388608),
    octet_length(sqlc.arg(input)::bytea) > 8388608,
    sqlc.arg(sequence),
    1
)
ON CONFLICT (session_id) DO UPDATE SET
    input = terminal_sessions.input
          || substring(EXCLUDED.input FROM 1 FOR
                       GREATEST(0, 8388608 - octet_length(terminal_sessions.input))),
    input_truncated = terminal_sessions.input_truncated
                   OR (octet_length(EXCLUDED.input)
                       > GREATEST(0, 8388608 - octet_length(terminal_sessions.input))),
    last_sequence = EXCLUDED.last_sequence,
    chunk_count   = terminal_sessions.chunk_count + 1
  WHERE EXCLUDED.last_sequence > terminal_sessions.last_sequence;

-- name: MarkTerminalSessionStopped :exec
-- TerminalSessionStopped — clean end of session from the bridge.
-- Upsert form so a missing row (Start upsert failed AND no chunks
-- arrived) is still created with the stop metadata, rather than
-- silently no-oping and losing the session from history.
--
-- First-finalizer-wins: the ON CONFLICT update only applies when
-- exit_reason is still NULL, so if admin TerminateTerminalSession
-- ran first and the bridge's delayed Stop event catches up later,
-- the Stop does NOT overwrite exit_reason='terminated' or leave a
-- stale terminated_by next to exit_reason='stopped'. The audit
-- record reflects what actually ended the session.
--
-- Orphan-row caveat: when this query creates a fresh row (Start
-- upsert failed AND no chunks arrived), started_at defaults to
-- NOW() — the time this finalizer ran, not the real session
-- start. Such rows appear as zero-duration sessions in the
-- history. The orphan case requires a DB outage exactly between
-- the event append and the Start upsert AND the user typing no
-- keys, which is vanishingly rare; flag in the UI rather than
-- add a nullable started_at.
INSERT INTO terminal_sessions (
    session_id, device_id, user_id, tty_user,
    started_at, stopped_at, exit_reason, exit_code
) VALUES (
    $1, $4, $5, '',
    NOW(), $2, 'stopped', $3
)
ON CONFLICT (session_id) DO UPDATE SET
    stopped_at  = EXCLUDED.stopped_at,
    exit_reason = 'stopped',
    exit_code   = EXCLUDED.exit_code
  WHERE terminal_sessions.exit_reason IS NULL;

-- name: MarkTerminalSessionTerminated :exec
-- TerminalSessionTerminated — admin force-kill via
-- ControlService.TerminateTerminalSession. Upsert form for the
-- same reason as MarkTerminalSessionStopped, with the same
-- first-finalizer-wins guard — if the bridge already emitted a
-- graceful Stop event, a subsequent admin Terminate does not
-- clobber exit_code or flip exit_reason.
INSERT INTO terminal_sessions (
    session_id, device_id, user_id, tty_user,
    started_at, stopped_at, exit_reason, terminated_by
) VALUES (
    $1, $4, $5, '',
    NOW(), $2, 'terminated', $3
)
ON CONFLICT (session_id) DO UPDATE SET
    stopped_at    = EXCLUDED.stopped_at,
    exit_reason   = 'terminated',
    terminated_by = EXCLUDED.terminated_by
  WHERE terminal_sessions.exit_reason IS NULL;

-- name: GetTerminalSession :one
-- Full row fetch for the session-replay detail view.
SELECT * FROM terminal_sessions WHERE session_id = $1;

-- name: ListTerminalSessionsByDevice :many
-- Device detail page: most-recent sessions on one device.
SELECT * FROM terminal_sessions
WHERE device_id = $1
ORDER BY started_at DESC
LIMIT $2 OFFSET $3;

-- name: ListTerminalSessionsByUser :many
-- Admin audit: most-recent sessions initiated by one user.
SELECT * FROM terminal_sessions
WHERE user_id = $1
ORDER BY started_at DESC
LIMIT $2 OFFSET $3;

-- name: ListTerminalSessions :many
-- Fleet-wide history: newest first. Caller supplies a date filter
-- to keep the working set bounded. Pagination via LIMIT/OFFSET is
-- fine at the expected volume (tens of sessions per device per
-- day); upgrade to keyset pagination later if this ever becomes
-- a hot query.
SELECT * FROM terminal_sessions
WHERE started_at >= $1 AND started_at < $2
ORDER BY started_at DESC
LIMIT $3 OFFSET $4;

-- name: DeleteTerminalSessionsBefore :exec
-- Retention: drop sessions started before the cutoff. Simple
-- delete because nothing else in the schema references
-- terminal_sessions; no cascade needed.
DELETE FROM terminal_sessions
WHERE started_at < $1;
