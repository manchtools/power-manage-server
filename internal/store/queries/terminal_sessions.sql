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
-- Called from the TerminalSessionStarted inbox handler. This is the
-- ONLY query that bootstraps a terminal_sessions row — the
-- AppendTerminalSessionChunk path below is UPDATE-only and cannot
-- INSERT, so an audit chunk can never mint an owner-bearing row with
-- attacker-chosen device_id/user_id. If a chunk races ahead of the
-- lifecycle Started event it is dropped by the inbox handler (the
-- session does not exist yet); the agent re-tees on the next batch
-- once Started has created the row. The upsert remains idempotent per
-- session_id so a redelivered Started event is harmless.
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
-- UPDATE-only (defense in depth, server SA-C2 / device-origin trust
-- binding): this statement can ONLY append stdin onto an EXISTING
-- session row, keyed by session_id. It deliberately does NOT INSERT
-- and does NOT set device_id/user_id — those owners are written once,
-- by UpsertTerminalSessionStart from the mTLS-authenticated lifecycle
-- event. A compromised gateway relaying a forged chunk for an unknown
-- session therefore updates zero rows (the inbox handler additionally
-- drops unknown sessions before reaching here), so it can never mint a
-- placeholder row with attacker-chosen owners that a later Started
-- event would bless. Ownership of the chunk is checked in the handler
-- against the session row BEFORE this runs.
--
-- Two safety guards retained from the previous upsert form:
--
--   * Sequence idempotency. The gateway's audit batcher stamps each
--     chunk with a strictly-monotonic per-session sequence. We only
--     apply the append when the incoming sequence is greater than the
--     stored last_sequence, so a duplicate or reordered retry from
--     Asynq is a no-op rather than a double-append that would corrupt
--     `input` and inflate chunk_count.
--
--   * 8 MiB cap on `input`. The appended payload is clamped to the
--     remaining capacity so a single oversized chunk still produces a
--     well-formed row and flips input_truncated to mark the loss.
--     Subsequent chunks clamp to zero bytes until retention or archive
--     runs.
--
-- Concurrency note: the last_sequence guard defends against Asynq
-- REDELIVERY of a single task (same sequence twice), but a NAIVE
-- deployment with two workers dequeuing different sequences for the
-- same session in parallel could still drop bytes on the loser of the
-- race (whichever commits last fails the guard and no-ops). To close
-- that window, the control server processes TypeTerminalAuditChunk on
-- a dedicated Asynq server with Concurrency=1 (queue
-- ControlTerminalAuditQueue, wired up in cmd/control/main.go). As long
-- as the operator does not flip that concurrency or re-route the task
-- type to the main inbox queue, per-session chunks commit strictly in
-- sequence order.
UPDATE terminal_sessions SET
    input = input
          || substring(sqlc.arg(input)::bytea FROM 1 FOR
                       GREATEST(0, 8388608 - octet_length(input))),
    input_truncated = input_truncated
                   OR (octet_length(sqlc.arg(input)::bytea)
                       > GREATEST(0, 8388608 - octet_length(input))),
    last_sequence = sqlc.arg(sequence),
    chunk_count   = chunk_count + 1
  WHERE session_id = sqlc.arg(session_id)
    AND sqlc.arg(sequence) > last_sequence;

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
