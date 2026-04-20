-- Queries for the terminal_sessions table. See migration 008 for
-- the full rationale — in short, this table replaces the per-chunk
-- TerminalInputChunk events on the audit stream. Lifecycle events
-- still exist; only the bulk stdin payload moves here.

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
-- Called from the TerminalAuditChunk inbox handler. Uses
-- INSERT ... ON CONFLICT so a chunk arriving before the lifecycle
-- Start event still produces a row (minimally populated — the
-- Start event's later upsert completes it). device_id and user_id
-- are required columns; the chunk payload carries them, so the
-- placeholder insert is well-formed.
INSERT INTO terminal_sessions (
    session_id, device_id, user_id, tty_user,
    started_at, input, chunk_count
) VALUES (
    $1, $2, $3, '',
    NOW(), $4, 1
)
ON CONFLICT (session_id) DO UPDATE SET
    input       = terminal_sessions.input || EXCLUDED.input,
    chunk_count = terminal_sessions.chunk_count + 1;

-- name: MarkTerminalSessionStopped :exec
-- TerminalSessionStopped — clean end of session from the bridge.
UPDATE terminal_sessions
SET stopped_at  = $2,
    exit_reason = 'stopped',
    exit_code   = $3
WHERE session_id = $1;

-- name: MarkTerminalSessionTerminated :exec
-- TerminalSessionTerminated — admin force-kill via
-- ControlService.TerminateTerminalSession.
UPDATE terminal_sessions
SET stopped_at    = $2,
    exit_reason   = 'terminated',
    terminated_by = $3
WHERE session_id = $1;

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
