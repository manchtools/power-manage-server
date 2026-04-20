-- +goose Up

-- terminal_sessions is the canonical record of one remote terminal
-- session. It replaces the earlier pattern of streaming per-keystroke
-- TerminalInputChunk events into the append-only event store, which
-- floodeded the event stream with opaque single-byte fragments and
-- left the Terminal Sessions UI no way to group them for replay.
--
-- This is a purpose-built table, NOT a projection of events:
--   * The three lifecycle events (TerminalSessionStarted /
--     TerminalSessionStopped / TerminalSessionTerminated) stay in
--     the event stream as audit-worthy records of who started /
--     ended / force-killed a session.
--   * Stdin is accumulated directly into the `input` BYTEA column
--     by the inbox worker on every TerminalAuditChunk task, so
--     chunks never become events in the first place.
--
-- Retention is a plain DELETE on this table — no cross-table
-- orchestration with the event store required.
CREATE TABLE terminal_sessions (
    session_id    TEXT PRIMARY KEY,
    device_id     TEXT NOT NULL,
    user_id       TEXT NOT NULL,
    tty_user      TEXT NOT NULL,
    started_at    TIMESTAMPTZ NOT NULL,
    stopped_at    TIMESTAMPTZ,
    exit_reason   TEXT,
    exit_code     INTEGER,
    terminated_by TEXT,
    input         BYTEA NOT NULL DEFAULT '\x'::bytea,
    chunk_count   INTEGER NOT NULL DEFAULT 0,
    cols          INTEGER NOT NULL DEFAULT 0,
    rows          INTEGER NOT NULL DEFAULT 0
);

-- Indexes sized for the two UI query shapes:
--   * device detail page   → sessions on ONE device, newest first
--   * admin "audit" view   → sessions for ONE user, newest first
--   * fleet-wide history   → all sessions, newest first
CREATE INDEX idx_terminal_sessions_device_started
    ON terminal_sessions (device_id, started_at DESC);
CREATE INDEX idx_terminal_sessions_user_started
    ON terminal_sessions (user_id, started_at DESC);
CREATE INDEX idx_terminal_sessions_started
    ON terminal_sessions (started_at DESC);

-- +goose Down
DROP TABLE IF EXISTS terminal_sessions;
