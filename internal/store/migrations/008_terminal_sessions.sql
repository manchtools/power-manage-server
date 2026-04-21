-- +goose Up

-- terminal_sessions is the canonical record of one remote terminal
-- session. It replaces the earlier pattern of streaming per-keystroke
-- TerminalInputChunk events into the append-only event store, which
-- flooded the event stream with opaque single-byte fragments and
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
--
-- The 8 MiB per-session cap on `input` is enforced in the
-- AppendTerminalSessionChunk query (see queries/terminal_sessions.sql)
-- via substring clamping + the input_truncated flag, NOT as a schema
-- CHECK constraint. A schema-level cap would hard-reject a
-- well-formed task rather than gracefully flagging the overflow, so
-- the clamp lives in the query. Reviewers inspecting this file in
-- isolation: don't expect to find a CHECK(octet_length(input) <= …).
CREATE TABLE terminal_sessions (
    session_id      TEXT PRIMARY KEY,
    device_id       TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    tty_user        TEXT NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL,
    stopped_at      TIMESTAMPTZ,
    exit_reason     TEXT,
    exit_code       INTEGER,
    terminated_by   TEXT,
    input           BYTEA NOT NULL DEFAULT '\x'::bytea,
    -- input_truncated flips true the first time an append would
    -- have exceeded the 8 MiB cap. Further appends after truncation
    -- clamp the written bytes (or drop them entirely once the cap
    -- is reached). 8 MiB is generous for human shell sessions
    -- (several hours of interactive work) and bounds pathological
    -- or malicious flooders.
    input_truncated BOOLEAN NOT NULL DEFAULT FALSE,
    -- last_sequence is the highest per-session sequence number
    -- accepted into `input` so far. The append query guards on
    -- EXCLUDED.last_sequence > terminal_sessions.last_sequence so
    -- duplicate or out-of-order Asynq retries don't double-append
    -- or stutter chunk_count. The gateway's audit batcher emits
    -- strictly monotonic sequences per session.
    last_sequence   BIGINT NOT NULL DEFAULT 0,
    chunk_count     INTEGER NOT NULL DEFAULT 0,
    cols            INTEGER NOT NULL DEFAULT 0,
    rows            INTEGER NOT NULL DEFAULT 0
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
