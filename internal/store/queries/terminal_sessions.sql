-- name: InsertTerminalSession :exec
INSERT INTO terminal_sessions (
    session_id, device_id, user_id, tty_user, started_at, cols, rows
) VALUES (
    sqlc.arg(session_id), sqlc.arg(device_id), sqlc.arg(user_id),
    sqlc.arg(tty_user), sqlc.arg(started_at), sqlc.arg(cols), sqlc.arg(rows)
);

-- name: GetOpenTerminalSession :one
SELECT ts.session_id, ts.device_id, d.hostname AS device_hostname,
       ts.user_id, u.email AS user_email, ts.tty_user,
       ts.started_at, ts.cols, ts.rows
FROM terminal_sessions ts
JOIN devices d ON d.id = ts.device_id
JOIN users u ON u.id = ts.user_id
WHERE ts.session_id = $1 AND ts.stopped_at IS NULL;

-- name: StopTerminalSession :execrows
UPDATE terminal_sessions
SET stopped_at = sqlc.arg(stopped_at),
    exit_reason = sqlc.arg(exit_reason),
    terminated_by = sqlc.narg(terminated_by)
WHERE session_id = sqlc.arg(session_id)
  AND stopped_at IS NULL;
