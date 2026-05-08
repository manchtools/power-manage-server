-- ============================================================================
-- Projector listener writes (manchtools/power-manage-server#136).
-- ============================================================================
--
-- Mirrors the deleted PL/pgSQL project_execution_event(). Nine event
-- types, every one a single-statement write against
-- executions_projection: 2 INSERTs (Created, Scheduled) plus 7 UPDATEs
-- (Dispatched, Started, Completed, Failed, TimedOut, Skipped,
-- Cancelled). No cross-stream effects, no member tables, no compliance
-- cascade — the simplest port left under tracker #136.
--
-- Tightening vs the PL/pgSQL projector: every UPDATE carries an
-- explicit `WHERE projection_version < $N` guard and uses :execrows so
-- the listener can short-circuit on stale-replay (asymmetric-guard
-- discipline). The PL/pgSQL projector stamped projection_version
-- without a guard, so an out-of-order Completed re-applied after a
-- newer Failed would silently rewind the row's terminal status.
--
-- ExecutionCancelled keeps the PL/pgSQL `AND status IN ('scheduled',
-- 'pending')` business-logic guard verbatim alongside the new
-- projection_version guard — a cancel arriving after the dispatch has
-- fired is still a documented no-op, and stale replays on top of that
-- still no-op via the version guard.

-- name: InsertExecutionCreatedProjection :exec
-- ExecutionCreated handler. Mirrors the PL/pgSQL
-- INSERT INTO executions_projection (...) VALUES (...) — status is
-- hardcoded to 'pending', created_at falls back to event.occurred_at
-- when the payload omits executed_at. ON CONFLICT DO NOTHING for
-- replay safety.
INSERT INTO executions_projection (
    id, device_id, action_id, action_type, desired_state,
    params, timeout_seconds, status, created_at,
    created_by_type, created_by_id, projection_version
) VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9, $10, $11)
ON CONFLICT (id) DO NOTHING;

-- name: InsertExecutionScheduledProjection :exec
-- ExecutionScheduled handler. Same column shape as the Created path
-- plus scheduled_for; status is hardcoded to 'scheduled'. created_at
-- always uses event.occurred_at on this branch (no executed_at
-- fallback in the PL/pgSQL source). ON CONFLICT DO NOTHING for replay
-- safety.
INSERT INTO executions_projection (
    id, device_id, action_id, action_type, desired_state,
    params, timeout_seconds, status, scheduled_for, created_at,
    created_by_type, created_by_id, projection_version
) VALUES ($1, $2, $3, $4, $5, $6, $7, 'scheduled', $8, $9, $10, $11, $12)
ON CONFLICT (id) DO NOTHING;

-- name: UpdateExecutionDispatchedProjection :execrows
-- ExecutionDispatched handler. Single UPDATE, projection_version
-- guard. :execrows so the listener can log + short-circuit on stale
-- replay (no downstream cascade exists, but :execrows keeps the shape
-- uniform across every UPDATE handler in this projector).
UPDATE executions_projection
SET status             = 'dispatched',
    dispatched_at      = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: UpdateExecutionStartedProjection :execrows
-- ExecutionStarted handler. Single UPDATE, projection_version guard.
UPDATE executions_projection
SET status             = 'running',
    started_at         = $2,
    projection_version = $3
WHERE id = $1
  AND projection_version < $3;

-- name: UpdateExecutionCompletedProjection :execrows
-- ExecutionCompleted handler. Mirrors the PL/pgSQL terminal-success
-- branch — status='success', plus the full result-payload column set
-- (output, duration_ms, changed, compliant, detection_output). The
-- projection_version guard prevents an older Completed from clobbering
-- a newer terminal state (Failed/TimedOut/etc).
UPDATE executions_projection
SET status             = 'success',
    completed_at       = $2,
    output             = $3,
    duration_ms        = $4,
    changed            = $5,
    compliant          = $6,
    detection_output   = $7,
    projection_version = $8
WHERE id = $1
  AND projection_version < $8;

-- name: UpdateExecutionFailedProjection :execrows
-- ExecutionFailed handler. Same shape as Completed plus error.
UPDATE executions_projection
SET status             = 'failed',
    completed_at       = $2,
    error              = $3,
    output             = $4,
    duration_ms        = $5,
    changed            = $6,
    compliant          = $7,
    detection_output   = $8,
    projection_version = $9
WHERE id = $1
  AND projection_version < $9;

-- name: UpdateExecutionTimedOutProjection :execrows
-- ExecutionTimedOut handler. Subset of the Failed shape — no
-- changed / compliant / detection_output (the PL/pgSQL projector did
-- not write those columns on timeout, leaving the column defaults to
-- stand for fresh rows and preserving prior values for in-flight
-- replays).
UPDATE executions_projection
SET status             = 'timeout',
    completed_at       = $2,
    error              = $3,
    output             = $4,
    duration_ms        = $5,
    projection_version = $6
WHERE id = $1
  AND projection_version < $6;

-- name: UpdateExecutionSkippedProjection :execrows
-- ExecutionSkipped handler. completed_at is event.occurred_at (no
-- payload fallback in the PL/pgSQL source); error column carries the
-- skip reason.
UPDATE executions_projection
SET status             = 'skipped',
    completed_at       = $2,
    error              = $3,
    projection_version = $4
WHERE id = $1
  AND projection_version < $4;

-- name: UpdateExecutionCancelledProjection :execrows
-- ExecutionCancelled handler. The PL/pgSQL projector layered TWO
-- guards: the status whitelist (only flip rows still in 'scheduled'
-- or 'pending' so a cancel arriving after dispatch is a documented
-- no-op) and now the projection_version guard (so a stale cancel
-- replayed by the reconciler cannot rewind a row that has since moved
-- on). Both guards stay — the status guard is business logic; the
-- version guard is replay safety.
UPDATE executions_projection
SET status             = 'cancelled',
    completed_at       = $2,
    error              = $3,
    projection_version = $4
WHERE id = $1
  AND projection_version < $4
  AND status IN ('scheduled', 'pending');
