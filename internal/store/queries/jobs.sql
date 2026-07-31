-- Database-backed scheduled work.

-- name: InsertJob :one
INSERT INTO jobs (job_id, kind, payload, state, due_at, max_attempts, dedupe_key)
VALUES ($1, $2, $3, 'PENDING', $4, $5, $6)
RETURNING *;

-- name: GetJob :one
SELECT * FROM jobs WHERE job_id = $1;

-- name: ClaimJob :execrows
-- The conditional transition that makes claiming safe without a lock
-- table: a row is claimable when it is due and unclaimed, or when a
-- previous claim's lease has expired. Two workers racing on the same
-- row produce one winner and one zero-row UPDATE.
UPDATE jobs
SET state = 'CLAIMED',
    claimed_at = $2,
    claimed_until = $3,
    claimed_by = $4,
    attempt_count = attempt_count + 1,
    updated_at = $2
WHERE job_id = $1
  AND (
        (state = 'PENDING' AND due_at <= $2)
     OR (state = 'CLAIMED' AND claimed_until <= $2)
  );

-- name: ListClaimableJobs :many
-- Candidates for the scheduler tick. FOR UPDATE SKIP LOCKED so two
-- ticks in the same process never hand the same candidate to two
-- workers before the conditional claim even runs.
SELECT * FROM jobs
WHERE (state = 'PENDING' AND due_at <= $1)
   OR (state = 'CLAIMED' AND claimed_until <= $1)
ORDER BY due_at
LIMIT $2
FOR UPDATE SKIP LOCKED;

-- name: ReleaseJobClaim :execrows
-- Hand a claimed row back for a later retry.
UPDATE jobs
SET state = 'PENDING',
    claimed_at = NULL,
    claimed_until = NULL,
    claimed_by = '',
    due_at = $2,
    result_code = $3,
    updated_at = $4
WHERE job_id = $1
  AND state = 'CLAIMED';

-- name: FinishJob :execrows
UPDATE jobs
SET state = $2,
    claimed_at = NULL,
    claimed_until = NULL,
    claimed_by = '',
    terminal_at = $3,
    result_code = $4,
    updated_at = $3
WHERE job_id = $1
  AND state = 'CLAIMED'
  AND $2 IN ('SUCCEEDED', 'FAILED', 'CANCELLED');

-- name: CancelPendingJob :execrows
UPDATE jobs
SET state = 'CANCELLED',
    terminal_at = $2,
    result_code = $3,
    updated_at = $2
WHERE job_id = $1
  AND state = 'PENDING';

-- name: DeleteTerminalJobsBefore :execrows
-- Terminal jobs are ordinary state with no evidentiary value; the
-- audit log holds the record of what ran.
DELETE FROM jobs
WHERE terminal_at IS NOT NULL AND terminal_at < $1;
