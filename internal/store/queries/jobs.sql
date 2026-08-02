-- Database-backed scheduled work.

-- name: InsertJob :one
INSERT INTO jobs (job_id, kind, payload, state, due_at, max_attempts, dedupe_key)
VALUES ($1, $2, $3, 'PENDING', $4, $5, $6)
RETURNING *;

-- name: GetJob :one
SELECT * FROM jobs WHERE job_id = $1;

-- name: GetLiveJobByDedupe :one
SELECT * FROM jobs
WHERE dedupe_key = $1 AND state IN ('PENDING', 'CLAIMED')
LIMIT 1;

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
-- Candidates for the scheduler tick. ClaimJob is the arbiter; concurrent
-- runners may see the same candidate but only one conditional UPDATE wins.
SELECT * FROM jobs
WHERE (state = 'PENDING' AND due_at <= $1)
   OR (state = 'CLAIMED' AND claimed_until <= $1)
ORDER BY due_at
LIMIT $2;

-- name: ReleaseJobClaim :execrows
-- Hand a claimed row back for a later retry.
UPDATE jobs
SET state = 'PENDING',
    claimed_at = NULL,
    claimed_until = NULL,
    claimed_by = '',
    due_at = $3,
    result_code = $4,
    updated_at = $5
WHERE job_id = $1
  AND state = 'CLAIMED'
  AND claimed_by = $2;

-- name: FinishJob :execrows
UPDATE jobs
SET state = $3,
    claimed_at = NULL,
    claimed_until = NULL,
    claimed_by = '',
    terminal_at = $4,
    result_code = $5,
    updated_at = $4
WHERE job_id = $1
  AND state = 'CLAIMED'
  AND claimed_by = $2
  AND $3 IN ('SUCCEEDED', 'FAILED', 'CANCELLED');

-- name: RescheduleJob :execrows
-- A successful recurring job keeps its durable identity and returns to the
-- pending state with a fresh retry budget.
UPDATE jobs
SET state = 'PENDING',
    due_at = $3,
    claimed_at = NULL,
    claimed_until = NULL,
    claimed_by = '',
    attempt_count = 0,
    result_code = 'OK',
    updated_at = $4
WHERE job_id = $1
  AND state = 'CLAIMED'
  AND claimed_by = $2;

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
