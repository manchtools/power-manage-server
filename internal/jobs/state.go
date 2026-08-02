// Package jobs owns durable SQLite job scheduling state. Claim leases and
// worker ownership are database conditions; process-local workers are only a
// bounded execution mechanism and may disappear at any point.
package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/store/sqlitetype"
)

const (
	StatePending   = "PENDING"
	StateClaimed   = "CLAIMED"
	StateSucceeded = "SUCCEEDED"
	StateFailed    = "FAILED"
	StateCancelled = "CANCELLED"

	maxPayloadBytes = 64 << 10
	maxAttempts     = int32(100)
)

var (
	ErrInvalidInput      = errors.New("invalid job input")
	ErrClaimLost         = errors.New("job claim lost")
	ErrInvalidTransition = errors.New("invalid job transition")

	kindPattern       = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)
	dedupePattern     = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,127}$`)
	resultCodePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

// InsertParams is one complete scheduled job.
type InsertParams struct {
	OperationID string
	Kind        string
	Payload     json.RawMessage
	DueAt       time.Time
	MaxAttempts int32
	DedupeKey   string
}

// InsertInTx commits a job through the operation that scheduled it. The
// process-local runner may be notified only after that transaction commits.
func InsertInTx(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder, p InsertParams) (string, error) {
	if ctx == nil || tx == nil || rec == nil || !validID(p.OperationID) || !kindPattern.MatchString(p.Kind) ||
		p.DueAt.IsZero() || p.MaxAttempts < 1 || p.MaxAttempts > maxAttempts || !validPayload(p.Payload) {
		return "", ErrInvalidInput
	}
	var dedupeKey *string
	if p.DedupeKey != "" {
		if !dedupePattern.MatchString(p.DedupeKey) {
			return "", ErrInvalidInput
		}
		dedupeKey = &p.DedupeKey
	}

	jobID := ulid.Make().String()
	if _, err := tx.InsertJob(ctx, db.InsertJobParams{
		JobID: jobID, Kind: p.Kind, Payload: sqlitetype.JSON(p.Payload), DueAt: p.DueAt,
		MaxAttempts: p.MaxAttempts, DedupeKey: dedupeKey,
	}); err != nil {
		return "", fmt.Errorf("insert job: %w", err)
	}
	rec.Effect(jobEffect(jobID, "CREATE", "kind", "payload", "state", "due_at"))
	return jobID, nil
}

func validPayload(payload json.RawMessage) bool {
	if len(payload) == 0 || len(payload) > maxPayloadBytes {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil || object == nil {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

func validID(id string) bool {
	_, err := ulid.ParseStrict(id)
	return err == nil
}

// Config supplies the job state clock and lease policy.
type Config struct {
	Store         *store.Store
	Now           func() time.Time
	LeaseDuration time.Duration
	RetryDelay    time.Duration
}

// Service advances job leases in audited transactions.
type Service struct {
	store         *store.Store
	now           func() time.Time
	leaseDuration time.Duration
	retryDelay    time.Duration
}

// New constructs a job state service.
func New(cfg Config) *Service {
	if cfg.Store == nil {
		panic("jobs: store is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.LeaseDuration <= 0 || cfg.RetryDelay <= 0 {
		panic("jobs: positive lease and retry durations are required")
	}
	return &Service{
		store: cfg.Store, now: cfg.Now,
		leaseDuration: cfg.LeaseDuration, retryDelay: cfg.RetryDelay,
	}
}

// Claim leases one due job to workerID. A live lease is a successful no-op;
// an expired lease can be reclaimed by a new worker.
func (s *Service) Claim(ctx context.Context, jobID, workerID string) (store.JobRow, bool, error) {
	if ctx == nil || !validID(jobID) || !validID(workerID) {
		return store.JobRow{}, false, ErrInvalidInput
	}
	now := s.now().UTC()
	row, err := s.store.GetJob(ctx, jobID)
	if err != nil {
		return store.JobRow{}, false, err
	}
	if !claimable(row, now) {
		return row, false, nil
	}
	_, err = s.store.WithAudit(ctx, workerOperation(workerID, "job.claim"), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		until := now.Add(s.leaseDuration)
		n, err := tx.ClaimJob(ctx, db.ClaimJobParams{
			JobID: jobID, Now: &now, ClaimedUntil: &until, ClaimedBy: workerID,
		})
		if err != nil {
			return fmt.Errorf("claim job: %w", err)
		}
		if n != 1 {
			return store.ErrConflict
		}
		afterCount := int64(row.AttemptCount + 1)
		effect := jobEffect(jobID, "CLAIM", "state", "claimed_by", "claimed_until", "attempt_count")
		effect.AfterCount = &afterCount
		rec.Effect(effect)
		return nil
	})
	if err == nil {
		claimed, readErr := s.store.GetJob(ctx, jobID)
		if readErr != nil {
			return store.JobRow{}, false, readErr
		}
		return claimed, true, nil
	}
	if !store.IsConflict(err) {
		return store.JobRow{}, false, err
	}
	current, readErr := s.store.GetJob(ctx, jobID)
	if readErr != nil {
		return store.JobRow{}, false, readErr
	}
	if !claimable(current, now) {
		return current, false, nil
	}
	return current, false, store.ErrConflict
}

func claimable(row store.JobRow, now time.Time) bool {
	switch row.State {
	case StatePending:
		return !row.DueAt.After(now)
	case StateClaimed:
		return row.ClaimedUntil != nil && !row.ClaimedUntil.After(now)
	default:
		return false
	}
}

// Release hands the current worker's claim back after the configured retry
// delay. A stale worker cannot release a claim another worker reclaimed.
func (s *Service) Release(ctx context.Context, jobID, workerID, resultCode string) (bool, error) {
	if ctx == nil || !validID(jobID) || !validID(workerID) || !resultCodePattern.MatchString(resultCode) {
		return false, ErrInvalidInput
	}
	row, err := s.store.GetJob(ctx, jobID)
	if err != nil {
		return false, err
	}
	if row.State == StatePending && row.ClaimedBy == "" && row.ResultCode == resultCode {
		return false, nil
	}
	if row.State != StateClaimed {
		return false, ErrInvalidTransition
	}
	if row.ClaimedBy != workerID {
		return false, ErrClaimLost
	}
	now := s.now().UTC()
	_, err = s.store.WithAudit(ctx, workerOperation(workerID, "job.release"), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		n, err := tx.ReleaseJobClaim(ctx, db.ReleaseJobClaimParams{
			JobID: jobID, ClaimedBy: workerID, DueAt: now.Add(s.retryDelay),
			ResultCode: resultCode, UpdatedAt: now,
		})
		if err != nil {
			return fmt.Errorf("release job: %w", err)
		}
		if n != 1 {
			return store.ErrConflict
		}
		rec.Effect(jobEffect(jobID, "RELEASE", "state", "claimed_by", "claimed_until", "due_at", "result_code"))
		return nil
	})
	if err == nil {
		return true, nil
	}
	if !store.IsConflict(err) {
		return false, err
	}
	return s.resolveReleaseConflict(ctx, jobID, workerID, resultCode)
}

func (s *Service) resolveReleaseConflict(ctx context.Context, jobID, workerID, resultCode string) (bool, error) {
	current, err := s.store.GetJob(ctx, jobID)
	if err != nil {
		return false, err
	}
	if current.State == StatePending && current.ClaimedBy == "" && current.ResultCode == resultCode {
		return false, nil
	}
	if current.State == StateClaimed && current.ClaimedBy != workerID {
		return false, ErrClaimLost
	}
	return false, ErrInvalidTransition
}

// Finish records the current worker's terminal result. Exact replays are
// absorbed; a stale worker cannot finish another worker's reclaimed lease.
func (s *Service) Finish(ctx context.Context, jobID, workerID, state, resultCode string) (bool, error) {
	if ctx == nil || !validID(jobID) || !validID(workerID) || !terminal(state) || !resultCodePattern.MatchString(resultCode) {
		return false, ErrInvalidInput
	}
	row, err := s.store.GetJob(ctx, jobID)
	if err != nil {
		return false, err
	}
	if terminal(row.State) {
		if row.State == state && row.ResultCode == resultCode {
			return false, nil
		}
		return false, ErrInvalidTransition
	}
	if row.State != StateClaimed {
		return false, ErrInvalidTransition
	}
	if row.ClaimedBy != workerID {
		return false, ErrClaimLost
	}
	now := s.now().UTC()
	_, err = s.store.WithAudit(ctx, workerOperation(workerID, "job.finish"), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		n, err := tx.FinishJob(ctx, db.FinishJobParams{
			JobID: jobID, ClaimedBy: workerID, NewState: state, TerminalAt: &now, ResultCode: resultCode,
		})
		if err != nil {
			return fmt.Errorf("finish job: %w", err)
		}
		if n != 1 {
			return store.ErrConflict
		}
		rec.Effect(jobEffect(jobID, "COMPLETE", "state", "claimed_by", "claimed_until", "terminal_at", "result_code"))
		return nil
	})
	if err == nil {
		return true, nil
	}
	if !store.IsConflict(err) {
		return false, err
	}
	return s.resolveFinishConflict(ctx, jobID, workerID, state, resultCode)
}

// Reschedule returns a successfully completed recurring job to PENDING with a
// fresh retry budget. A stale worker cannot move a claim it no longer owns.
func (s *Service) Reschedule(ctx context.Context, jobID, workerID string, dueAt time.Time) (bool, error) {
	if ctx == nil || !validID(jobID) || !validID(workerID) || dueAt.IsZero() {
		return false, ErrInvalidInput
	}
	row, err := s.store.GetJob(ctx, jobID)
	if err != nil {
		return false, err
	}
	if row.State != StateClaimed {
		return false, ErrInvalidTransition
	}
	if row.ClaimedBy != workerID {
		return false, ErrClaimLost
	}
	now := s.now().UTC()
	dueAt = dueAt.UTC()
	_, err = s.store.WithAudit(ctx, workerOperation(workerID, "job.reschedule"), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		n, err := tx.RescheduleJob(ctx, db.RescheduleJobParams{
			JobID: jobID, ClaimedBy: workerID, DueAt: dueAt, UpdatedAt: now,
		})
		if err != nil {
			return fmt.Errorf("reschedule job: %w", err)
		}
		if n != 1 {
			return store.ErrConflict
		}
		rec.Effect(jobEffect(jobID, "RESCHEDULE", "state", "claimed_by", "claimed_until", "due_at", "attempt_count", "result_code"))
		return nil
	})
	if err == nil {
		return true, nil
	}
	if !store.IsConflict(err) {
		return false, err
	}
	current, readErr := s.store.GetJob(ctx, jobID)
	if readErr != nil {
		return false, readErr
	}
	if current.State == StateClaimed && current.ClaimedBy != workerID {
		return false, ErrClaimLost
	}
	return false, ErrInvalidTransition
}

func (s *Service) resolveFinishConflict(ctx context.Context, jobID, workerID, state, resultCode string) (bool, error) {
	current, err := s.store.GetJob(ctx, jobID)
	if err != nil {
		return false, err
	}
	if terminal(current.State) {
		if current.State == state && current.ResultCode == resultCode {
			return false, nil
		}
		return false, ErrInvalidTransition
	}
	if current.State == StateClaimed && current.ClaimedBy != workerID {
		return false, ErrClaimLost
	}
	return false, ErrInvalidTransition
}

func terminal(state string) bool {
	return state == StateSucceeded || state == StateFailed || state == StateCancelled
}

func jobEffect(jobID, action string, fields ...string) store.AuditEffect {
	return store.AuditEffect{
		ResourceType: "job", ResourceID: jobID, Action: action,
		Outcome: store.EffectApplied, ChangedFields: fields,
	}
}

func workerOperation(workerID, descriptor string) store.AuditOperation {
	return store.AuditOperation{
		Class: store.ClassBackgroundWriter, ActorType: "control_worker", ActorID: workerID,
		Origin: "in_process", RequestDescriptor: descriptor,
		AuthorizationOutcome: store.AuthorizationNotApplicable,
		Result:               store.ResultSuccess, ResultCode: "OK",
	}
}
