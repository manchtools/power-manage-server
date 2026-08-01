// Package dispatch turns already-compiled manifests into durable device work.
package dispatch

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/delivery"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// ErrInvalidInput means no complete device delivery could be formed.
var ErrInvalidInput = errors.New("invalid dispatch submission")

// Waker is the lossy process-local optimization used after the database commit.
// The delivery sweep remains the correctness path when Wake returns false.
type Waker interface {
	Wake(deliveryID string) bool
}

// Config supplies the direct store, bounded wake queue, and clock.
type Config struct {
	Store *store.Store
	Waker Waker
	Now   func() time.Time
}

// Service commits complete manifests and their visible execution rows.
type Service struct {
	store *store.Store
	waker Waker
	now   func() time.Time
}

// New constructs a submission service. Missing dependencies are boot defects.
func New(cfg Config) *Service {
	if cfg.Store == nil || cfg.Waker == nil {
		panic("dispatch: store and waker are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{store: cfg.Store, waker: cfg.Waker, now: cfg.Now}
}

// ManifestInput distinguishes catalog-backed occurrences from inline actions.
// A manifest never mixes the two forms.
type ManifestInput struct {
	Manifest         *pmv1.Manifest
	PersistActionIDs bool
}

// SubmitParams is one atomic operator dispatch, including fan-out.
type SubmitParams struct {
	Operation    store.AuditOperation
	DeviceID     string
	Manifests    []ManifestInput
	ScheduledFor *time.Time
}

// TargetInput is one device's complete portion of an atomic fan-out.
type TargetInput struct {
	DeviceID     string
	Manifests    []ManifestInput
	ScheduledFor *time.Time
}

// SubmitBatchParams groups every device reached by one operator request.
type SubmitBatchParams struct {
	Operation store.AuditOperation
	Targets   []TargetInput
}

// Result names every durable delivery and execution in request order.
type Result struct {
	DeliveryIDs []string
	Executions  []store.ExecutionView
}

type preparedExecution struct {
	params db.InsertExecutionParams
	view   store.ExecutionView
}

type preparedManifest struct {
	input      ManifestInput
	executions []preparedExecution
}

type preparedTarget struct {
	deviceID    string
	availableAt time.Time
	manifests   []preparedManifest
}

// Submit commits every manifest and occurrence through the same audit
// transaction. A wake is attempted only after the commit succeeds.
func (s *Service) Submit(ctx context.Context, p SubmitParams) (Result, error) {
	return s.SubmitBatch(ctx, SubmitBatchParams{
		Operation: p.Operation,
		Targets: []TargetInput{{
			DeviceID: p.DeviceID, Manifests: p.Manifests, ScheduledFor: p.ScheduledFor,
		}},
	})
}

// SubmitBatch commits every target, manifest, and occurrence under one audit
// operation. No device is woken unless the complete fan-out commits.
func (s *Service) SubmitBatch(ctx context.Context, p SubmitBatchParams) (Result, error) {
	if ctx == nil || len(p.Targets) == 0 {
		return Result{}, ErrInvalidInput
	}
	now := s.now().UTC()
	if p.Operation.OperationID == "" {
		p.Operation.OperationID = ulid.Make().String()
	}

	prepared := make([]preparedTarget, len(p.Targets))
	seenOccurrences := make(map[string]struct{})
	seenDevices := make(map[string]struct{}, len(p.Targets))
	for targetIndex, target := range p.Targets {
		if !validID(target.DeviceID) || len(target.Manifests) == 0 {
			return Result{}, ErrInvalidInput
		}
		if _, duplicate := seenDevices[target.DeviceID]; duplicate {
			return Result{}, ErrInvalidInput
		}
		seenDevices[target.DeviceID] = struct{}{}
		availableAt := now
		status := "pending"
		if target.ScheduledFor != nil {
			scheduled := target.ScheduledFor.UTC()
			if !scheduled.After(now) {
				return Result{}, ErrInvalidInput
			}
			target.ScheduledFor = &scheduled
			availableAt, status = scheduled, "scheduled"
		}
		prepared[targetIndex] = preparedTarget{
			deviceID: target.DeviceID, availableAt: availableAt,
			manifests: make([]preparedManifest, len(target.Manifests)),
		}
		for manifestIndex, input := range target.Manifests {
			if input.Manifest == nil || len(input.Manifest.Occurrences) == 0 {
				return Result{}, ErrInvalidInput
			}
			prepared[targetIndex].manifests[manifestIndex] = preparedManifest{
				input: input, executions: make([]preparedExecution, len(input.Manifest.Occurrences)),
			}
			for occurrenceIndex, occurrence := range input.Manifest.Occurrences {
				if occurrence == nil || occurrence.Action == nil || !validID(occurrence.OccurrenceId) {
					return Result{}, ErrInvalidInput
				}
				if _, duplicate := seenOccurrences[occurrence.OccurrenceId]; duplicate {
					return Result{}, ErrInvalidInput
				}
				seenOccurrences[occurrence.OccurrenceId] = struct{}{}
				rawParams, err := actionParams(occurrence.Action)
				if err != nil {
					return Result{}, err
				}
				var actionID *string
				if input.PersistActionIDs {
					id := occurrence.Action.GetId().GetValue()
					if !validID(id) {
						return Result{}, ErrInvalidInput
					}
					actionID = &id
				}
				createdAt := now
				insert := db.InsertExecutionParams{
					ID: occurrence.OccurrenceId, DeviceID: target.DeviceID, ActionID: actionID,
					ActionType: int32(occurrence.Action.Type), DesiredState: int32(occurrence.Action.DesiredState),
					Params: rawParams, TimeoutSeconds: occurrence.Action.TimeoutSeconds,
					Status: status, CreatedAt: &createdAt, ScheduledFor: target.ScheduledFor,
					CreatedByType: p.Operation.ActorType, CreatedByID: p.Operation.ActorID,
				}
				prepared[targetIndex].manifests[manifestIndex].executions[occurrenceIndex] = preparedExecution{
					params: insert,
					view: store.ExecutionView{
						ID: insert.ID, DeviceID: insert.DeviceID, ActionID: insert.ActionID,
						ActionType: insert.ActionType, DesiredState: insert.DesiredState,
						Status: insert.Status, CreatedAt: insert.CreatedAt,
						ScheduledFor: insert.ScheduledFor, CreatedByID: insert.CreatedByID,
					},
				}
			}
		}
	}

	deliveryIDs := make([]string, 0)
	executions := make([]store.ExecutionView, 0, len(seenOccurrences))
	_, err := s.store.WithAudit(ctx, p.Operation, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		for _, target := range prepared {
			for _, compiled := range target.manifests {
				deliveryID, err := delivery.InsertInTx(ctx, tx, rec, delivery.InsertParams{
					OperationID: p.Operation.OperationID, DeviceID: target.deviceID,
					Manifest: compiled.input.Manifest, AvailableAt: target.availableAt,
				})
				if err != nil {
					return err
				}
				deliveryIDs = append(deliveryIDs, deliveryID)
				for _, execution := range compiled.executions {
					if _, err := tx.InsertExecution(ctx, execution.params); err != nil {
						return fmt.Errorf("insert execution: %w", err)
					}
					executions = append(executions, execution.view)
					rec.Effect(store.AuditEffect{
						ResourceType: "execution", ResourceID: execution.params.ID,
						Action: "CREATE", Outcome: store.EffectApplied,
						ChangedFields: []string{"device_id", "params", "status"},
					})
				}
			}
		}
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("submit dispatch: %w", err)
	}
	for _, id := range deliveryIDs {
		s.waker.Wake(id)
	}
	return Result{DeliveryIDs: deliveryIDs, Executions: executions}, nil
}

func actionParams(action *pmv1.Action) ([]byte, error) {
	params := actionparams.ExtractParamsMsg(action)
	if params == nil {
		return []byte("{}"), nil
	}
	raw, err := actionparams.MarshalActionParams(params)
	if err != nil {
		return nil, fmt.Errorf("marshal dispatch params: %w", err)
	}
	return raw, nil
}

func validID(id string) bool {
	_, err := ulid.ParseStrict(id)
	return err == nil
}
