// Package delivery owns the durable control-side manifest delivery state
// machine. Transport retries may repeat a frame; only these conditional,
// audited SQLite transitions decide whether durable state advances.
package delivery

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/encoding/protojson"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	sdkvalidate "github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	StatePending      = "PENDING"
	StatePushed       = "PUSHED"
	StateAckedReceipt = "ACKED_RECEIPT"
	StateSucceeded    = "SUCCEEDED"
	StatePartial      = "PARTIAL"
	StateFailed       = "FAILED"
	StateExpired      = "EXPIRED"
	StateCancelled    = "CANCELLED"

	retryDelay = 30 * time.Second
)

var (
	ErrInvalidInput      = errors.New("invalid delivery input")
	ErrStaleEpoch        = errors.New("stale delivery epoch")
	ErrWrongDevice       = errors.New("delivery belongs to another device")
	ErrWrongManifest     = errors.New("delivery carries another manifest")
	ErrInvalidTransition = errors.New("invalid delivery transition")

	resultCodePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	manifestValidator = sdkvalidate.NewValidator()
)

// InsertParams is the complete durable input for one device delivery.
type InsertParams struct {
	OperationID string
	DeviceID    string
	Manifest    *pmv1.Manifest
	AvailableAt time.Time
	ExpiresAt   *time.Time
}

// InsertInTx commits a complete manifest through the initiating operation's
// audited transaction. The caller may wake the dispatcher only after that
// transaction commits.
func InsertInTx(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder, p InsertParams) (string, error) {
	if ctx == nil || tx == nil || rec == nil || p.Manifest == nil || p.AvailableAt.IsZero() {
		return "", ErrInvalidInput
	}
	if !validID(p.OperationID) || !validID(p.DeviceID) || !validManifest(p.Manifest) {
		return "", ErrInvalidInput
	}
	if p.ExpiresAt != nil && !p.ExpiresAt.After(p.AvailableAt) {
		return "", ErrInvalidInput
	}

	payload, err := protojson.Marshal(p.Manifest)
	if err != nil {
		return "", fmt.Errorf("marshal delivery manifest: %w", err)
	}
	deliveryID := ulid.Make().String()
	operationID := p.OperationID
	if _, err := tx.InsertDelivery(ctx, db.InsertDeliveryParams{
		DeliveryID: deliveryID, DeviceID: p.DeviceID, ManifestID: p.Manifest.ManifestId,
		Manifest: payload, OperationID: &operationID, AvailableAt: p.AvailableAt, ExpiresAt: p.ExpiresAt,
	}); err != nil {
		return "", fmt.Errorf("insert delivery: %w", err)
	}
	manifestID := p.Manifest.ManifestId
	rec.Effect(store.AuditEffect{
		ResourceType: "delivery", ResourceID: deliveryID, Action: "CREATE",
		Outcome: store.EffectApplied, ChangedFields: []string{"manifest", "state"}, AfterRef: &manifestID,
	})
	return deliveryID, nil
}

func validManifest(manifest *pmv1.Manifest) bool {
	if _, ok := sdkvalidate.Struct(manifestValidator, manifest); !ok {
		return false
	}
	p := manifest.GetProvenance()
	if p == nil {
		return false
	}
	validPath := (p.DefinitionId != "" && p.ActionSetId != "" && p.ActionId == "") ||
		(p.DefinitionId == "" && p.ActionSetId != "" && p.ActionId == "") ||
		(p.DefinitionId == "" && p.ActionSetId == "" && p.ActionId != "")
	if !validPath {
		return false
	}
	seen := make(map[string]struct{}, len(manifest.Occurrences))
	for _, occurrence := range manifest.Occurrences {
		if occurrence == nil {
			return false
		}
		if _, duplicate := seen[occurrence.OccurrenceId]; duplicate {
			return false
		}
		seen[occurrence.OccurrenceId] = struct{}{}
	}
	return true
}

func validID(id string) bool {
	_, err := ulid.ParseStrict(id)
	return err == nil
}

// Config supplies the durable store and clock used by delivery transitions.
type Config struct {
	Store *store.Store
	Now   func() time.Time
}

// Service advances delivery rows in audited transactions.
type Service struct {
	store *store.Store
	now   func() time.Time
}

// New constructs a delivery service. A missing store is a boot-time wiring
// defect and is rejected immediately.
func New(cfg Config) *Service {
	if cfg.Store == nil {
		panic("delivery: store is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{store: cfg.Store, now: cfg.Now}
}

// MarkPushed records that a specific live connection epoch is about to carry
// the manifest. A lower epoch can never overwrite a newer one.
func (s *Service) MarkPushed(ctx context.Context, deliveryID, deviceID string, epoch int64) (bool, error) {
	if ctx == nil || !validID(deliveryID) || !validID(deviceID) || epoch <= 0 {
		return false, ErrInvalidInput
	}
	row, err := s.store.GetDelivery(ctx, deliveryID)
	if err != nil {
		return false, err
	}
	if err := pushAllowed(row, deviceID, epoch); err != nil {
		return false, err
	}
	if !pushable(row.State) {
		return false, nil
	}

	now := s.now().UTC()
	_, err = s.store.WithAudit(ctx, backgroundOperation("delivery.push"), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		n, err := tx.MarkDeliveryPushed(ctx, db.MarkDeliveryPushedParams{
			DeliveryID: deliveryID, PushedAt: &now, PushEpoch: epoch, AvailableAt: now.Add(retryDelay),
		})
		if err != nil {
			return fmt.Errorf("mark delivery pushed: %w", err)
		}
		if n != 1 {
			return store.ErrConflict
		}
		rec.Effect(deliveryEffect(deliveryID, "PUSH", "state", "push_epoch", "attempt_count"))
		return nil
	})
	if err == nil {
		return true, nil
	}
	if !store.IsConflict(err) {
		return false, err
	}
	current, readErr := s.store.GetDelivery(ctx, deliveryID)
	if readErr != nil {
		return false, readErr
	}
	if allowedErr := pushAllowed(current, deviceID, epoch); allowedErr != nil {
		return false, allowedErr
	}
	if !pushable(current.State) {
		return false, nil
	}
	return false, store.ErrConflict
}

func pushAllowed(row store.DeliveryRow, deviceID string, epoch int64) error {
	if row.DeviceID != deviceID {
		return ErrWrongDevice
	}
	if row.PushEpoch > epoch {
		return ErrStaleEpoch
	}
	if !pushable(row.State) && row.State != StateAckedReceipt && !terminal(row.State) {
		return ErrInvalidTransition
	}
	return nil
}

func pushable(state string) bool { return state == StatePending || state == StatePushed }

// AcknowledgeReceipt records the agent's confirmation that its local receipt
// row is durable. Replays after that point are successful no-ops.
func (s *Service) AcknowledgeReceipt(ctx context.Context, deliveryID, deviceID string) (bool, error) {
	if ctx == nil || !validID(deliveryID) || !validID(deviceID) {
		return false, ErrInvalidInput
	}
	row, err := s.store.GetDelivery(ctx, deliveryID)
	if err != nil {
		return false, err
	}
	if err := receiptAllowed(row, deviceID); err != nil {
		return false, err
	}
	if row.State != StatePushed {
		return false, nil
	}

	now := s.now().UTC()
	_, err = s.store.WithAudit(ctx, agentOperation(deviceID, "delivery.receipt"), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		n, err := tx.MarkDeliveryAckedReceipt(ctx, db.MarkDeliveryAckedReceiptParams{
			DeliveryID: deliveryID, AckedReceiptAt: &now,
		})
		if err != nil {
			return fmt.Errorf("acknowledge delivery receipt: %w", err)
		}
		if n != 1 {
			return store.ErrConflict
		}
		rec.Effect(deliveryEffect(deliveryID, "ACK", "state", "acked_receipt_at"))
		return nil
	})
	if err == nil {
		return true, nil
	}
	if !store.IsConflict(err) {
		return false, err
	}
	current, readErr := s.store.GetDelivery(ctx, deliveryID)
	if readErr != nil {
		return false, readErr
	}
	if allowedErr := receiptAllowed(current, deviceID); allowedErr != nil {
		return false, allowedErr
	}
	if current.State != StatePushed {
		return false, nil
	}
	return false, store.ErrConflict
}

func receiptAllowed(row store.DeliveryRow, deviceID string) error {
	if row.DeviceID != deviceID {
		return ErrWrongDevice
	}
	switch row.State {
	case StatePushed, StateAckedReceipt, StateSucceeded, StatePartial, StateFailed:
		return nil
	default:
		return ErrInvalidTransition
	}
}

// Complete records one manifest's aggregate terminal result. A replay must
// agree with the already committed state and fixed result code.
func (s *Service) Complete(ctx context.Context, deliveryID, deviceID, manifestID, state, resultCode string) (bool, error) {
	if ctx == nil || !validID(deliveryID) || !validID(deviceID) || !validID(manifestID) || !resultCodePattern.MatchString(resultCode) {
		return false, ErrInvalidInput
	}
	if state != StateSucceeded && state != StatePartial && state != StateFailed {
		return false, ErrInvalidInput
	}
	row, err := s.store.GetDelivery(ctx, deliveryID)
	if err != nil {
		return false, err
	}
	if err := resultAllowed(row, deviceID, manifestID, state, resultCode); err != nil {
		return false, err
	}
	if terminal(row.State) {
		return false, nil
	}

	now := s.now().UTC()
	_, err = s.store.WithAudit(ctx, agentOperation(deviceID, "delivery.result"), func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		n, err := tx.MarkDeliveryResult(ctx, db.MarkDeliveryResultParams{
			DeliveryID: deliveryID, State: state, TerminalAt: &now, ResultCode: resultCode,
		})
		if err != nil {
			return fmt.Errorf("complete delivery: %w", err)
		}
		if n != 1 {
			return store.ErrConflict
		}
		rec.Effect(deliveryEffect(deliveryID, "RESULT", "state", "result_code", "terminal_at"))
		return nil
	})
	if err == nil {
		return true, nil
	}
	if !store.IsConflict(err) {
		return false, err
	}
	current, readErr := s.store.GetDelivery(ctx, deliveryID)
	if readErr != nil {
		return false, readErr
	}
	if allowedErr := resultAllowed(current, deviceID, manifestID, state, resultCode); allowedErr != nil {
		return false, allowedErr
	}
	if terminal(current.State) {
		return false, nil
	}
	return false, store.ErrConflict
}

func resultAllowed(row store.DeliveryRow, deviceID, manifestID, state, resultCode string) error {
	if row.DeviceID != deviceID {
		return ErrWrongDevice
	}
	if row.ManifestID != manifestID {
		return ErrWrongManifest
	}
	if terminal(row.State) {
		if row.State == state && row.ResultCode == resultCode {
			return nil
		}
		return ErrInvalidTransition
	}
	if row.State != StateAckedReceipt {
		return ErrInvalidTransition
	}
	return nil
}

func terminal(state string) bool {
	switch state {
	case StateSucceeded, StatePartial, StateFailed, StateExpired, StateCancelled:
		return true
	default:
		return false
	}
}

func deliveryEffect(deliveryID, action string, fields ...string) store.AuditEffect {
	return store.AuditEffect{
		ResourceType: "delivery", ResourceID: deliveryID, Action: action,
		Outcome: store.EffectApplied, ChangedFields: fields,
	}
}

func backgroundOperation(descriptor string) store.AuditOperation {
	return store.AuditOperation{
		Class: store.ClassBackgroundWriter, ActorType: "control", Origin: "in_process",
		RequestDescriptor: descriptor, AuthorizationOutcome: store.AuthorizationNotApplicable,
		Result: store.ResultSuccess, ResultCode: "OK",
	}
}

func agentOperation(deviceID, descriptor string) store.AuditOperation {
	return store.AuditOperation{
		Class: store.ClassMutation, ActorType: "agent", ActorID: deviceID, Origin: "agent_stream",
		RequestDescriptor: descriptor, AuthorizationOutcome: store.AuthorizationAllowed,
		AuthorizationDetail: "device_mtls", Result: store.ResultSuccess, ResultCode: "OK",
	}
}
