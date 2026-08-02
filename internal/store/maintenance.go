package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/oklog/ulid/v2"
)

const maintenanceResourceID = "00000000000000000000000003"

// CleanupExpiredAuthStates deletes expired one-time OIDC state in the same
// transaction as its bounded maintenance audit effect.
func (s *Store) CleanupExpiredAuthStates(ctx context.Context) (int64, error) {
	if ctx == nil || s == nil {
		return 0, errors.New("auth-state cleanup requires a store and context")
	}
	op := AuditOperation{
		OperationID: ulid.Make().String(), Class: ClassBackgroundWriter,
		ActorType: "control_worker", Origin: "in_process", RequestDescriptor: "identity.auth_state.cleanup",
		AuthorizationOutcome: AuthorizationNotApplicable, Result: ResultSuccess, ResultCode: "OK",
	}
	var deleted int64
	remaining := int64(0)
	_, err := s.WithAudit(ctx, op, func(ctx context.Context, tx *Tx, rec *AuditRecorder) error {
		var err error
		deleted, err = tx.CleanupExpiredAuthStates(ctx)
		if err != nil {
			return fmt.Errorf("cleanup expired auth states: %w", err)
		}
		rec.Effect(AuditEffect{
			ResourceType: "auth_state_collection", ResourceID: maintenanceResourceID,
			Action: "CLEANUP", Outcome: EffectApplied, ChangedFields: []string{"expired_count"},
			BeforeCount: &deleted, AfterCount: &remaining,
		})
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}
